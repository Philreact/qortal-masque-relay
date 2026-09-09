package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"qortal.org/qortal-masque-relay/internal/relay"
	"qortal.org/qortal-masque-relay/internal/upnp"
)

type targetList []string

func (values *targetList) String() string { return strings.Join(*values, ",") }
func (values *targetList) Set(value string) error {
	for _, target := range strings.Split(value, ",") {
		target = strings.TrimSpace(target)
		if target != "" {
			*values = append(*values, target)
		}
	}
	return nil
}

func main() {
	var targets targetList
	accessFile := flag.String("access-config", "", "strict JSON relay access configuration")
	listen := flag.String("listen", "0.0.0.0:47322", "literal UDP listen endpoint")
	public := flag.String("public-address", "", "manual public literal UDP endpoint (when omitted, discover and map it with UPnP)")
	useUPnP := flag.Bool("upnp", true, "automatically map the relay UDP port and advertise the router's public IP")
	serverName := flag.String("server-name", "qortal-masque-relay", "pinned TLS server name")
	stateDir := flag.String("state-dir", "./masque-relay-data", "persistent relay state directory")
	maxSessions := flag.Int("max-sessions", 256, "maximum concurrent CONNECT-UDP sessions")
	allowPrivate := flag.Bool("allow-private-targets", false, "allow private/loopback targets (development only)")
	flag.Var(&targets, "allow-target", "optional exact private/loopback UDP exception; public targets are allowed by default; repeat or use commas")
	rnsConfig := flag.String("rns-config", "", "Reticulum config directory used to broadcast availability")
	discoveryScript := flag.String("discovery-script", "", "path to masque_relay_discovery.py")
	python := flag.String("python", "python3", "Python interpreter containing the RNS package")
	noDiscovery := flag.Bool("no-reticulum-discovery", false, "run without Reticulum advertisements")
	allowLocalAdvertise := flag.Bool("allow-local-advertise", false, "advertise a loopback endpoint for local development")
	flag.Parse()
	access := relay.AccessConfig{Mode: "public"}
	if *accessFile != "" {
		var err error
		access, err = relay.LoadAccessConfig(*accessFile)
		if err != nil {
			fatal("invalid access configuration: %v", err)
		}
	}

	listenAddress, err := netip.ParseAddrPort(*listen)
	if err != nil || !listenAddress.IsValid() || listenAddress.Port() == 0 {
		fatal("invalid --listen %q", *listen)
	}
	allowed := make([]netip.AddrPort, 0, len(targets))
	for _, value := range targets {
		target, err := netip.ParseAddrPort(value)
		if err != nil || !target.IsValid() || target.Port() == 0 {
			fatal("invalid --allow-target %q", value)
		}
		allowed = append(allowed, target)
	}
	if !*noDiscovery && *rnsConfig == "" {
		fatal("--rns-config is required unless --no-reticulum-discovery is set")
	}
	discoveryScriptPath := ""
	if !*noDiscovery {
		discoveryScriptPath = resolveDiscoveryScript(*discoveryScript)
	}

	var portMapping *upnp.Mapping
	if *public == "" {
		if !*useUPnP {
			fatal("--public-address is required when --upnp=false")
		}
		mapping, err := upnp.Open(context.Background(), listenAddress.Port(), "Qortal MASQUE Relay")
		if err != nil {
			fatal("automatic public UDP mapping unavailable: %v", err)
		}
		portMapping = mapping
		*public = mapping.PublicAddress().String()
		fmt.Fprintf(os.Stderr, "UPnP mapped UDP %d; public endpoint %s\n", listenAddress.Port(), *public)
	}
	certificatePath := filepath.Join(*stateDir, "relay-cert.pem")
	privateKeyPath := filepath.Join(*stateDir, "relay-key.pem")
	server, metadata, err := relay.Start(relay.Config{
		Access:              access,
		ListenAddress:       *listen,
		PublicAddress:       *public,
		ServerName:          *serverName,
		CertificatePath:     certificatePath,
		PrivateKeyPath:      privateKeyPath,
		AllowedTargets:      allowed,
		AllowPrivateTargets: *allowPrivate,
		AllowLocalAdvertise: *allowLocalAdvertise,
		MaxSessions:         *maxSessions,
	})
	if err != nil {
		closePortMapping(portMapping)
		fatal("start relay: %v", err)
	}
	encoded, _ := json.Marshal(metadata)
	fmt.Println(string(encoded))

	var announcer *exec.Cmd
	announcerDone := make(chan error, 1)
	if !*noDiscovery {
		args := []string{
			// Access metadata is signed by the persistent discovery identity.
			discoveryScriptPath,
			"--rns-config", *rnsConfig,
			"--identity", filepath.Join(*stateDir, "discovery.identity"),
			"--host", netip.MustParseAddrPort(metadata.RelayAddress).Addr().String(),
			"--port", fmt.Sprint(netip.MustParseAddrPort(metadata.RelayAddress).Port()),
			"--server-name", metadata.RelayServerName,
			"--cert-sha256", metadata.RelayCertSHA256,
		}
		groupJSON, _ := json.Marshal(access.AllowedGroupIDs)
		if len(access.AllowedGroupIDs) == 0 {
			groupJSON = []byte("[]")
		}
		args = append(args, "--access-mode", access.Mode, "--allowed-group-ids", string(groupJSON))
		if access.Mode == "groups" {
			args = append(args, "--ticket-socket", filepath.Join(*stateDir, "ticket-authority.sock"))
		}
		if *allowLocalAdvertise {
			args = append(args, "--allow-local")
		}
		announcer = exec.Command(*python, args...)
		announcer.Stdout = os.Stderr
		announcer.Stderr = os.Stderr
		if err := announcer.Start(); err != nil {
			_ = server.Close()
			closePortMapping(portMapping)
			fatal("start Reticulum discovery announcer: %v", err)
		}
		go func() {
			announcerDone <- announcer.Wait()
		}()
	}

	signals := make(chan os.Signal, 1)
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM)
	mappingContext, stopMappingMaintenance := context.WithCancel(context.Background())
	mappingFailure := make(chan error, 1)
	if portMapping != nil {
		go func() { mappingFailure <- portMapping.Maintain(mappingContext) }()
	}
	if announcer == nil {
		select {
		case <-signals:
		case err := <-mappingFailure:
			if err != nil {
				fmt.Fprintf(os.Stderr, "UPnP mapping lost; stopping relay: %v\n", err)
			}
		}
	} else {
		select {
		case <-signals:
		case err := <-announcerDone:
			_ = server.Close()
			closePortMapping(portMapping)
			fatal("Reticulum discovery announcer stopped: %v", err)
		case err := <-mappingFailure:
			if err != nil {
				fmt.Fprintf(os.Stderr, "UPnP mapping lost; stopping relay: %v\n", err)
			}
		}
	}
	stopMappingMaintenance()
	if announcer != nil && announcer.Process != nil {
		_ = announcer.Process.Signal(os.Interrupt)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = server.Shutdown(ctx)
	closePortMapping(portMapping)
}

func closePortMapping(mapping *upnp.Mapping) {
	if mapping == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := mapping.Close(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "remove UPnP UDP mapping: %v\n", err)
	} else {
		fmt.Fprintln(os.Stderr, "UPnP UDP mapping removed")
	}
}

func resolveDiscoveryScript(value string) string {
	if value != "" {
		return value
	}
	if executable, err := os.Executable(); err == nil {
		candidate := filepath.Join(filepath.Dir(executable), "masque_relay_discovery.py")
		if _, err := os.Stat(candidate); err == nil {
			return candidate
		}
	}
	for _, candidate := range []string{
		"scripts/masque_relay_discovery.py",
	} {
		if _, err := os.Stat(candidate); err == nil {
			return candidate
		}
	}
	fatal("unable to locate masque_relay_discovery.py; pass --discovery-script")
	return ""
}

func fatal(format string, values ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", values...)
	os.Exit(1)
}
