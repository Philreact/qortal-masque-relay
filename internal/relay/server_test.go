package relay

import (
	"context"
	"net"
	"net/netip"
	"path/filepath"
	"testing"
	"time"

	masqueclient "qortal.org/qortal-masque-relay/internal/masque"
)

func TestPubliclyRoutable(t *testing.T) {
	for _, value := range []string{"127.0.0.1", "10.0.0.1", "192.168.1.2", "169.254.1.1", "198.51.100.2", "203.0.113.9", "::1", "2001:db8::1", "fe80::1"} {
		if publiclyRoutable(netip.MustParseAddr(value)) {
			t.Fatalf("expected %s to be rejected", value)
		}
	}
	for _, value := range []string{"8.8.8.8", "1.1.1.1", "2606:4700:4700::1111"} {
		if !publiclyRoutable(netip.MustParseAddr(value)) {
			t.Fatalf("expected %s to be accepted", value)
		}
	}
}

func TestRelayCarriesDatagramToAllowlistedTarget(t *testing.T) {
	echo, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	target := echo.LocalAddr().(*net.UDPAddr).AddrPort()
	go func() {
		buffer := make([]byte, 1500)
		for {
			n, source, readErr := echo.ReadFromUDP(buffer)
			if readErr != nil {
				return
			}
			_, _ = echo.WriteToUDP(buffer[:n], source)
		}
	}()

	reserved, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	relayAddress := reserved.LocalAddr().String()
	_ = reserved.Close()
	state := t.TempDir()
	server, metadata, err := Start(Config{
		ListenAddress:       relayAddress,
		PublicAddress:       relayAddress,
		ServerName:          "relay.test",
		CertificatePath:     filepath.Join(state, "cert.pem"),
		PrivateKeyPath:      filepath.Join(state, "key.pem"),
		AllowedTargets:      []netip.AddrPort{target},
		AllowLocalAdvertise: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()

	tunnel, err := masqueclient.Open(context.Background(), masqueclient.Config{
		RelayAddress:    metadata.RelayAddress,
		RelayServerName: metadata.RelayServerName,
		RelayCertSHA256: metadata.RelayCertSHA256,
		TargetAddress:   target.String(),
		Timeout:         3 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer tunnel.Close()
	payload := []byte("standalone-relay")
	if err := tunnel.Send(payload); err != nil {
		t.Fatal(err)
	}
	received, err := tunnel.Receive(3 * time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if string(received) != string(payload) {
		t.Fatalf("received %q, want %q", received, payload)
	}
}

func TestExplicitTargetAllowlist(t *testing.T) {
	target := netip.MustParseAddrPort("127.0.0.1:9000")
	server := &Server{allowedTargets: map[netip.AddrPort]struct{}{target: {}}}
	if !server.targetAllowed(target) {
		t.Fatal("allowlisted target was rejected")
	}
	if server.targetAllowed(netip.MustParseAddrPort("127.0.0.1:9001")) {
		t.Fatal("non-allowlisted target was accepted")
	}
}

func TestPublicTargetsAndOptionalLocalExceptions(t *testing.T) {
	for _, localException := range []bool{false, true} {
		server := &Server{allowedTargets: make(map[netip.AddrPort]struct{})}
		if localException {
			server.allowedTargets[netip.MustParseAddrPort("127.0.0.1:9000")] = struct{}{}
		}
		for _, value := range []string{"8.8.8.8:9000", "[2606:4700:4700::1111]:9000", "[::ffff:8.8.8.8]:9000"} {
			if !server.targetAllowed(netip.MustParseAddrPort(value)) {
				t.Errorf("public target %s blocked (exception=%v)", value, localException)
			}
		}
		for _, value := range []string{"127.0.0.1:9000", "[::ffff:127.0.0.1]:9000"} {
			if server.targetAllowed(netip.MustParseAddrPort(value)) != localException {
				t.Errorf("incorrect exception handling for %s", value)
			}
		}
		for _, value := range []string{"127.0.0.1:9001", "10.0.0.1:9000", "[::1]:9000",
			"169.254.169.254:80", "100.64.0.1:9000", "224.0.0.1:9000",
			"0.0.0.0:9000", "255.255.255.255:9000", "[fe80::1]:9000", "[ff02::1]:9000",
			"8.8.8.8:0", "203.0.113.1:9000"} {
			if server.targetAllowed(netip.MustParseAddrPort(value)) {
				t.Errorf("blocked target %s accepted (exception=%v)", value, localException)
			}
		}
	}
}

func TestExceptionsCannotEnableInvalidOrLinkLocalDestinations(t *testing.T) {
	for _, value := range []string{"224.0.0.1:9000", "0.0.0.0:9000",
		"169.254.169.254:80", "[ff02::1]:9000", "[fe80::1]:9000"} {
		target := netip.MustParseAddrPort(value)
		server := &Server{allowedTargets: map[netip.AddrPort]struct{}{target: {}}}
		if server.targetAllowed(target) {
			t.Errorf("exception enabled invalid or link-local target %s", value)
		}
	}
}
