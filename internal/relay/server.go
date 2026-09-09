// Package relay implements the standalone Qortal MASQUE relay server.
package relay

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	masque "github.com/quic-go/masque-go"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/yosida95/uritemplate/v3"
)

type Config struct {
	Access              AccessConfig
	ListenAddress       string
	PublicAddress       string
	ServerName          string
	CertificatePath     string
	PrivateKeyPath      string
	AllowedTargets      []netip.AddrPort
	AllowPrivateTargets bool
	AllowLocalAdvertise bool
	MaxSessions         int
}

type Server struct {
	tickets         *ticketAuthority
	mu              sync.Mutex
	server          *http3.Server
	proxy           masque.Proxy
	udp             *net.UDPConn
	config          Config
	allowedTargets  map[netip.AddrPort]struct{}
	activeByAddress map[string]int
	activeSessions  int
	closed          bool
}

type Metadata struct {
	RelayAddress    string `json:"relayAddress"`
	RelayServerName string `json:"relayServerName"`
	RelayCertSHA256 string `json:"relayCertSha256"`
}

func Start(config Config) (*Server, Metadata, error) {
	if config.MaxSessions <= 0 {
		config.MaxSessions = 256
	}
	if config.ServerName == "" || len(config.ServerName) > 128 {
		return nil, Metadata{}, errors.New("server name is required and must be at most 128 characters")
	}
	listen, err := netip.ParseAddrPort(config.ListenAddress)
	if err != nil || !listen.Addr().IsValid() || listen.Port() == 0 {
		return nil, Metadata{}, errors.New("listen address must be a literal IP endpoint")
	}
	public, err := netip.ParseAddrPort(config.PublicAddress)
	if err != nil || !public.Addr().IsValid() || public.Port() == 0 {
		return nil, Metadata{}, errors.New("public address must be a literal IP endpoint")
	}
	if !publiclyRoutable(public.Addr()) && !(config.AllowLocalAdvertise && public.Addr().IsLoopback()) {
		return nil, Metadata{}, errors.New("public address must be globally routable")
	}
	certificate, leafDER, err := loadOrCreateCertificate(config)
	if err != nil {
		return nil, Metadata{}, err
	}
	pin := sha256.Sum256(leafDER)
	policy, err := newAccessPolicy(config.Access, hex.EncodeToString(pin[:]))
	if err != nil {
		return nil, Metadata{}, err
	}
	var tickets *ticketAuthority
	started := false
	if policy.config.Mode == "groups" {
		tickets, err = newTicketAuthority(policy, filepath.Dir(config.PrivateKeyPath))
		if err != nil {
			return nil, Metadata{}, err
		}
		policy.tickets = tickets
		defer func() {
			if !started {
				tickets.close()
			}
		}()
		if err = tickets.serve(filepath.Join(filepath.Dir(config.PrivateKeyPath), "ticket-authority.sock")); err != nil {
			return nil, Metadata{}, err
		}
	}
	// The signed v2 payload must fit the smallest supported Reticulum announce
	// packet. Reject unadvertisable configurations before opening the socket.
	groupBytes := 0
	for _, id := range config.Access.AllowedGroupIDs {
		groupBytes++
		for id >= 128 {
			groupBytes++
			id >>= 7
		}
	}
	tail := 96
	header := 4
	if tickets != nil {
		tail = 160
		header = 3
	}
	if header+len(public.Addr().AsSlice())+6+32+len(config.ServerName)+groupBytes+tail > 316 {
		return nil, Metadata{}, errors.New("relay name and group list exceed Reticulum announcement capacity")
	}
	udp, err := net.ListenUDP("udp", net.UDPAddrFromAddrPort(listen))
	if err != nil {
		return nil, Metadata{}, err
	}
	server := &Server{
		tickets:         tickets,
		udp:             udp,
		config:          config,
		allowedTargets:  make(map[netip.AddrPort]struct{}),
		activeByAddress: make(map[string]int),
	}
	for _, target := range config.AllowedTargets {
		target = netip.AddrPortFrom(target.Addr().Unmap(), target.Port())
		server.allowedTargets[target] = struct{}{}
	}
	template := uritemplate.MustNew("https://" + public.String() + "/.well-known/masque/udp/{target_host}/{target_port}/")
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/masque/udp/", func(w http.ResponseWriter, request *http.Request) {
		account, authorized := policy.authorize(w, request)
		if !authorized {
			return
		}
		if request.Header.Get("Qortal-Relay-Control") == "authorize" {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		proxyRequest, parseErr := masque.ParseProxyRequest(request, template)
		if parseErr != nil {
			fmt.Fprintln(os.Stderr, "MASQUE CONNECT-UDP request rejected: invalid request")
			http.Error(w, "invalid CONNECT-UDP request", http.StatusBadRequest)
			return
		}
		target, parseErr := netip.ParseAddrPort(proxyRequest.Target)
		if parseErr == nil {
			target = netip.AddrPortFrom(target.Addr().Unmap(), target.Port())
		}
		if parseErr != nil || !server.targetAllowed(target) {
			fmt.Fprintf(os.Stderr, "MASQUE CONNECT-UDP request rejected: target %s is not permitted\n", target)
			accessError(w, http.StatusForbidden, "RELAY_TARGET_DENIED")
			return
		}
		fmt.Fprintf(os.Stderr, "MASQUE CONNECT-UDP request accepted for target %s\n", target)
		source := sourceHost(request.RemoteAddr)
		if account != "" {
			source = "account:" + account
		}
		if !server.acquire(source) {
			w.Header().Set("Retry-After", "5")
			accessError(w, http.StatusTooManyRequests, "RELAY_FULL")
			return
		}
		defer server.release(source)
		egress, dialErr := net.DialUDP("udp", nil, net.UDPAddrFromAddrPort(target))
		if dialErr != nil {
			http.Error(w, "target unavailable", http.StatusBadGateway)
			return
		}
		defer egress.Close()
		_ = server.proxy.ProxyConnectedSocket(w, proxyRequest, egress)
	})
	server.server = &http3.Server{
		ConnContext:    policy.connectionContext,
		MaxHeaderBytes: 8192,
		TLSConfig: &tls.Config{
			MinVersion:   tls.VersionTLS13,
			Certificates: []tls.Certificate{certificate},
			NextProtos:   []string{http3.NextProtoH3},
		},
		QUICConfig: &quic.Config{
			EnableDatagrams:    true,
			MaxIdleTimeout:     2 * time.Minute,
			MaxIncomingStreams: 512,
			KeepAlivePeriod:    30 * time.Second,
		},
		EnableDatagrams: true,
		Handler:         mux,
	}
	go func() { _ = server.server.Serve(udp) }()
	started = true
	return server, Metadata{
		RelayAddress:    public.String(),
		RelayServerName: config.ServerName,
		RelayCertSHA256: hex.EncodeToString(pin[:]),
	}, nil
}

func (s *Server) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	s.mu.Unlock()
	_ = s.proxy.Close()
	if s.server != nil {
		_ = s.server.Close()
	}
	if s.tickets != nil {
		s.tickets.close()
	}
	if s.udp != nil {
		return s.udp.Close()
	}
	return nil
}

func (s *Server) ActiveSessions() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.activeSessions
}

func (s *Server) targetAllowed(target netip.AddrPort) bool {
	if !target.IsValid() || target.Port() == 0 {
		return false
	}
	target = netip.AddrPortFrom(target.Addr().Unmap(), target.Port())
	address := target.Addr()
	if address.IsUnspecified() || address.IsMulticast() || address.Zone() != "" {
		return false
	}
	if publiclyRoutable(address) {
		return true
	}
	if address.IsPrivate() || address.IsLoopback() {
		_, explicitlyAllowed := s.allowedTargets[target]
		return explicitlyAllowed || s.config.AllowPrivateTargets
	}
	return false
}

func (s *Server) acquire(source string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.activeSessions >= s.config.MaxSessions || s.activeByAddress[source] >= 8 {
		return false
	}
	s.activeSessions++
	s.activeByAddress[source]++
	return true
}

func (s *Server) release(source string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.activeSessions > 0 {
		s.activeSessions--
	}
	if s.activeByAddress[source] <= 1 {
		delete(s.activeByAddress, source)
	} else {
		s.activeByAddress[source]--
	}
}

func sourceHost(value string) string {
	host, _, err := net.SplitHostPort(value)
	if err != nil || host == "" {
		return value
	}
	return host
}

func publiclyRoutable(address netip.Addr) bool {
	address = address.Unmap()
	if !address.IsValid() || address.IsUnspecified() || address.IsLoopback() || address.IsMulticast() || address.IsLinkLocalUnicast() || address.IsPrivate() {
		return false
	}
	if address.Is4() {
		octets := address.As4()
		if octets[0] == 0 || octets[0] >= 224 || (octets[0] == 100 && octets[1] >= 64 && octets[1] <= 127) || (octets[0] == 192 && octets[1] == 0) || (octets[0] == 198 && (octets[1] == 18 || octets[1] == 19)) || (octets[0] == 198 && octets[1] == 51 && octets[2] == 100) || (octets[0] == 203 && octets[1] == 0 && octets[2] == 113) {
			return false
		}
	}
	if netip.MustParsePrefix("2001:db8::/32").Contains(address) {
		return false
	}
	return true
}

func loadOrCreateCertificate(config Config) (tls.Certificate, []byte, error) {
	if config.CertificatePath == "" || config.PrivateKeyPath == "" {
		return tls.Certificate{}, nil, errors.New("certificate and private-key paths are required")
	}
	if cert, err := tls.LoadX509KeyPair(config.CertificatePath, config.PrivateKeyPath); err == nil {
		if len(cert.Certificate) == 0 {
			return tls.Certificate{}, nil, errors.New("certificate has no leaf")
		}
		leaf, parseErr := x509.ParseCertificate(cert.Certificate[0])
		if parseErr == nil && time.Now().Add(24*time.Hour).Before(leaf.NotAfter) && leaf.VerifyHostname(config.ServerName) == nil {
			return cert, cert.Certificate[0], nil
		}
	} else if !errors.Is(err, os.ErrNotExist) && !strings.Contains(err.Error(), "no such file") {
		return tls.Certificate{}, nil, fmt.Errorf("load relay certificate: %w", err)
	}
	return createCertificate(config)
}

func createCertificate(config Config) (tls.Certificate, []byte, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(now.UnixNano()),
		Subject:      pkix.Name{CommonName: config.ServerName},
		DNSNames:     []string{config.ServerName},
		NotBefore:    now.Add(-time.Minute),
		NotAfter:     now.AddDate(1, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	if err := os.MkdirAll(filepath.Dir(config.CertificatePath), 0o700); err != nil {
		return tls.Certificate{}, nil, err
	}
	if err := os.MkdirAll(filepath.Dir(config.PrivateKeyPath), 0o700); err != nil {
		return tls.Certificate{}, nil, err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	if err := os.WriteFile(config.CertificatePath, certPEM, 0o600); err != nil {
		return tls.Certificate{}, nil, err
	}
	if err := os.WriteFile(config.PrivateKeyPath, keyPEM, 0o600); err != nil {
		return tls.Certificate{}, nil, err
	}
	certificate, err := tls.X509KeyPair(certPEM, keyPEM)
	return certificate, der, err
}

func (s *Server) Shutdown(ctx context.Context) error {
	if s.server == nil {
		return s.Close()
	}
	done := make(chan error, 1)
	go func() { done <- s.Close() }()
	select {
	case err := <-done:
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}
