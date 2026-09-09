package masqueclient

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"time"

	masque "github.com/quic-go/masque-go"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/yosida95/uritemplate/v3"
)

const MaxDatagramBytes = 1200

type Config struct {
	RelayAddress    string
	RelayServerName string
	RelayCertSHA256 string
	TargetAddress   string
	Timeout         time.Duration
}

type Tunnel struct {
	conn net.PacketConn
}

func Open(ctx context.Context, cfg Config) (*Tunnel, error) {
	relay, err := parseLiteralAddrPort("relayAddress", cfg.RelayAddress)
	if err != nil {
		return nil, err
	}
	target, err := parseLiteralAddrPort("targetAddress", cfg.TargetAddress)
	if err != nil {
		return nil, err
	}
	if cfg.RelayServerName == "" {
		return nil, errors.New("relayServerName is required")
	}
	pin, err := hex.DecodeString(cfg.RelayCertSHA256)
	if err != nil || len(pin) != sha256.Size {
		return nil, errors.New("relayCertSha256 must be a 64-character hexadecimal SHA-256 hash")
	}

	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	relayAddress := relay.String()
	tlsConfig := &tls.Config{
		MinVersion:         tls.VersionTLS13,
		NextProtos:         []string{http3.NextProtoH3},
		ServerName:         cfg.RelayServerName,
		InsecureSkipVerify: true,
		VerifyConnection: func(state tls.ConnectionState) error {
			if len(state.PeerCertificates) == 0 {
				return errors.New("relay did not present a certificate")
			}
			leaf := state.PeerCertificates[0]
			if now := time.Now(); now.Before(leaf.NotBefore) || now.After(leaf.NotAfter) {
				return errors.New("relay certificate is outside its validity period")
			}
			if err := leaf.VerifyHostname(cfg.RelayServerName); err != nil {
				return errors.New("relay certificate identity mismatch")
			}
			observed := sha256.Sum256(leaf.Raw)
			if subtle.ConstantTimeCompare(observed[:], pin) != 1 {
				return errors.New("relay certificate pin mismatch")
			}
			return nil
		},
	}

	proxyTemplate := uritemplate.MustNew(fmt.Sprintf(
		"https://%s/.well-known/masque/udp/{target_host}/{target_port}/",
		relayAddress,
	))
	request, err := masque.NewRequest(ctx, proxyTemplate, target.String())
	if err != nil {
		return nil, fmt.Errorf("create CONNECT-UDP request: %w", err)
	}
	transport := masque.Transport{
		TLSClientConfig: tlsConfig,
		QUICConfig:      &quic.Config{EnableDatagrams: true},
		DialAddr: func(dialCtx context.Context, address string, tlsConf *tls.Config, quicConf *quic.Config) (*quic.Conn, error) {
			if address != relayAddress {
				return nil, fmt.Errorf("unexpected relay address %q", address)
			}
			return quic.DialAddr(dialCtx, relayAddress, tlsConf, quicConf)
		},
	}
	connection, _, err := transport.Dial(request)
	if err != nil {
		return nil, fmt.Errorf("open CONNECT-UDP tunnel: %w", err)
	}
	return &Tunnel{conn: connection}, nil
}

func parseLiteralAddrPort(name, value string) (netip.AddrPort, error) {
	address, err := netip.ParseAddrPort(value)
	if err != nil || !address.Addr().IsValid() || address.Port() == 0 {
		return netip.AddrPort{}, fmt.Errorf("%s must be a literal IP address and non-zero port", name)
	}
	return address, nil
}

func (t *Tunnel) Send(data []byte) error {
	if len(data) == 0 || len(data) > MaxDatagramBytes {
		return fmt.Errorf("datagram must contain 1..%d bytes", MaxDatagramBytes)
	}
	_, err := t.conn.WriteTo(data, nil)
	return err
}

func (t *Tunnel) Receive(timeout time.Duration) ([]byte, error) {
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	if err := t.conn.SetReadDeadline(time.Now().Add(timeout)); err != nil {
		return nil, err
	}
	buffer := make([]byte, 1500)
	n, _, err := t.conn.ReadFrom(buffer)
	if err != nil {
		return nil, err
	}
	return append([]byte(nil), buffer[:n]...), nil
}

func (t *Tunnel) Close() error { return t.conn.Close() }
