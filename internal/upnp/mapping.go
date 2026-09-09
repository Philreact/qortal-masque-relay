// Package upnp manages the relay's public UDP port mapping.
package upnp

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"time"

	"github.com/huin/goupnp/dcps/internetgateway2"
)

const (
	defaultLeaseSeconds = 7200
	discoveryTimeout    = 8 * time.Second
)

type gatewayClient interface {
	LocalAddr() net.IP
	GetExternalIPAddressCtx(context.Context) (string, error)
	AddPortMappingCtx(context.Context, string, uint16, string, uint16, string, bool, string, uint32) error
	DeletePortMappingCtx(context.Context, string, uint16, string) error
}

// Mapping owns one UPnP UDP mapping. Close removes it from the router.
type Mapping struct {
	client       gatewayClient
	internalPort uint16
	externalPort uint16
	description  string
	leaseSeconds uint32
	publicIP     netip.Addr
}

// Open discovers an Internet Gateway Device, maps the UDP port, and returns
// the router-reported public endpoint. It deliberately rejects private/CGNAT
// addresses because those endpoints cannot serve remote Qortal users.
func Open(ctx context.Context, port uint16, description string) (*Mapping, error) {
	if port == 0 {
		return nil, errors.New("UPnP port must be non-zero")
	}
	discoveryCtx, cancel := context.WithTimeout(ctx, discoveryTimeout)
	defer cancel()

	clients, discoveryErrors, err := discoverClients(discoveryCtx)
	if err != nil && len(clients) == 0 {
		return nil, fmt.Errorf("discover UPnP gateway: %w", err)
	}
	var failures []string
	for _, discoveryErr := range discoveryErrors {
		failures = append(failures, discoveryErr.Error())
	}
	for _, client := range clients {
		mapping, mapErr := openWithClient(ctx, client, port, description)
		if mapErr == nil {
			return mapping, nil
		}
		failures = append(failures, mapErr.Error())
	}
	if len(failures) == 0 {
		return nil, errors.New("no UPnP Internet Gateway Device found")
	}
	return nil, fmt.Errorf("no usable UPnP mapping: %s", strings.Join(failures, "; "))
}

func (mapping *Mapping) PublicAddress() netip.AddrPort {
	return netip.AddrPortFrom(mapping.publicIP, mapping.externalPort)
}

// Maintain refreshes the finite lease. A refresh failure is returned so the
// relay can stop advertising an endpoint that may no longer be reachable.
func (mapping *Mapping) Maintain(ctx context.Context) error {
	interval := time.Duration(mapping.leaseSeconds/2) * time.Second
	if interval < 10*time.Minute {
		interval = 10 * time.Minute
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			refreshCtx, cancel := context.WithTimeout(ctx, discoveryTimeout)
			err := mapping.add(refreshCtx)
			cancel()
			if err != nil {
				return fmt.Errorf("refresh UPnP UDP mapping: %w", err)
			}
		}
	}
}

func (mapping *Mapping) Close(ctx context.Context) error {
	return mapping.client.DeletePortMappingCtx(ctx, "", mapping.externalPort, "UDP")
}

func (mapping *Mapping) add(ctx context.Context) error {
	return mapping.client.AddPortMappingCtx(
		ctx,
		"",
		mapping.externalPort,
		"UDP",
		mapping.internalPort,
		mapping.client.LocalAddr().String(),
		true,
		mapping.description,
		mapping.leaseSeconds,
	)
}

func openWithClient(ctx context.Context, client gatewayClient, port uint16, description string) (*Mapping, error) {
	external, err := client.GetExternalIPAddressCtx(ctx)
	if err != nil {
		return nil, fmt.Errorf("read router external IP: %w", err)
	}
	publicIP, err := netip.ParseAddr(strings.TrimSpace(external))
	if err != nil || !isPublicInternetAddress(publicIP) {
		return nil, fmt.Errorf("router reported non-public external IP %q", external)
	}
	localIP, ok := netip.AddrFromSlice(client.LocalAddr())
	if !ok || !localIP.IsValid() || localIP.IsUnspecified() {
		return nil, errors.New("UPnP gateway did not provide a usable local address")
	}
	mapping := &Mapping{
		client:       client,
		internalPort: port,
		externalPort: port,
		description:  description,
		leaseSeconds: defaultLeaseSeconds,
		publicIP:     publicIP.Unmap(),
	}
	mapCtx, cancel := context.WithTimeout(ctx, discoveryTimeout)
	defer cancel()
	if err := mapping.add(mapCtx); err != nil {
		return nil, fmt.Errorf("map UDP %d: %w", port, err)
	}
	return mapping, nil
}

func isPublicInternetAddress(address netip.Addr) bool {
	if !address.IsValid() || !address.IsGlobalUnicast() || address.IsPrivate() || address.IsLoopback() || address.IsLinkLocalUnicast() {
		return false
	}
	if address.Is4() {
		value := address.As4()
		// RFC 6598 shared carrier-grade NAT space (100.64.0.0/10).
		if value[0] == 100 && value[1] >= 64 && value[1] <= 127 {
			return false
		}
	}
	return true
}

func discoverClients(ctx context.Context) ([]gatewayClient, []error, error) {
	var clients []gatewayClient
	var discoveryErrors []error
	var fatalErrors []error

	ip2, errs, err := internetgateway2.NewWANIPConnection2ClientsCtx(ctx)
	for _, client := range ip2 {
		clients = append(clients, client)
	}
	discoveryErrors = append(discoveryErrors, errs...)
	if err != nil {
		fatalErrors = append(fatalErrors, err)
	}

	ip1, errs, err := internetgateway2.NewWANIPConnection1ClientsCtx(ctx)
	for _, client := range ip1 {
		clients = append(clients, client)
	}
	discoveryErrors = append(discoveryErrors, errs...)
	if err != nil {
		fatalErrors = append(fatalErrors, err)
	}

	ppp1, errs, err := internetgateway2.NewWANPPPConnection1ClientsCtx(ctx)
	for _, client := range ppp1 {
		clients = append(clients, client)
	}
	discoveryErrors = append(discoveryErrors, errs...)
	if err != nil {
		fatalErrors = append(fatalErrors, err)
	}

	return clients, discoveryErrors, errors.Join(fatalErrors...)
}
