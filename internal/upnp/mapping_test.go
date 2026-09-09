package upnp

import (
	"net/netip"
	"testing"
)

func TestIsPublicInternetAddress(t *testing.T) {
	tests := []struct {
		address string
		want    bool
	}{
		{"8.8.8.8", true},
		{"2001:4860:4860::8888", true},
		{"127.0.0.1", false},
		{"192.168.1.10", false},
		{"10.0.0.1", false},
		{"100.64.0.1", false},
		{"100.127.255.254", false},
		{"169.254.1.1", false},
	}
	for _, test := range tests {
		t.Run(test.address, func(t *testing.T) {
			if got := isPublicInternetAddress(netip.MustParseAddr(test.address)); got != test.want {
				t.Fatalf("isPublicInternetAddress(%s) = %v, want %v", test.address, got, test.want)
			}
		})
	}
}
