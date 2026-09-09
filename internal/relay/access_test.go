package relay

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	masque "github.com/quic-go/masque-go"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/yosida95/uritemplate/v3"
)

func signChallenge(t *testing.T, challenge string, key ed25519.PrivateKey, mutate func(map[string]any)) string {
	t.Helper()
	var fields map[string]any
	if err := json.Unmarshal([]byte(challenge), &fields); err != nil {
		t.Fatal(err)
	}
	pub := key.Public().(ed25519.PublicKey)
	fields["authorAddress"] = addressForKey(pub)
	fields["authorPublicKey"] = encodeBase58(pub)
	if mutate != nil {
		mutate(fields)
	}
	raw, _ := json.Marshal(fields)
	fields["signature"] = encodeBase58(ed25519.Sign(key, raw))
	raw, _ = json.Marshal(fields)
	return string(raw)
}

func TestAccessConfigRejectsUnsafeRestrictions(t *testing.T) {
	for _, c := range []AccessConfig{
		{Mode: "groups"}, {Mode: "public", AllowedGroupIDs: []int32{1}},
		{Mode: "groups", AllowedGroupIDs: []int32{1, 1}, CoreURLBases: []string{"https://core.test"}},
		{Mode: "groups", AllowedGroupIDs: []int32{1}, CoreURLBases: []string{"http://core.test"}},
		{Mode: "groups", AllowedGroupIDs: []int32{1}, CoreURLBases: []string{"https://user:secret@core.test"}},
	} {
		if c.validate() == nil {
			t.Fatalf("accepted unsafe config: %+v", c)
		}
	}
	c := AccessConfig{Mode: "public"}
	if c.validate() != nil {
		t.Fatal("public default rejected")
	}
}

func TestAccessConfigFileIsStrict(t *testing.T) {
	for _, raw := range []string{`{"mode":"groups","mode":"public"}`, `{"mode":"public","typo":[]}`, `{"mode":"public"} {}`, `null`, strings.Repeat(" ", 16385)} {
		path := filepath.Join(t.TempDir(), "access.json")
		if err := os.WriteFile(path, []byte(raw), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadAccessConfig(path); err == nil {
			t.Fatalf("accepted invalid config %q", raw[:min(len(raw), 80)])
		}
	}
}

func TestMembershipAnyGroupBackupsAndFailClosed(t *testing.T) {
	var calls atomic.Int32
	good := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		var addresses []string
		if r.Method != "POST" || json.NewDecoder(r.Body).Decode(&addresses) != nil || len(addresses) != 1 {
			t.Error("invalid Core request")
			w.WriteHeader(400)
			return
		}
		switch {
		case strings.Contains(r.URL.Path, "/2/"):
			w.WriteHeader(503)
		case strings.Contains(r.URL.Path, "/3/"):
			fmt.Fprintf(w, `[{"address":%q,"isMember":true,"isAdmin":false}]`, addresses[0])
		case strings.Contains(r.URL.Path, "/4/"):
			fmt.Fprint(w, `[{"address":"wrong","isMember":true}]`)
		default:
			fmt.Fprintf(w, `[{"address":%q,"isMember":false,"isAdmin":true}]`, addresses[0])
		}
	}))
	defer good.Close()
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(503) }))
	defer bad.Close()
	for _, tc := range []struct {
		ids                 []int32
		member, unavailable bool
	}{
		{[]int32{1}, false, false}, {[]int32{1, 3}, true, false}, {[]int32{1, 2}, false, true},
		{[]int32{2, 3}, true, false}, {[]int32{4}, false, true},
	} {
		p, err := newAccessPolicy(AccessConfig{Mode: "groups", AllowedGroupIDs: tc.ids, CoreURLBases: []string{bad.URL, good.URL}}, "pin")
		if err != nil {
			t.Fatal(err)
		}
		result := p.membership(context.Background(), "address")
		if result.member != tc.member || (result.err != nil) != tc.unavailable {
			t.Fatalf("%v: %+v", tc.ids, result)
		}
		if result.err == nil {
			before := calls.Load()
			p.membership(context.Background(), "address")
			if calls.Load() != before {
				t.Fatal("membership cache not reused")
			}
		}
	}
	// A valid negative is authoritative; do not search backups for a positive.
	p, _ := newAccessPolicy(AccessConfig{Mode: "groups", AllowedGroupIDs: []int32{1}, CoreURLBases: []string{good.URL, bad.URL}}, "pin")
	if r := p.membership(context.Background(), "address"); r.err != nil || r.member {
		t.Fatal(r)
	}
}

func TestRestrictedRelayRealQUICAuthorizationAndExpiry(t *testing.T) {
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	core := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, `[{"address":%q,"isMember":true}]`, addressForKey(pub))
	}))
	defer core.Close()
	echo, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	var packets atomic.Int32
	go func() {
		b := make([]byte, 1500)
		for {
			n, a, e := echo.ReadFromUDP(b)
			if e != nil {
				return
			}
			packets.Add(1)
			echo.WriteToUDP(b[:n], a)
		}
	}()
	target := echo.LocalAddr().(*net.UDPAddr).AddrPort()
	reservation, _ := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	address := reservation.LocalAddr().String()
	reservation.Close()
	dir := t.TempDir()
	server, _, err := Start(Config{ListenAddress: address, PublicAddress: address, ServerName: "relay.test", CertificatePath: filepath.Join(dir, "cert"), PrivateKeyPath: filepath.Join(dir, "key"), AllowedTargets: []netip.AddrPort{target}, AllowLocalAdvertise: true, Access: AccessConfig{Mode: "groups", AllowedGroupIDs: []int32{1}, CoreURLBases: []string{core.URL}}})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	// Capture connection state only in this in-package integration test.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := quic.DialAddr(ctx, address, &tls.Config{InsecureSkipVerify: true, NextProtos: []string{http3.NextProtoH3}}, &quic.Config{EnableDatagrams: true})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.CloseWithError(0, "")
	tr := &masque.Transport{}
	client, err := tr.NewClientConn(conn)
	if err != nil {
		t.Fatal(err)
	}
	template := uritemplate.MustNew("https://" + address + "/.well-known/masque/udp/{target_host}/{target_port}/")
	request, _ := masque.NewRequest(ctx, template, target.String())
	tunnel, response, err := client.Dial(request)
	if err == nil || tunnel != nil || response == nil || response.StatusCode != 401 || packets.Load() != 0 {
		t.Fatal("unauthorized forwarding was not rejected")
	}
	tickets := issueTestTickets(t, server.tickets, key)
	request, _ = masque.NewRequest(ctx, template, "0.0.0.0:1")
	request.Header().Set("Qortal-Relay-Control", "authorize")
	request.Header().Set("Qortal-Relay-Ticket", tickets[0])
	control, response, err := client.Dial(request)
	if err != nil || response.StatusCode != 204 {
		t.Fatalf("authorize: %v %+v", err, response)
	}
	control.Close()
	request, _ = masque.NewRequest(ctx, template, target.String())
	tunnel, _, err = client.Dial(request)
	if err != nil {
		t.Fatal(err)
	}
	defer tunnel.Close()
	if _, err = tunnel.WriteTo([]byte("authorized"), net.UDPAddrFromAddrPort(target)); err != nil {
		t.Fatal(err)
	}
	tunnel.SetReadDeadline(time.Now().Add(time.Second))
	b := make([]byte, 64)
	n, _, err := tunnel.ReadFrom(b)
	if err != nil || string(b[:n]) != "authorized" {
		t.Fatalf("echo: %q %v", b[:n], err)
	}
	// Expiry must close a connection even while its authorization lock is held.
	a := &connectionAuthorization{conn: conn}
	a.timerGeneration.Store(2)
	a.expire(1)
	if conn.Context().Err() != nil {
		t.Fatal("superseded timer closed renewed connection")
	}
	a.mu.Lock()
	a.expire(2)
	a.mu.Unlock()
	select {
	case <-conn.Context().Done():
	case <-time.After(time.Second):
		t.Fatal("expiration failed to close connection")
	}
}
