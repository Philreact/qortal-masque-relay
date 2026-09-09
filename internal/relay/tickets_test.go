package relay

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/cloudflare/circl/blindsign/blindrsa"
	bolt "go.etcd.io/bbolt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func authorityRequest(t *testing.T, a *ticketAuthority, path string, data any) *httptest.ResponseRecorder {
	t.Helper()
	raw, _ := json.Marshal(data)
	w := httptest.NewRecorder()
	a.handle(w, httptest.NewRequest("POST", path, strings.NewReader(string(raw))))
	return w
}
func issueTestTickets(t *testing.T, a *ticketAuthority, key ed25519.PrivateKey) []string {
	t.Helper()
	d, private, err := a.descriptor(time.Now().Unix() / 3600)
	if err != nil {
		t.Fatal(err)
	}
	client, _ := blindrsa.NewClient(blindrsa.SHA384PSSDeterministic, &private.PublicKey)
	var blinded []string
	var states []blindrsa.State
	var messages [][]byte
	for i := 0; i < 3; i++ {
		nonce := make([]byte, 32)
		rand.Read(nonce)
		msg := append([]byte(ticketDomain+d.KeyID), nonce...)
		b, s, e := client.Blind(rand.Reader, msg)
		if e != nil {
			t.Fatal(e)
		}
		blinded = append(blinded, base64.StdEncoding.EncodeToString(b))
		states = append(states, s)
		messages = append(messages, msg)
	}
	input := map[string]any{"descriptor": d, "blinded": blinded}
	c := authorityRequest(t, a, "/challenge", input)
	if c.Code != 200 {
		t.Fatal(c.Body.String())
	}
	var proof relayProof
	json.Unmarshal([]byte(signChallenge(t, c.Body.String(), key, nil)), &proof)
	input["proof"] = proof
	w := authorityRequest(t, a, "/issue", input)
	if w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	var result struct {
		Signatures []string `json:"signatures"`
	}
	json.Unmarshal(w.Body.Bytes(), &result)
	var tokens []string
	for i, b := range result.Signatures {
		s, _ := base64.StdEncoding.DecodeString(b)
		sig, e := client.Finalize(states[i], s)
		if e != nil {
			t.Fatal(e)
		}
		raw, _ := json.Marshal(map[string]any{"epoch": d.Epoch, "keyId": d.KeyID, "message": base64.StdEncoding.EncodeToString(messages[i]), "signature": base64.StdEncoding.EncodeToString(sig)})
		tokens = append(tokens, string(raw))
	}
	if repeat := authorityRequest(t, a, "/issue", input); repeat.Code != 403 {
		t.Fatal("issuance challenge replay accepted")
	}
	return tokens
}
func testAuthority(t *testing.T) (*ticketAuthority, ed25519.PrivateKey, string) {
	t.Helper()
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	core := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var addresses []string
		json.NewDecoder(r.Body).Decode(&addresses)
		fmt.Fprintf(w, `[{"address":%q,"isMember":%t}]`, addresses[0], addresses[0] == addressForKey(pub))
	}))
	t.Cleanup(core.Close)
	p, _ := newAccessPolicy(AccessConfig{Mode: "groups", AllowedGroupIDs: []int32{1144}, CoreURLBases: []string{core.URL}}, strings.Repeat("ab", 32))
	dir := t.TempDir()
	a, err := newTicketAuthority(p, dir)
	if err != nil {
		t.Fatal(err)
	}
	p.tickets = a
	return a, key, dir
}
func TestAnonymousTicketsExpiryReplayAndRestart(t *testing.T) {
	a, key, dir := testAuthority(t)
	tokens := issueTestTickets(t, a, key)
	id, until, err := a.redeem(tokens[0])
	if err != nil || id == addressForKey(key.Public().(ed25519.PublicKey)) {
		t.Fatal("anonymous redemption failed", err)
	}
	remaining := time.Until(until)
	if remaining <= 11*time.Hour || remaining > 12*time.Hour {
		t.Fatal("unexpected expiry", remaining)
	}
	if _, _, err = a.redeem(tokens[0]); err == nil {
		t.Fatal("replay accepted")
	}
	policy := a.policy
	a.close()
	a, err = newTicketAuthority(policy, dir)
	if err != nil {
		t.Fatal(err)
	}
	defer a.close()
	if _, _, err = a.redeem(tokens[0]); err == nil {
		t.Fatal("replay accepted after restart")
	}
	if _, _, err = a.redeem(tokens[1]); err != nil {
		t.Fatal("unused ticket lost on restart", err)
	}
	var forged map[string]any
	json.Unmarshal([]byte(tokens[2]), &forged)
	for _, change := range []map[string]any{{"epoch": float64(time.Now().Unix()/3600 + 1)}, {"keyId": strings.Repeat("0", 64)}, {"signature": base64.StdEncoding.EncodeToString(make([]byte, 256))}, {"authorAddress": "injected"}} {
		copy := map[string]any{}
		for k, v := range forged {
			copy[k] = v
		}
		for k, v := range change {
			copy[k] = v
		}
		raw, _ := json.Marshal(copy)
		if _, _, e := a.redeem(string(raw)); e == nil {
			t.Fatal("forged ticket accepted")
		}
	}
	var successes atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, _, e := a.redeem(tokens[2]); e == nil {
				successes.Add(1)
			}
		}()
	}
	wg.Wait()
	if successes.Load() != 1 {
		t.Fatal("concurrent redemption", successes.Load())
	}
}
func TestIssuanceDeniesNonMembersAndInvalidProofs(t *testing.T) {
	a, key, _ := testAuthority(t)
	defer a.close()
	d, private, _ := a.descriptor(time.Now().Unix() / 3600)
	client, _ := blindrsa.NewClient(blindrsa.SHA384PSSDeterministic, &private.PublicKey)
	b, _, _ := client.Blind(rand.Reader, []byte("test"))
	for _, kind := range []string{"nonmember", "account", "signature", "binding", "policy", "pin", "expiry"} {
		t.Run(kind, func(t *testing.T) {
			input := map[string]any{"descriptor": d, "blinded": []string{base64.StdEncoding.EncodeToString(b)}}
			c := authorityRequest(t, a, "/challenge", input)
			signer := key
			if kind == "nonmember" {
				_, signer, _ = ed25519.GenerateKey(rand.Reader)
			}
			signed := signChallenge(t, c.Body.String(), signer, func(f map[string]any) {
				switch kind {
				case "account":
					f["authorAddress"] = "bad"
				case "binding":
					f["binding"] = "bad"
				case "policy":
					f["policy"] = "bad"
				case "pin":
					f["relayPin"] = "bad"
				case "expiry":
					f["expiresAt"] = 1
				}
			})
			var proof map[string]any
			json.Unmarshal([]byte(signed), &proof)
			if kind == "signature" {
				proof["signature"] = strings.Repeat("1", 64)
			}
			input["proof"] = proof
			w := authorityRequest(t, a, "/issue", input)
			if w.Code != 403 {
				t.Fatalf("accepted %s: %d", kind, w.Code)
			}
		})
	}
}
func TestQUICRejectsAccountProofAndDoesNotCheckMembership(t *testing.T) {
	a, key, _ := testAuthority(t)
	defer a.close()
	tokens := issueTestTickets(t, a, key)
	p := a.policy
	p.config.CoreURLBases = []string{"http://127.0.0.1:1"}
	p.cache = map[string]membershipResult{}
	auth := &connectionAuthorization{}
	req := httptest.NewRequest("CONNECT", "https://relay/", nil).WithContext(context.WithValue(context.Background(), relayAuthContextKey{}, auth))
	req.Header.Set("Qortal-Relay-Proof", `{"authorAddress":"account"}`)
	w := httptest.NewRecorder()
	if _, ok := p.authorize(w, req); ok || w.Code != 403 {
		t.Fatal("identity proof accepted")
	}
	req.Header.Del("Qortal-Relay-Proof")
	req.Header.Set("Qortal-Relay-Ticket", tokens[0])
	w = httptest.NewRecorder()
	if _, ok := p.authorize(w, req); !ok {
		t.Fatal("redemption needed Core", w.Body.String())
	}
}
func TestStrictTicketJSON(t *testing.T) {
	for _, raw := range []string{`{"x":1,"x":2}`, `{"x":1} {}`, `{"x":1,"other":2}`} {
		var v struct {
			X int `json:"x"`
		}
		if strictJSON([]byte(raw), &v) == nil {
			t.Fatal("unsafe JSON accepted")
		}
	}
}

func TestIssuanceQuotaAndClockRollbackPersist(t *testing.T) {
	a, key, dir := testAuthority(t)
	for i := 0; i < 8; i++ {
		issueTestTickets(t, a, key)
	}
	p := a.policy
	a.close()
	var err error
	a, err = newTicketAuthority(p, dir)
	if err != nil {
		t.Fatal(err)
	}
	defer a.close()
	d, private, _ := a.descriptor(time.Now().Unix() / 3600)
	client, _ := blindrsa.NewClient(blindrsa.SHA384PSSDeterministic, &private.PublicKey)
	blinded, _, _ := client.Blind(rand.Reader, []byte("quota test"))
	data := map[string]any{"descriptor": d, "blinded": []string{base64.StdEncoding.EncodeToString(blinded)}}
	c := authorityRequest(t, a, "/challenge", data)
	var proof relayProof
	json.Unmarshal([]byte(signChallenge(t, c.Body.String(), key, nil)), &proof)
	data["proof"] = proof
	if w := authorityRequest(t, a, "/issue", data); w.Code != 429 {
		t.Fatal("restart reset issuance quota", w.Code)
	}
	// A high-water mark from a later hour prevents expired keys from becoming
	// valid again if the system clock is rolled back across an expiry boundary.
	a.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket([]byte("meta")).Put([]byte("latestEpoch"), []byte(fmt.Sprint(time.Now().Unix()/3600+1)))
	})
	if _, _, err = a.descriptor(time.Now().Unix() / 3600); err == nil {
		t.Fatal("clock rollback accepted")
	}
}
