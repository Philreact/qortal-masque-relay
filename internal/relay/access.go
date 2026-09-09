package relay

// Access checks are performed before any UDP egress socket is opened. The
// authorization lifetime is measured from the membership lookup, never from
// the last use of a cache entry.
import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go"
	"golang.org/x/crypto/ripemd160"
)

type AccessConfig struct {
	Mode            string   `json:"mode"`
	AllowedGroupIDs []int32  `json:"allowed_group_ids"`
	CoreURLBases    []string `json:"core_url_bases"`
}

func LoadAccessConfig(path string) (AccessConfig, error) {
	f, err := os.Open(path)
	if err != nil {
		return AccessConfig{}, err
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, 16385))
	if err != nil {
		return AccessConfig{}, err
	}
	if len(raw) > 16384 {
		return AccessConfig{}, errors.New("access configuration exceeds 16 KiB")
	}
	keys := json.NewDecoder(bytes.NewReader(raw))
	opening, err := keys.Token()
	if err != nil || opening != json.Delim('{') {
		return AccessConfig{}, errors.New("access configuration must be an object")
	}
	seen := map[string]bool{}
	for keys.More() {
		key, err := keys.Token()
		if err != nil {
			return AccessConfig{}, err
		}
		name, ok := key.(string)
		if !ok || seen[name] {
			return AccessConfig{}, errors.New("duplicate access configuration key")
		}
		seen[name] = true
		var value json.RawMessage
		if err = keys.Decode(&value); err != nil {
			return AccessConfig{}, err
		}
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	var c AccessConfig
	if err = d.Decode(&c); err != nil {
		return c, err
	}
	var extra any
	if d.Decode(&extra) != io.EOF {
		return c, errors.New("access configuration has trailing data")
	}
	return c, c.validate()
}

func (c *AccessConfig) validate() error {
	if c.Mode != "public" && c.Mode != "groups" {
		return errors.New("access mode must be public or groups")
	}
	if c.Mode == "public" && len(c.AllowedGroupIDs) != 0 {
		return errors.New("public access cannot have group restrictions")
	}
	seen := map[int32]bool{}
	for _, id := range c.AllowedGroupIDs {
		if id <= 0 || seen[id] {
			return errors.New("group IDs must be unique positive integers")
		}
		seen[id] = true
	}
	if len(seen) > 16 || (c.Mode == "groups" && len(seen) == 0) {
		return errors.New("groups mode requires 1 to 16 group IDs")
	}
	if len(c.CoreURLBases) > 8 || (c.Mode == "groups" && len(c.CoreURLBases) == 0) {
		return errors.New("groups mode requires 1 to 8 Core URLs")
	}
	for i, base := range c.CoreURLBases {
		u, err := url.Parse(base)
		if err != nil || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Scheme != "https" && u.Scheme != "http") {
			return errors.New("invalid Core URL")
		}
		if u.Scheme == "http" && u.Hostname() != "127.0.0.1" && u.Hostname() != "localhost" && u.Hostname() != "::1" {
			return errors.New("remote Core URLs must use HTTPS")
		}
		c.CoreURLBases[i] = strings.TrimRight(base, "/")
	}
	sort.Slice(c.AllowedGroupIDs, func(i, j int) bool { return c.AllowedGroupIDs[i] < c.AllowedGroupIDs[j] })
	return nil
}

type membershipResult struct {
	member  bool
	checked time.Time
	err     error
}
type accessPolicy struct {
	tickets         *ticketAuthority
	config          AccessConfig
	revision        string
	pin             string
	client          *http.Client
	mu              sync.Mutex
	cache           map[string]membershipResult
	pending         map[string]chan struct{}
	slots           chan struct{}
	coreFailures    map[string]time.Time
	connections     map[string]int
	connectionCount int
}

func newAccessPolicy(c AccessConfig, pin string) (*accessPolicy, error) {
	if c.Mode == "" {
		c.Mode = "public"
	}
	if err := c.validate(); err != nil {
		return nil, err
	}
	raw, _ := json.Marshal(struct {
		Mode   string
		Groups []int32
	}{c.Mode, c.AllowedGroupIDs})
	digest := sha256.Sum256(raw)
	return &accessPolicy{config: c, revision: hex.EncodeToString(digest[:]), pin: pin,
		client: &http.Client{Timeout: 2 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }},
		cache:  map[string]membershipResult{}, pending: map[string]chan struct{}{}, slots: make(chan struct{}, 16), coreFailures: map[string]time.Time{}, connections: map[string]int{}}, nil
}

func (p *accessPolicy) membership(ctx context.Context, address string) membershipResult {
	for {
		p.mu.Lock()
		if r, ok := p.cache[address]; ok && time.Since(r.checked) < 30*time.Second {
			p.mu.Unlock()
			return r
		}
		if done, ok := p.pending[address]; ok {
			p.mu.Unlock()
			select {
			case <-done:
				continue
			case <-ctx.Done():
				return membershipResult{err: ctx.Err()}
			}
		}
		if len(p.pending) >= 128 {
			p.mu.Unlock()
			return membershipResult{err: errors.New("membership capacity")}
		}
		done := make(chan struct{})
		p.pending[address] = done
		p.mu.Unlock()
		result := p.checkGroups(ctx, address)
		p.mu.Lock()
		if result.err == nil {
			if len(p.cache) >= 4096 {
				for key, r := range p.cache {
					if time.Since(r.checked) >= 30*time.Second {
						delete(p.cache, key)
					}
				}
				if len(p.cache) >= 4096 {
					for key := range p.cache {
						delete(p.cache, key)
						break
					}
				}
			}
			p.cache[address] = result
		}
		delete(p.pending, address)
		close(done)
		p.mu.Unlock()
		return result
	}
}

func (p *accessPolicy) checkGroups(ctx context.Context, address string) membershipResult {
	ctx, cancel := context.WithTimeout(ctx, 6*time.Second)
	defer cancel()
	results := make(chan membershipResult, len(p.config.AllowedGroupIDs))
	// At most four group lookups per user; the policy-wide budget bounds all users.
	parallel := make(chan struct{}, 4)
	for _, id := range p.config.AllowedGroupIDs {
		go func(id int32) {
			select {
			case parallel <- struct{}{}:
			case <-ctx.Done():
				results <- membershipResult{err: ctx.Err()}
				return
			}
			defer func() { <-parallel }()
			results <- p.checkGroup(ctx, address, id)
		}(id)
	}
	var unresolved error
	for range p.config.AllowedGroupIDs {
		r := <-results
		if r.err != nil {
			unresolved = r.err
		} else if r.member {
			return r
		}
	}
	return membershipResult{checked: time.Now(), err: unresolved}
}

func (p *accessPolicy) checkGroup(ctx context.Context, address string, id int32) membershipResult {
	body, _ := json.Marshal([]string{address})
	// Temporarily demote failed Core endpoints, preserving configured order
	// among healthy endpoints. If all failed, allow a bounded recovery probe.
	p.mu.Lock()
	bases := make([]string, 0, len(p.config.CoreURLBases))
	for _, base := range p.config.CoreURLBases {
		if !time.Now().Before(p.coreFailures[base]) {
			bases = append(bases, base)
		}
	}
	if len(bases) == 0 {
		bases = append(bases, p.config.CoreURLBases...)
	}
	p.mu.Unlock()
	for _, base := range bases {
		select {
		case p.slots <- struct{}{}:
		case <-ctx.Done():
			return membershipResult{err: ctx.Err()}
		}
		started := time.Now()
		req, err := http.NewRequestWithContext(ctx, "POST", fmt.Sprintf("%s/groups/members/%d/validate", base, id), bytes.NewReader(body))
		if err != nil {
			<-p.slots
			p.coreFailed(base)
			continue
		}
		req.Header.Set("Content-Type", "application/json")
		resp, err := p.client.Do(req)
		if err != nil {
			<-p.slots
			if ctx.Err() == nil {
				p.coreFailed(base)
			}
			continue
		}
		raw, readErr := io.ReadAll(io.LimitReader(resp.Body, 8193))
		resp.Body.Close()
		<-p.slots
		if readErr != nil || len(raw) > 8192 || resp.StatusCode != 200 {
			p.coreFailed(base)
			continue
		}
		var rows []struct {
			Address  string `json:"address"`
			IsMember *bool  `json:"isMember"`
		}
		if json.Unmarshal(raw, &rows) != nil || len(rows) != 1 || rows[0].Address != address || rows[0].IsMember == nil {
			p.coreFailed(base)
			continue
		}
		return membershipResult{member: *rows[0].IsMember, checked: started}
	}
	return membershipResult{err: errors.New("membership verification unavailable")}
}

func (p *accessPolicy) coreFailed(base string) {
	p.mu.Lock()
	p.coreFailures[base] = time.Now().Add(5 * time.Second)
	p.mu.Unlock()
}

type relayAuthContextKey struct{}
type connectionAuthorization struct {
	mu              sync.Mutex
	conn            *quic.Conn
	authorizedUntil time.Time
	address         string
	timer           *time.Timer
	attempts        int
	timerGeneration atomic.Uint64
}

func (p *accessPolicy) connectionContext(ctx context.Context, c *quic.Conn) context.Context {
	source := sourceHost(c.RemoteAddr().String())
	p.mu.Lock()
	if p.connectionCount >= 512 || p.connections[source] >= 32 {
		p.mu.Unlock()
		c.CloseWithError(0x515203, "relay connection capacity")
		return ctx
	}
	p.connectionCount++
	p.connections[source]++
	p.mu.Unlock()
	a := &connectionAuthorization{conn: c}
	if p.config.Mode == "groups" {
		generation := a.timerGeneration.Add(1)
		a.timer = time.AfterFunc(15*time.Second, func() { a.expire(generation) })
	}
	context.AfterFunc(c.Context(), func() {
		p.mu.Lock()
		p.connectionCount--
		p.connections[source]--
		if p.connections[source] == 0 {
			delete(p.connections, source)
		}
		p.mu.Unlock()
		a.mu.Lock()
		defer a.mu.Unlock()
		if a.timer != nil {
			a.timer.Stop()
		}
	})
	return context.WithValue(ctx, relayAuthContextKey{}, a)
}

// Never wait for an in-flight membership request to enforce expiration.
func (a *connectionAuthorization) expire(generation uint64) {
	// Go timers use monotonic time. A wall-clock rollback must not leave an
	// expired connection alive, and an old timer must not cancel a renewal.
	if a.timerGeneration.Load() == generation {
		a.conn.CloseWithError(0x515202, "relay authorization expired")
	}
}

type relayProof struct {
	Type            string `json:"type"`
	RelayPin        string `json:"relayPin"`
	Policy          string `json:"policy"`
	Binding         string `json:"binding"`
	Nonce           string `json:"nonce"`
	ExpiresAt       int64  `json:"expiresAt"`
	AuthorAddress   string `json:"authorAddress"`
	AuthorPublicKey string `json:"authorPublicKey"`
	Signature       string `json:"signature"`
}

func accessError(w http.ResponseWriter, status int, code string) {
	w.Header().Set("Qortal-Relay-Error", code)
	http.Error(w, code, status)
}

func (p *accessPolicy) authorize(w http.ResponseWriter, r *http.Request) (string, bool) {
	if p.config.Mode == "public" {
		return "", true
	}
	a, _ := r.Context().Value(relayAuthContextKey{}).(*connectionAuthorization)
	if a == nil || p.tickets == nil {
		accessError(w, 503, "RELAY_AUTH_UNAVAILABLE")
		return "", false
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	// Identity-bearing proofs are forbidden on the IP-visible connection.
	if r.Header.Get("Qortal-Relay-Proof") != "" {
		accessError(w, 403, "RELAY_PROOF_INVALID")
		return "", false
	}
	if time.Now().Before(a.authorizedUntil) && r.Header.Get("Qortal-Relay-Renew") != "1" {
		w.Header().Set("Qortal-Relay-Expires", fmt.Sprint(a.authorizedUntil.UnixMilli()))
		return a.address, true
	}
	raw := r.Header.Get("Qortal-Relay-Ticket")
	if raw == "" {
		w.Header().Set("Qortal-Relay-Challenge", `{"type":"masque-ticket-required-v1"}`)
		accessError(w, 401, "RELAY_AUTH_REQUIRED")
		return "", false
	}
	a.attempts++
	if a.attempts > 8 {
		accessError(w, 429, "RELAY_AUTH_RATE_LIMITED")
		return "", false
	}
	id, until, err := p.tickets.redeem(raw)
	if err != nil {
		accessError(w, 403, "RELAY_PROOF_INVALID")
		return "", false
	}
	a.address = "ticket:" + id
	a.authorizedUntil = until
	generation := a.timerGeneration.Add(1)
	a.attempts = 0
	if a.timer != nil {
		a.timer.Stop()
	}
	if a.conn != nil {
		a.timer = time.AfterFunc(time.Until(until), func() { a.expire(generation) })
	}
	w.Header().Set("Qortal-Relay-Expires", fmt.Sprint(until.UnixMilli()))
	return a.address, true
}

const base58Alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

func decodeBase58(s string, size int) []byte {
	if len(s) > 100 || s == "" {
		return nil
	}
	n := new(big.Int)
	for _, c := range s {
		i := strings.IndexRune(base58Alphabet, c)
		if i < 0 {
			return nil
		}
		n.Mul(n, big.NewInt(58))
		n.Add(n, big.NewInt(int64(i)))
	}
	b := n.Bytes()
	for _, c := range s {
		if c != '1' {
			break
		}
		b = append([]byte{0}, b...)
	}
	if len(b) != size {
		return nil
	}
	return b
}
func encodeBase58(b []byte) string {
	n := new(big.Int).SetBytes(b)
	var out []byte
	mod := new(big.Int)
	for n.Sign() > 0 {
		n.QuoRem(n, big.NewInt(58), mod)
		out = append(out, base58Alphabet[mod.Int64()])
	}
	for _, v := range b {
		if v != 0 {
			break
		}
		out = append(out, '1')
	}
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return string(out)
}
func addressForKey(key []byte) string {
	digest := sha256.Sum256(key)
	h := ripemd160.New()
	h.Write(digest[:])
	b := append([]byte{58}, h.Sum(nil)...)
	check := sha256.Sum256(b)
	check = sha256.Sum256(check[:])
	return encodeBase58(append(b, check[:4]...))
}
