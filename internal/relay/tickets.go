package relay

// Account proofs enter ONLY through the private Unix socket used by the
// Reticulum child. QUIC accepts anonymous, single-use RFC 9474 tickets only.
import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/cloudflare/circl/blindsign/blindrsa"
	bolt "go.etcd.io/bbolt"
)

const ticketLifetime = 12 * time.Hour
const ticketDomain = "Qortal-MASQUE-Ticket-v1\x00"

type ticketDescriptor struct {
	Epoch     int64  `json:"epoch"`
	ExpiresAt int64  `json:"expiresAt"`
	PublicKey string `json:"publicKey"`
	KeyID     string `json:"keyId"`
	Policy    string `json:"policy"`
	RelayPin  string `json:"relayPin"`
}
type issueChallenge struct {
	Binding string
	Epoch   int64
	Expires time.Time
}
type ticketAuthority struct {
	mu         sync.Mutex
	db         *bolt.DB
	policy     *accessPolicy
	challenges map[string]issueChallenge
	keys       map[int64]*rsa.PrivateKey
	slots      chan struct{}
	listener   net.Listener
}

func ticketKeyID(der []byte, policy, pin string, epoch int64) string {
	h := sha256.New()
	h.Write([]byte(ticketDomain + policy + pin + strconv.FormatInt(epoch, 10)))
	h.Write(der)
	return hex.EncodeToString(h.Sum(nil))
}
func newTicketAuthority(p *accessPolicy, dir string) (*ticketAuthority, error) {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	db, err := bolt.Open(filepath.Join(dir, "tickets.db"), 0600, &bolt.Options{Timeout: time.Second})
	if err != nil {
		return nil, err
	}
	t := &ticketAuthority{db: db, policy: p, challenges: map[string]issueChallenge{}, keys: map[int64]*rsa.PrivateKey{}, slots: make(chan struct{}, 8)}
	err = db.Update(func(tx *bolt.Tx) error {
		for _, n := range []string{"keys", "spent", "quota", "meta"} {
			if _, e := tx.CreateBucketIfNotExists([]byte(n)); e != nil {
				return e
			}
		}
		return nil
	})
	if err == nil {
		_, _, err = t.descriptor(time.Now().Unix() / 3600)
	}
	if err != nil {
		db.Close()
		return nil, err
	}
	return t, nil
}
func (t *ticketAuthority) descriptor(epoch int64) (ticketDescriptor, *rsa.PrivateKey, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	nowEpoch := time.Now().Unix() / 3600
	if epoch > nowEpoch || epoch <= nowEpoch-12 {
		return ticketDescriptor{}, nil, errors.New("RELAY_PROOF_INVALID")
	}
	if err := t.db.Update(func(tx *bolt.Tx) error {
		meta := tx.Bucket([]byte("meta"))
		latest, _ := strconv.ParseInt(string(meta.Get([]byte("latestEpoch"))), 10, 64)
		if nowEpoch < latest {
			return errors.New("relay clock moved backwards")
		}
		if nowEpoch > latest {
			if e := meta.Put([]byte("latestEpoch"), []byte(strconv.FormatInt(nowEpoch, 10))); e != nil {
				return e
			}
			for _, name := range []string{"keys", "quota", "spent"} {
				b := tx.Bucket([]byte(name))
				c := b.Cursor()
				for k, _ := c.First(); k != nil; k, _ = c.Next() {
					part := strings.Split(string(k), ":")
					index := 0
					if name == "keys" {
						index = 1
					}
					if len(part) <= index {
						return errors.New("invalid ticket database")
					}
					ep, e := strconv.ParseInt(part[index], 10, 64)
					if e != nil {
						return e
					}
					if ep <= nowEpoch-12 {
						if e = c.Delete(); e != nil {
							return e
						}
					}
				}
			}
		}
		return nil
	}); err != nil {
		return ticketDescriptor{}, nil, err
	}
	key := t.keys[epoch]
	name := []byte(t.policy.revision + ":" + strconv.FormatInt(epoch, 10))
	if key == nil {
		var raw []byte
		if err := t.db.View(func(tx *bolt.Tx) error { raw = append([]byte(nil), tx.Bucket([]byte("keys")).Get(name)...); return nil }); err != nil {
			return ticketDescriptor{}, nil, err
		}
		var err error
		if len(raw) > 0 {
			key, err = x509.ParsePKCS1PrivateKey(raw)
		} else if epoch == nowEpoch {
			key, err = rsa.GenerateKey(rand.Reader, 2048)
			if err == nil {
				err = t.db.Update(func(tx *bolt.Tx) error { return tx.Bucket([]byte("keys")).Put(name, x509.MarshalPKCS1PrivateKey(key)) })
			}
		} else {
			err = errors.New("RELAY_PROOF_INVALID")
		}
		if err != nil {
			return ticketDescriptor{}, nil, err
		}
		t.keys[epoch] = key
	}
	for e := range t.keys {
		if e <= nowEpoch-12 {
			delete(t.keys, e)
		}
	}
	der := x509.MarshalPKCS1PublicKey(&key.PublicKey)
	return ticketDescriptor{Epoch: epoch, ExpiresAt: (epoch*3600 + int64(ticketLifetime/time.Second)) * 1000, PublicKey: base64.StdEncoding.EncodeToString(der), KeyID: ticketKeyID(der, t.policy.revision, t.policy.pin, epoch), Policy: t.policy.revision, RelayPin: t.policy.pin}, key, nil
}
func (t *ticketAuthority) close() {
	if t.listener != nil {
		t.listener.Close()
	}
	t.db.Close()
}
func (t *ticketAuthority) serve(path string) error {
	// Remove only a stale Unix socket, never a regular file or a live listener.
	if info, err := os.Lstat(path); err == nil {
		if info.Mode()&os.ModeSocket == 0 {
			return errors.New("ticket socket path is not a socket")
		}
		c, e := net.DialTimeout("unix", path, 100*time.Millisecond)
		if e == nil {
			c.Close()
			return errors.New("ticket authority already running")
		}
		if err = os.Remove(path); err != nil {
			return err
		}
	}
	l, err := net.Listen("unix", path)
	if err != nil {
		return err
	}
	t.listener = l
	if err = os.Chmod(path, 0600); err != nil {
		l.Close()
		return err
	}
	server := &http.Server{Handler: http.HandlerFunc(t.handle), ReadHeaderTimeout: 2 * time.Second, ReadTimeout: 3 * time.Second, WriteTimeout: 10 * time.Second, IdleTimeout: time.Second, MaxHeaderBytes: 2048}
	go server.Serve(l)
	return nil
}
func strictJSON(raw []byte, out any) error {
	// Reject duplicate keys as well as unknown fields and trailing values.
	var walk func(*json.Decoder) error
	walk = func(d *json.Decoder) error {
		tok, e := d.Token()
		if e != nil {
			return e
		}
		if delim, ok := tok.(json.Delim); ok {
			switch delim {
			case '{':
				seen := map[string]bool{}
				for d.More() {
					k, e := d.Token()
					if e != nil {
						return e
					}
					s, ok := k.(string)
					if !ok || seen[s] {
						return errors.New("duplicate key")
					}
					seen[s] = true
					if e = walk(d); e != nil {
						return e
					}
				}
			case '[':
				for d.More() {
					if e := walk(d); e != nil {
						return e
					}
				}
			default:
				return errors.New("unexpected delimiter")
			}
			_, e = d.Token()
			return e
		}
		return nil
	}
	if err := walk(json.NewDecoder(strings.NewReader(string(raw)))); err != nil {
		return err
	}
	d := json.NewDecoder(strings.NewReader(string(raw)))
	d.DisallowUnknownFields()
	if err := d.Decode(out); err != nil {
		return err
	}
	var extra any
	if d.Decode(&extra) != io.EOF {
		return errors.New("trailing JSON")
	}
	return nil
}
func (t *ticketAuthority) handle(w http.ResponseWriter, r *http.Request) {
	select {
	case t.slots <- struct{}{}:
		defer func() { <-t.slots }()
	default:
		accessError(w, 429, "RELAY_AUTH_RATE_LIMITED")
		return
	}
	if r.Method != "POST" {
		accessError(w, 405, "RELAY_PROOF_INVALID")
		return
	}
	raw, err := io.ReadAll(io.LimitReader(r.Body, 8193))
	if err != nil || len(raw) > 8192 {
		accessError(w, 400, "RELAY_PROOF_INVALID")
		return
	}
	var input struct {
		Descriptor *ticketDescriptor `json:"descriptor"`
		Blinded    []string          `json:"blinded"`
		Proof      *relayProof       `json:"proof"`
	}
	if strictJSON(raw, &input) != nil {
		accessError(w, 400, "RELAY_PROOF_INVALID")
		return
	}
	descriptor, _, err := t.descriptor(time.Now().Unix() / 3600)
	if err != nil {
		accessError(w, 503, "RELAY_AUTH_UNAVAILABLE")
		return
	}
	if r.URL.Path == "/catalog" {
		json.NewEncoder(w).Encode(descriptor)
		return
	}
	if t.policy.config.Mode != "groups" {
		accessError(w, 403, "RELAY_ACCESS_DENIED")
		return
	}
	if input.Descriptor == nil || *input.Descriptor != descriptor || len(input.Blinded) < 1 || len(input.Blinded) > 3 {
		accessError(w, 403, "RELAY_PROOF_INVALID")
		return
	}
	for _, b := range input.Blinded {
		v, e := base64.StdEncoding.DecodeString(b)
		if e != nil || len(v) != 256 {
			accessError(w, 403, "RELAY_PROOF_INVALID")
			return
		}
	}
	bindingRaw, _ := json.Marshal(struct {
		Key     string   `json:"key"`
		Blinded []string `json:"blinded"`
	}{descriptor.KeyID, input.Blinded})
	binding := sha256.Sum256(bindingRaw)
	if r.URL.Path == "/challenge" {
		nonce := make([]byte, 32)
		if _, e := rand.Read(nonce); e != nil {
			accessError(w, 503, "RELAY_AUTH_UNAVAILABLE")
			return
		}
		n := hex.EncodeToString(nonce)
		expires := time.Now().Add(time.Minute)
		t.mu.Lock()
		for k, c := range t.challenges {
			if time.Now().After(c.Expires) {
				delete(t.challenges, k)
			}
		}
		if len(t.challenges) >= 256 {
			t.mu.Unlock()
			accessError(w, 429, "RELAY_AUTH_RATE_LIMITED")
			return
		}
		t.challenges[n] = issueChallenge{hex.EncodeToString(binding[:]), descriptor.Epoch, expires}
		t.mu.Unlock()
		json.NewEncoder(w).Encode(map[string]any{"type": "masque-ticket-issue-v1", "relayPin": t.policy.pin, "policy": t.policy.revision, "binding": hex.EncodeToString(binding[:]), "nonce": n, "expiresAt": expires.UnixMilli()})
		return
	}
	if r.URL.Path != "/issue" || input.Proof == nil {
		accessError(w, 403, "RELAY_PROOF_INVALID")
		return
	}
	proof := input.Proof
	t.mu.Lock()
	c, ok := t.challenges[proof.Nonce]
	delete(t.challenges, proof.Nonce)
	t.mu.Unlock()
	if !ok || time.Now().After(c.Expires) || c.Epoch != descriptor.Epoch || c.Binding != hex.EncodeToString(binding[:]) || proof.Type != "masque-ticket-issue-v1" || proof.RelayPin != t.policy.pin || proof.Policy != t.policy.revision || proof.Binding != c.Binding || proof.ExpiresAt != c.Expires.UnixMilli() {
		accessError(w, 403, "RELAY_PROOF_INVALID")
		return
	}
	key := decodeBase58(proof.AuthorPublicKey, 32)
	sig := decodeBase58(proof.Signature, 64)
	message, _ := json.Marshal(map[string]any{"type": proof.Type, "relayPin": proof.RelayPin, "policy": proof.Policy, "binding": proof.Binding, "nonce": proof.Nonce, "expiresAt": proof.ExpiresAt, "authorAddress": proof.AuthorAddress, "authorPublicKey": proof.AuthorPublicKey})
	if len(key) != 32 || len(sig) != 64 || addressForKey(key) != proof.AuthorAddress || !ed25519.Verify(key, message, sig) {
		accessError(w, 403, "RELAY_PROOF_INVALID")
		return
	}
	result := t.policy.membership(r.Context(), proof.AuthorAddress)
	if result.err == nil && result.member && result.checked.Unix() < descriptor.Epoch*3600 {
		result = t.policy.checkGroups(r.Context(), proof.AuthorAddress)
	}
	if result.err != nil {
		accessError(w, 503, "RELAY_MEMBERSHIP_UNAVAILABLE")
		return
	}
	if !result.member {
		accessError(w, 403, "RELAY_ACCESS_DENIED")
		return
	}
	// Current membership, not a cached positive, determines the maximum window.
	if descriptor.ExpiresAt > result.checked.Add(ticketLifetime).UnixMilli() {
		accessError(w, 503, "RELAY_AUTH_UNAVAILABLE")
		return
	}
	addressHash := sha256.Sum256([]byte(proof.AuthorAddress))
	quotaKey := []byte(fmt.Sprintf("%012d:%x", descriptor.Epoch, addressHash))
	err = t.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("quota"))
		if b.Stats().KeyN >= 100000 && b.Get(quotaKey) == nil {
			return errors.New("capacity")
		}
		count, _ := strconv.Atoi(string(b.Get(quotaKey)))
		if count+len(input.Blinded) > 24 {
			return errors.New("quota")
		}
		return b.Put(quotaKey, []byte(strconv.Itoa(count+len(input.Blinded))))
	})
	if err != nil {
		accessError(w, 429, "RELAY_AUTH_RATE_LIMITED")
		return
	}
	_, private, err := t.descriptor(descriptor.Epoch)
	if err != nil {
		accessError(w, 503, "RELAY_AUTH_UNAVAILABLE")
		return
	}
	signer := blindrsa.NewSigner(private)
	out := make([]string, 0, len(input.Blinded))
	for _, b := range input.Blinded {
		v, _ := base64.StdEncoding.DecodeString(b)
		s, e := signer.BlindSign(v)
		if e != nil {
			accessError(w, 403, "RELAY_PROOF_INVALID")
			return
		}
		out = append(out, base64.StdEncoding.EncodeToString(s))
	}
	json.NewEncoder(w).Encode(map[string]any{"signatures": out})
}

// redeem writes the spent marker durably BEFORE any forwarding is allowed.
func (t *ticketAuthority) redeem(raw string) (string, time.Time, error) {
	var v struct {
		Epoch     int64  `json:"epoch"`
		KeyID     string `json:"keyId"`
		Message   string `json:"message"`
		Signature string `json:"signature"`
	}
	if len(raw) > 2048 || strictJSON([]byte(raw), &v) != nil {
		return "", time.Time{}, errors.New("RELAY_PROOF_INVALID")
	}
	d, key, err := t.descriptor(v.Epoch)
	if err != nil || d.KeyID != v.KeyID || d.ExpiresAt <= time.Now().UnixMilli() {
		return "", time.Time{}, errors.New("RELAY_PROOF_INVALID")
	}
	msg, e := base64.StdEncoding.DecodeString(v.Message)
	sig, se := base64.StdEncoding.DecodeString(v.Signature)
	prefix := []byte(ticketDomain + d.KeyID)
	if e != nil || se != nil || len(msg) != len(prefix)+32 || !strings.HasPrefix(string(msg), string(prefix)) || len(sig) != 256 {
		return "", time.Time{}, errors.New("RELAY_PROOF_INVALID")
	}
	client, _ := blindrsa.NewClient(blindrsa.SHA384PSSDeterministic, &key.PublicKey)
	if client.Verify(msg, sig) != nil {
		return "", time.Time{}, errors.New("RELAY_PROOF_INVALID")
	}
	digest := sha256.Sum256(msg)
	id := hex.EncodeToString(digest[:])
	spentKey := []byte(fmt.Sprintf("%012d:%s", v.Epoch, id))
	err = t.db.Update(func(tx *bolt.Tx) error {
		// Bounded retention: remove expired hourly records on each redemption.
		cutoff := time.Now().Unix()/3600 - 12
		for _, name := range []string{"spent", "quota"} {
			b := tx.Bucket([]byte(name))
			c := b.Cursor()
			for k, _ := c.First(); k != nil; k, _ = c.Next() {
				if len(k) < 13 {
					return errors.New("invalid ticket database")
				}
				ep, e := strconv.ParseInt(string(k[:12]), 10, 64)
				if e != nil {
					return e
				}
				if ep > cutoff {
					break
				}
				if e = c.Delete(); e != nil {
					return e
				}
			}
		}
		b := tx.Bucket([]byte("spent"))
		if b.Get(spentKey) != nil {
			return errors.New("RELAY_PROOF_INVALID")
		}
		if b.Stats().KeyN >= 100000 {
			return errors.New("RELAY_FULL")
		}
		return b.Put(spentKey, []byte{1})
	})
	if err != nil {
		return "", time.Time{}, errors.New("RELAY_PROOF_INVALID")
	}
	return id, time.Now().Add(time.Duration(d.ExpiresAt-time.Now().UnixMilli()) * time.Millisecond), nil
}
