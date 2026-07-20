// Package token implements token storage: the credentials clients present to
// authenticate (docs/DESIGN.md §3.3). A token carries the set of ACL policies
// that authorize its requests; the special "root" policy grants everything.
//
// Tokens are stored in the barrier (encrypted at rest) but indexed by the
// SHA-256 of the token value, never by the value itself. The barrier encrypts
// values but not keys, so keying by the raw token would leak it in on-disk key
// names. Because token values are high-entropy random strings, a plain hash
// index is sufficient (there is nothing to brute-force).
package token

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/cwolsen7905/ubixvault/internal/storage"
)

// RootPolicy is the policy name that grants unrestricted access.
const RootPolicy = "root"

// displayPrefix makes tokens recognizable; it is part of the token value.
const displayPrefix = "uv."

// storePrefix is the storage namespace for token records.
const storePrefix = "sys/token/"

// idBytes is the amount of entropy in a token value.
const idBytes = 24

// ErrTokenNotFound is returned when a token id has no record.
// Token errors.
var (
	ErrTokenNotFound = errors.New("token: not found")
	ErrTokenExpired  = errors.New("token: expired")
)

// DefaultTTL is applied to tokens created without an explicit TTL. Root tokens
// never expire.
const DefaultTTL = 32 * 24 * time.Hour // 32 days, matching Vault's default

// Token is an authentication credential with attached policies.
type Token struct {
	ID          string    `json:"id"`
	Policies    []string  `json:"policies"`
	CreatedTime time.Time `json:"created_time"`
	ExpiresAt   time.Time `json:"expires_at,omitempty"` // zero means never expires
}

// IsRoot reports whether the token carries the root policy.
func (t *Token) IsRoot() bool {
	for _, p := range t.Policies {
		if p == RootPolicy {
			return true
		}
	}
	return false
}

// expired reports whether the token has passed its expiration.
func (t *Token) expired(now time.Time) bool {
	return !t.ExpiresAt.IsZero() && now.After(t.ExpiresAt)
}

// Storage is the subset of a backend the token store needs. *barrier.Barrier
// and the raw backends satisfy it.
type Storage interface {
	Get(ctx context.Context, key string) (*storage.Entry, error)
	Put(ctx context.Context, entry *storage.Entry) error
	Delete(ctx context.Context, key string) error
}

// Store persists and retrieves tokens.
type Store struct {
	store Storage
	now   func() time.Time
}

// NewStore returns a token store over s.
func NewStore(s Storage) *Store {
	return &Store{store: s, now: func() time.Time { return time.Now().UTC() }}
}

// CreateRoot creates a non-expiring token with the root policy.
func (st *Store) CreateRoot(ctx context.Context) (*Token, error) {
	return st.create(ctx, []string{RootPolicy}, time.Time{})
}

// Create issues a token with the given policies and the default TTL.
func (st *Store) Create(ctx context.Context, policies []string) (*Token, error) {
	return st.create(ctx, policies, st.now().Add(DefaultTTL))
}

// CreateWithTTL issues a token that expires after ttl. A ttl <= 0 means the
// token never expires.
func (st *Store) CreateWithTTL(ctx context.Context, policies []string, ttl time.Duration) (*Token, error) {
	var expiresAt time.Time
	if ttl > 0 {
		expiresAt = st.now().Add(ttl)
	}
	return st.create(ctx, policies, expiresAt)
}

func (st *Store) create(ctx context.Context, policies []string, expiresAt time.Time) (*Token, error) {
	id, err := generateID()
	if err != nil {
		return nil, err
	}
	t := &Token{ID: id, Policies: policies, CreatedTime: st.now(), ExpiresAt: expiresAt}
	if err := st.save(ctx, t); err != nil {
		return nil, err
	}
	return t, nil
}

// Lookup returns the token with the given id. It returns [ErrTokenNotFound] if
// absent and [ErrTokenExpired] if it has expired (deleting the expired record).
func (st *Store) Lookup(ctx context.Context, id string) (*Token, error) {
	entry, err := st.store.Get(ctx, storeKey(id))
	if err != nil {
		return nil, fmt.Errorf("token: lookup: %w", err)
	}
	if entry == nil {
		return nil, ErrTokenNotFound
	}
	var t Token
	if err := json.Unmarshal(entry.Value, &t); err != nil {
		return nil, fmt.Errorf("token: unmarshal: %w", err)
	}
	if t.expired(st.now()) {
		_ = st.store.Delete(ctx, storeKey(id)) // best-effort cleanup of the expired token
		return nil, ErrTokenExpired
	}
	return &t, nil
}

// Renew extends a token's expiration by ttl from now (or the default TTL if
// ttl <= 0). Root and other non-expiring tokens are returned unchanged. It
// returns [ErrTokenNotFound]/[ErrTokenExpired] like Lookup.
func (st *Store) Renew(ctx context.Context, id string, ttl time.Duration) (*Token, error) {
	t, err := st.Lookup(ctx, id)
	if err != nil {
		return nil, err
	}
	if t.ExpiresAt.IsZero() {
		return t, nil // never-expiring token; nothing to extend
	}
	if ttl <= 0 {
		ttl = DefaultTTL
	}
	t.ExpiresAt = st.now().Add(ttl)
	if err := st.save(ctx, t); err != nil {
		return nil, err
	}
	return t, nil
}

func (st *Store) save(ctx context.Context, t *Token) error {
	blob, err := json.Marshal(t)
	if err != nil {
		return fmt.Errorf("token: marshal: %w", err)
	}
	if err := st.store.Put(ctx, &storage.Entry{Key: storeKey(t.ID), Value: blob}); err != nil {
		return fmt.Errorf("token: persist: %w", err)
	}
	return nil
}

// Revoke deletes the token with the given id. It is a no-op if absent.
func (st *Store) Revoke(ctx context.Context, id string) error {
	if err := st.store.Delete(ctx, storeKey(id)); err != nil {
		return fmt.Errorf("token: revoke: %w", err)
	}
	return nil
}

// generateID returns a new random token value.
func generateID() (string, error) {
	b := make([]byte, idBytes)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("token: generate id: %w", err)
	}
	return displayPrefix + hex.EncodeToString(b), nil
}

// storeKey maps a token value to its storage key: the hash of the value, so the
// value itself never appears in an (unencrypted) key name.
func storeKey(id string) string {
	sum := sha256.Sum256([]byte(id))
	return storePrefix + hex.EncodeToString(sum[:])
}
