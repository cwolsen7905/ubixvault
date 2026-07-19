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
var ErrTokenNotFound = errors.New("token: not found")

// Token is an authentication credential with attached policies.
type Token struct {
	ID          string    `json:"id"`
	Policies    []string  `json:"policies"`
	CreatedTime time.Time `json:"created_time"`
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

// CreateRoot creates a token with the root policy.
func (st *Store) CreateRoot(ctx context.Context) (*Token, error) {
	return st.Create(ctx, []string{RootPolicy})
}

// Create issues a new token with the given policies and persists it.
func (st *Store) Create(ctx context.Context, policies []string) (*Token, error) {
	id, err := generateID()
	if err != nil {
		return nil, err
	}
	t := &Token{ID: id, Policies: policies, CreatedTime: st.now()}

	blob, err := json.Marshal(t)
	if err != nil {
		return nil, fmt.Errorf("token: marshal: %w", err)
	}
	if err := st.store.Put(ctx, &storage.Entry{Key: storeKey(id), Value: blob}); err != nil {
		return nil, fmt.Errorf("token: persist: %w", err)
	}
	return t, nil
}

// Lookup returns the token with the given id, or [ErrTokenNotFound].
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
	return &t, nil
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
