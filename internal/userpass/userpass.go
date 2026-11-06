// Package userpass implements the userpass auth method: a human logs in with a
// username and password and receives a token carrying the user's policies.
//
// Passwords are never stored — only a PBKDF2-HMAC-SHA256 hash with a per-user
// random salt (stdlib crypto/pbkdf2, no dependency). Login compares in constant
// time and equalizes timing for unknown users, so it cannot be used to
// enumerate accounts.
package userpass

import (
	"context"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/cwolsen7905/ubixvault/internal/storage"
	"github.com/cwolsen7905/ubixvault/internal/token"
)

// Password-hashing parameters. 600k PBKDF2-SHA256 iterations follows the OWASP
// recommendation.
const (
	saltSize   = 16
	keyLen     = 32
	iterations = 600_000
)

// Errors.
var (
	ErrInvalidName   = errors.New("userpass: invalid username")
	ErrUserNotFound  = errors.New("userpass: user not found")
	ErrDenied        = errors.New("userpass: invalid username or password")
	ErrInvalidConfig = errors.New("userpass: a password and at least one policy are required")
)

// Storage is the subset of a backend the method needs.
type Storage interface {
	Get(ctx context.Context, key string) (*storage.Entry, error)
	Put(ctx context.Context, entry *storage.Entry) error
	Delete(ctx context.Context, key string) error
	List(ctx context.Context, prefix string) ([]string, error)
}

// stored is the persisted user record. The password appears only as its hash.
type stored struct {
	Salt       []byte        `json:"salt"`
	Iterations int           `json:"iterations"`
	Hash       []byte        `json:"hash"`
	Policies   []string      `json:"policies"`
	TokenTTL   time.Duration `json:"token_ttl"`
	MaxTTL     time.Duration `json:"token_max_ttl"`
}

// UserInfo is the non-secret view of a user.
type UserInfo struct {
	Policies    []string
	TokenTTL    time.Duration
	TokenMaxTTL time.Duration
}

// Method is the userpass auth method.
type Method struct {
	store  Storage
	tokens *token.Store
	prefix string

	writeMu sync.Mutex // serializes user writes, so UpdateUser is atomic
}

// New returns a method storing under prefix (e.g. "auth/userpass").
func New(store Storage, tokens *token.Store, prefix string) *Method {
	return &Method{store: store, tokens: tokens, prefix: strings.Trim(prefix, "/")}
}

func (m *Method) userKey(name string) string { return m.prefix + "/user/" + name }

func validName(name string) bool { return name != "" && !strings.Contains(name, "/") }

func derive(password string, salt []byte, iter int) ([]byte, error) {
	return pbkdf2.Key(sha256.New, password, salt, iter, keyLen)
}

// WriteUser creates or replaces a user with the given password and policies.
func (m *Method) WriteUser(ctx context.Context, username, password string, policies []string, ttl, maxTTL time.Duration) error {
	if !validName(username) {
		return ErrInvalidName
	}
	if password == "" {
		return ErrInvalidConfig
	}
	m.writeMu.Lock()
	defer m.writeMu.Unlock()
	return m.writeUser(ctx, username, password, nil, UserInfo{Policies: policies, TokenTTL: ttl, TokenMaxTTL: maxTTL})
}

// UpdateUser applies change to the stored user's settings (zero values if
// there is no such user) and writes the result, with no other user write in
// between. An empty password keeps the current one; a new user needs one.
// Only the active node writes (standbys forward), so an in-process lock is
// enough.
func (m *Method) UpdateUser(ctx context.Context, username, password string, change func(*UserInfo) error) error {
	if !validName(username) {
		return ErrInvalidName
	}
	m.writeMu.Lock()
	defer m.writeMu.Unlock()
	existing, err := m.load(ctx, username)
	switch {
	case errors.Is(err, ErrUserNotFound):
		existing = nil
	case err != nil:
		return err
	}
	info := UserInfo{}
	if existing != nil {
		info = UserInfo{Policies: existing.Policies, TokenTTL: existing.TokenTTL, TokenMaxTTL: existing.MaxTTL}
	}
	if err := change(&info); err != nil {
		return err
	}
	if password == "" && existing == nil {
		return ErrInvalidConfig
	}
	return m.writeUser(ctx, username, password, existing, info)
}

// writeUser persists a user. With a password it hashes it afresh; without
// one it keeps keep's salt and hash. The caller holds writeMu.
func (m *Method) writeUser(ctx context.Context, username, password string, keep *stored, info UserInfo) error {
	if len(info.Policies) == 0 {
		return ErrInvalidConfig
	}
	if token.HasRootPolicy(info.Policies) {
		return token.ErrRootPolicy
	}
	rec := stored{Policies: info.Policies, TokenTTL: info.TokenTTL, MaxTTL: info.TokenMaxTTL}
	if password != "" {
		salt := make([]byte, saltSize)
		if _, err := rand.Read(salt); err != nil {
			return fmt.Errorf("userpass: salt: %w", err)
		}
		hash, err := derive(password, salt, iterations)
		if err != nil {
			return fmt.Errorf("userpass: hash password: %w", err)
		}
		rec.Salt, rec.Iterations, rec.Hash = salt, iterations, hash
	} else {
		rec.Salt, rec.Iterations, rec.Hash = keep.Salt, keep.Iterations, keep.Hash
	}
	blob, err := json.Marshal(rec)
	if err != nil {
		return fmt.Errorf("userpass: marshal user: %w", err)
	}
	if err := m.store.Put(ctx, &storage.Entry{Key: m.userKey(username), Value: blob}); err != nil {
		return fmt.Errorf("userpass: persist user: %w", err)
	}
	return nil
}

// ReadUser returns a user's non-secret info, or [ErrUserNotFound].
func (m *Method) ReadUser(ctx context.Context, username string) (*UserInfo, error) {
	u, err := m.load(ctx, username)
	if err != nil {
		return nil, err
	}
	return &UserInfo{Policies: u.Policies, TokenTTL: u.TokenTTL, TokenMaxTTL: u.MaxTTL}, nil
}

// ListUsers returns the usernames.
func (m *Method) ListUsers(ctx context.Context) ([]string, error) {
	names, err := m.store.List(ctx, m.prefix+"/user/")
	if err != nil {
		return nil, fmt.Errorf("userpass: list users: %w", err)
	}
	return names, nil
}

// DeleteUser removes a user.
func (m *Method) DeleteUser(ctx context.Context, username string) error {
	if !validName(username) {
		return ErrInvalidName
	}
	m.writeMu.Lock()
	defer m.writeMu.Unlock()
	if err := m.store.Delete(ctx, m.userKey(username)); err != nil {
		return fmt.Errorf("userpass: delete user: %w", err)
	}
	return nil
}

// Login verifies a password and, on success, issues a token with the user's
// policies. Unknown users and wrong passwords both return [ErrDenied], and an
// unknown user still runs a hash to equalize timing (no account enumeration).
func (m *Method) Login(ctx context.Context, username, password string) (*token.Token, error) {
	u, err := m.load(ctx, username)
	if errors.Is(err, ErrUserNotFound) {
		// Spend comparable time so a missing user is indistinguishable by timing.
		_, _ = derive(password, make([]byte, saltSize), iterations)
		return nil, ErrDenied
	}
	if err != nil {
		return nil, err
	}
	got, err := derive(password, u.Salt, u.Iterations)
	if err != nil {
		return nil, err
	}
	if subtle.ConstantTimeCompare(got, u.Hash) != 1 {
		return nil, ErrDenied
	}
	if u.TokenTTL > 0 {
		return m.tokens.CreateForLogin(ctx, u.Policies, u.TokenTTL, u.MaxTTL, "userpass", username, nil)
	}
	return m.tokens.CreateForLogin(ctx, u.Policies, 0, u.MaxTTL, "userpass", username, nil)
}

func (m *Method) load(ctx context.Context, username string) (*stored, error) {
	entry, err := m.store.Get(ctx, m.userKey(username))
	if err != nil {
		return nil, fmt.Errorf("userpass: read user: %w", err)
	}
	if entry == nil {
		return nil, ErrUserNotFound
	}
	var u stored
	if err := json.Unmarshal(entry.Value, &u); err != nil {
		return nil, fmt.Errorf("userpass: unmarshal user: %w", err)
	}
	return &u, nil
}
