// Package quota implements Vault-compatible resource quotas. Phase 1 covers
// rate-limit quotas: path-prefix-scoped, API-managed request-rate limits, each
// backed by a per-client token bucket ([ratelimit.Limiter]) and persisted in the
// barrier. See docs/design/resource-quotas.md and ADR D-020.
//
// Enforcement is a hot path (every request), so quotas are held in memory; they
// are loaded from the barrier once after unseal ([Manager.EnsureLoaded]) and
// kept current by the write path ([Manager.Set]/[Manager.Delete]).
package quota

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/cwolsen7905/ubixvault/internal/ratelimit"
	"github.com/cwolsen7905/ubixvault/internal/storage"
)

// storePrefix is the barrier key prefix for rate-limit quota records.
const storePrefix = "sys/quotas/rate-limit/"

// Errors returned by the manager.
var (
	// ErrNotFound is returned for an unknown quota name.
	ErrNotFound = errors.New("quota: not found")
	// ErrInvalidName is returned for a name that is empty or not a single path-safe segment.
	ErrInvalidName = errors.New("quota: invalid name (must be a single path-safe segment)")
	// ErrInvalidRate is returned when rate is not positive.
	ErrInvalidRate = errors.New("quota: rate must be greater than 0")
	// ErrInvalidPath is returned for a path that is not a valid API path prefix.
	ErrInvalidPath = errors.New("quota: invalid path prefix")
)

// Storage is the subset of the barrier the manager needs.
type Storage interface {
	Get(ctx context.Context, key string) (*storage.Entry, error)
	Put(ctx context.Context, entry *storage.Entry) error
	Delete(ctx context.Context, key string) error
	List(ctx context.Context, prefix string) ([]string, error)
}

// RateLimitQuota is a persisted, path-scoped request-rate limit.
type RateLimitQuota struct {
	Name string `json:"name"`
	// Path is the API path prefix the quota applies to; "" matches every path
	// (a global default). Matching is longest-prefix-wins.
	Path string `json:"path"`
	// Rate is the allowed requests per second per client; Burst is the most a
	// single client may spend at once (defaults to Rate when not positive).
	Rate  float64 `json:"rate"`
	Burst float64 `json:"burst"`
}

// effectiveBurst returns Burst, defaulting to Rate when unset.
func (q RateLimitQuota) effectiveBurst() float64 {
	if q.Burst > 0 {
		return q.Burst
	}
	return q.Rate
}

type liveQuota struct {
	spec    RateLimitQuota
	limiter *ratelimit.Limiter
}

// Manager holds the rate-limit quotas and enforces them. Safe for concurrent use.
type Manager struct {
	store      Storage
	onExceeded func(name string) // optional metrics hook

	mu     sync.RWMutex
	quotas map[string]*liveQuota // by name
	loaded bool
}

// New returns a manager over store. onExceeded, if non-nil, is called with the
// quota name each time a request is denied (for metrics); it must not block.
func New(store Storage, onExceeded func(name string)) *Manager {
	return &Manager{store: store, onExceeded: onExceeded, quotas: map[string]*liveQuota{}}
}

// EnsureLoaded loads all persisted quotas into memory once. It is a no-op after a
// successful load, so callers may invoke it on the request path (guarded by the
// vault being unsealed). On error it leaves the manager unloaded so a later call
// retries.
func (m *Manager) EnsureLoaded(ctx context.Context) error {
	m.mu.RLock()
	loaded := m.loaded
	m.mu.RUnlock()
	if loaded {
		return nil
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	if m.loaded { // won the race
		return nil
	}
	names, err := m.store.List(ctx, storePrefix)
	if err != nil {
		return fmt.Errorf("quota: list: %w", err)
	}
	loadedQuotas := make(map[string]*liveQuota, len(names))
	for _, name := range names {
		entry, err := m.store.Get(ctx, storePrefix+name)
		if err != nil {
			return fmt.Errorf("quota: read %q: %w", name, err)
		}
		if entry == nil {
			continue
		}
		var q RateLimitQuota
		if err := json.Unmarshal(entry.Value, &q); err != nil {
			return fmt.Errorf("quota: decode %q: %w", name, err)
		}
		loadedQuotas[q.Name] = &liveQuota{spec: q, limiter: ratelimit.New(q.Rate, q.effectiveBurst())}
	}
	m.quotas = loadedQuotas
	m.loaded = true
	return nil
}

// Set creates or replaces a rate-limit quota: it validates, persists to the
// barrier, and updates the in-memory limiter.
func (m *Manager) Set(ctx context.Context, q RateLimitQuota) error {
	if !validName(q.Name) {
		return ErrInvalidName
	}
	if q.Rate <= 0 {
		return ErrInvalidRate
	}
	if !validPath(q.Path) {
		return ErrInvalidPath
	}
	blob, err := json.Marshal(q)
	if err != nil {
		return fmt.Errorf("quota: encode: %w", err)
	}
	if err := m.store.Put(ctx, &storage.Entry{Key: storePrefix + q.Name, Value: blob}); err != nil {
		return fmt.Errorf("quota: persist: %w", err)
	}
	m.mu.Lock()
	m.quotas[q.Name] = &liveQuota{spec: q, limiter: ratelimit.New(q.Rate, q.effectiveBurst())}
	m.mu.Unlock()
	return nil
}

// Get returns the named quota's spec, or [ErrNotFound].
func (m *Manager) Get(name string) (RateLimitQuota, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	q, ok := m.quotas[name]
	if !ok {
		return RateLimitQuota{}, ErrNotFound
	}
	return q.spec, nil
}

// Delete removes the named quota. Absent is not an error.
func (m *Manager) Delete(ctx context.Context, name string) error {
	if !validName(name) {
		return ErrInvalidName
	}
	if err := m.store.Delete(ctx, storePrefix+name); err != nil {
		return fmt.Errorf("quota: delete: %w", err)
	}
	m.mu.Lock()
	delete(m.quotas, name)
	m.mu.Unlock()
	return nil
}

// List returns all quota specs, unordered.
func (m *Manager) List() []RateLimitQuota {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]RateLimitQuota, 0, len(m.quotas))
	for _, q := range m.quotas {
		out = append(out, q.spec)
	}
	return out
}

// Allow reports whether a request to path from client may proceed. It applies
// the single most-specific matching quota (longest path prefix); a request with
// no matching quota is always allowed. When a quota denies the request, its name
// is returned and the onExceeded hook (if any) is called.
func (m *Manager) Allow(path, client string) (allowed bool, quota string) {
	m.mu.RLock()
	var best *liveQuota
	bestLen := -1
	for _, q := range m.quotas {
		if !pathMatches(q.spec.Path, path) {
			continue
		}
		if len(q.spec.Path) > bestLen {
			best, bestLen = q, len(q.spec.Path)
		}
	}
	m.mu.RUnlock()

	if best == nil {
		return true, ""
	}
	if best.limiter.Allow(client) {
		return true, best.spec.Name
	}
	if m.onExceeded != nil {
		m.onExceeded(best.spec.Name)
	}
	return false, best.spec.Name
}

// pathMatches reports whether quotaPath is a prefix of reqPath. An empty
// quotaPath matches everything (global).
func pathMatches(quotaPath, reqPath string) bool {
	return quotaPath == "" || strings.HasPrefix(reqPath, quotaPath)
}

// validName restricts quota names to a single path-safe segment (as policies).
func validName(name string) bool {
	if name == "" || strings.Contains(name, "/") {
		return false
	}
	return storage.ValidateKey(storePrefix+name) == nil
}

// validPath allows an empty prefix (global) or any prefix without control
// characters; it is a match prefix for request paths, not a storage key.
func validPath(p string) bool {
	if strings.ContainsAny(p, "\x00\n\r") {
		return false
	}
	return true
}
