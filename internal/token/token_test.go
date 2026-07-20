package token

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/cwolsen7905/ubixvault/internal/storage"
)

func newStore() (*Store, *storage.MemoryBackend) {
	mem := storage.NewMemoryBackend()
	return NewStore(mem), mem
}

// clockedStore returns a store whose clock the caller controls via the returned
// pointer, plus its backend.
func clockedStore() (*Store, *storage.MemoryBackend, *time.Time) {
	mem := storage.NewMemoryBackend()
	st := NewStore(mem)
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	st.now = func() time.Time { return now }
	return st, mem, &now
}

func TestCreateRootAndLookup(t *testing.T) {
	ctx := context.Background()
	st, _ := newStore()

	root, err := st.CreateRoot(ctx)
	if err != nil {
		t.Fatalf("CreateRoot: %v", err)
	}
	if !root.IsRoot() {
		t.Fatal("root token is not root")
	}
	if !strings.HasPrefix(root.ID, displayPrefix) {
		t.Fatalf("token id %q lacks prefix %q", root.ID, displayPrefix)
	}

	got, err := st.Lookup(ctx, root.ID)
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if got.ID != root.ID || !got.IsRoot() {
		t.Fatalf("looked-up token = %+v", got)
	}
}

func TestCreateWithPolicies(t *testing.T) {
	ctx := context.Background()
	st, _ := newStore()

	tok, err := st.Create(ctx, []string{"read-only", "app"})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if tok.IsRoot() {
		t.Fatal("non-root token reports root")
	}
	got, _ := st.Lookup(ctx, tok.ID)
	if len(got.Policies) != 2 || got.Policies[0] != "read-only" {
		t.Fatalf("policies = %v", got.Policies)
	}
}

func TestLookupUnknown(t *testing.T) {
	ctx := context.Background()
	st, _ := newStore()
	if _, err := st.Lookup(ctx, "uv.does-not-exist"); !errors.Is(err, ErrTokenNotFound) {
		t.Fatalf("want ErrTokenNotFound, got %v", err)
	}
}

func TestRevoke(t *testing.T) {
	ctx := context.Background()
	st, _ := newStore()
	tok, _ := st.CreateRoot(ctx)

	if err := st.Revoke(ctx, tok.ID); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if _, err := st.Lookup(ctx, tok.ID); !errors.Is(err, ErrTokenNotFound) {
		t.Fatalf("after revoke: want ErrTokenNotFound, got %v", err)
	}
	// Revoking again is a no-op.
	if err := st.Revoke(ctx, tok.ID); err != nil {
		t.Fatalf("second Revoke: %v", err)
	}
}

func TestTokensAreUnique(t *testing.T) {
	ctx := context.Background()
	st, _ := newStore()
	a, _ := st.CreateRoot(ctx)
	b, _ := st.CreateRoot(ctx)
	if a.ID == b.ID {
		t.Fatal("two tokens share an id")
	}
}

// TestTokenValueNotInStorageKey is the anti-leak guarantee: because the barrier
// does not encrypt key names, the token value must never appear in a storage
// key. Records are indexed by the hash of the token instead.
func TestTokenValueNotInStorageKey(t *testing.T) {
	ctx := context.Background()
	st, mem := newStore()
	tok, _ := st.CreateRoot(ctx)

	keys, err := mem.List(ctx, storePrefix)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	rawID := strings.TrimPrefix(tok.ID, displayPrefix)
	for _, k := range keys {
		if strings.Contains(k, rawID) || strings.Contains(k, tok.ID) {
			t.Fatalf("token value leaked into storage key %q", k)
		}
	}
	// And the token is still retrievable by its value.
	if _, err := st.Lookup(ctx, tok.ID); err != nil {
		t.Fatalf("Lookup after key check: %v", err)
	}
}

func TestCreateAppliesDefaultTTL(t *testing.T) {
	ctx := context.Background()
	st, _ := newStore()
	tok, err := st.Create(ctx, []string{"p"})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if tok.ExpiresAt.IsZero() {
		t.Fatal("Create should set an expiry (default TTL)")
	}
}

func TestRootNeverExpires(t *testing.T) {
	ctx := context.Background()
	st, _, now := clockedStore()
	root, _ := st.CreateRoot(ctx)
	if !root.ExpiresAt.IsZero() {
		t.Fatalf("root token has an expiry: %v", root.ExpiresAt)
	}
	// Far in the future, the root token is still valid.
	*now = now.AddDate(10, 0, 0)
	if _, err := st.Lookup(ctx, root.ID); err != nil {
		t.Fatalf("root token expired: %v", err)
	}
}

func TestCreateWithTTL(t *testing.T) {
	ctx := context.Background()
	st, _, _ := clockedStore()

	ttlTok, _ := st.CreateWithTTL(ctx, []string{"p"}, time.Hour)
	if ttlTok.ExpiresAt.IsZero() {
		t.Fatal("CreateWithTTL(1h) should set an expiry")
	}
	neverTok, _ := st.CreateWithTTL(ctx, []string{"p"}, 0)
	if !neverTok.ExpiresAt.IsZero() {
		t.Fatal("CreateWithTTL(0) should never expire")
	}
}

func TestLookupExpiredTokenIsGone(t *testing.T) {
	ctx := context.Background()
	st, mem, now := clockedStore()

	tok, _ := st.CreateWithTTL(ctx, []string{"p"}, time.Hour)
	*now = now.Add(2 * time.Hour) // past expiry

	if _, err := st.Lookup(ctx, tok.ID); !errors.Is(err, ErrTokenExpired) {
		t.Fatalf("expired lookup: want ErrTokenExpired, got %v", err)
	}
	// The expired record is cleaned up.
	if raw, _ := mem.Get(ctx, storeKey(tok.ID)); raw != nil {
		t.Fatal("expired token record not deleted")
	}
}

func TestRenewExtendsExpiry(t *testing.T) {
	ctx := context.Background()
	st, _, now := clockedStore()

	tok, _ := st.CreateWithTTL(ctx, []string{"p"}, time.Hour) // expires at base+1h
	*now = now.Add(30 * time.Minute)                          // still valid

	renewed, err := st.Renew(ctx, tok.ID, 2*time.Hour)
	if err != nil {
		t.Fatalf("Renew: %v", err)
	}
	want := now.Add(2 * time.Hour)
	if !renewed.ExpiresAt.Equal(want) {
		t.Fatalf("renewed expiry = %v, want %v", renewed.ExpiresAt, want)
	}
	// After the original expiry it is still valid thanks to the renewal.
	*now = now.Add(90 * time.Minute)
	if _, err := st.Lookup(ctx, tok.ID); err != nil {
		t.Fatalf("token expired despite renewal: %v", err)
	}
}

func TestRenewNonExpiringIsNoOp(t *testing.T) {
	ctx := context.Background()
	st, _, _ := clockedStore()
	root, _ := st.CreateRoot(ctx)
	renewed, err := st.Renew(ctx, root.ID, time.Hour)
	if err != nil {
		t.Fatalf("Renew root: %v", err)
	}
	if !renewed.ExpiresAt.IsZero() {
		t.Fatal("renewing a non-expiring token gave it an expiry")
	}
}
