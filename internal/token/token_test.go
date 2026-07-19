package token

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/cwolsen7905/ubixvault/internal/storage"
)

func newStore() (*Store, *storage.MemoryBackend) {
	mem := storage.NewMemoryBackend()
	return NewStore(mem), mem
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
