//go:build integration

package storage_test

import (
	"context"
	"os"
	"testing"

	"github.com/cwolsen7905/ubixvault/internal/storage"
	"github.com/cwolsen7905/ubixvault/internal/storage/storagetest"
)

// TestMySQLBackendConformance runs the shared Backend contract suite against a
// real database — the same suite the file and in-memory backends pass, proving
// the SQL backend is interchangeable with them. It needs UBIXVAULT_MARIADB_DSN
// (see mysql_integration_test.go).
func TestMySQLBackendConformance(t *testing.T) {
	dsn := os.Getenv("UBIXVAULT_MARIADB_DSN")
	if dsn == "" {
		t.Skip("set UBIXVAULT_MARIADB_DSN to run MySQL storage backend tests")
	}
	storagetest.RunBackendConformance(t, func(t *testing.T) storage.Backend {
		b, err := storage.NewMySQLBackend(dsn)
		if err != nil {
			t.Fatalf("NewMySQLBackend: %v", err)
		}
		t.Cleanup(func() { _ = b.Close() })
		// Each conformance subtest expects an empty backend.
		ctx := context.Background()
		var keys []string
		err = storage.Walk(ctx, b, func(e *storage.Entry) error {
			keys = append(keys, e.Key)
			return nil
		})
		if err != nil {
			t.Fatalf("list: %v", err)
		}
		for _, k := range keys {
			if err := b.Delete(ctx, k); err != nil {
				t.Fatalf("clear %q: %v", k, err)
			}
		}
		return b
	})
}
