package storage_test

import (
	"testing"

	"github.com/cwolsen7905/ubixvault/internal/storage"
	"github.com/cwolsen7905/ubixvault/internal/storage/storagetest"
)

func TestMemoryBackendConformance(t *testing.T) {
	storagetest.RunBackendConformance(t, func(_ *testing.T) storage.Backend {
		return storage.NewMemoryBackend()
	})
}

func TestFileBackendConformance(t *testing.T) {
	storagetest.RunBackendConformance(t, func(t *testing.T) storage.Backend {
		b, err := storage.NewFileBackend(t.TempDir())
		if err != nil {
			t.Fatalf("NewFileBackend: %v", err)
		}
		return b
	})
}
