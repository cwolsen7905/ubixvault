package raft

import (
	"sort"
	"strings"

	"go.etcd.io/bbolt"

	"github.com/cwolsen7905/ubixvault/internal/storage"
)

var (
	kvBucket    = []byte("kv")   // key -> value
	metaBucket  = []byte("meta") // bookkeeping, outside the key space
	lastApplied = []byte("last_applied")
)

// maxKeyLen matches the MySQL backend's VARBINARY(768) bound so a store moves
// between backends losslessly in either direction.
const maxKeyLen = 768

func checkKey(key string) error {
	if err := storage.ValidateKey(key); err != nil {
		return err
	}
	if len(key) > maxKeyLen {
		return storage.ErrInvalidKey
	}
	return nil
}

func checkPrefix(prefix string) error {
	if prefix == "" {
		return nil
	}
	if !strings.HasSuffix(prefix, "/") {
		return storage.ErrInvalidKey
	}
	return storage.ValidateKey(strings.TrimSuffix(prefix, "/"))
}

// kvGet reads key inside tx. It returns nil if the key is absent, and a copy
// of the value otherwise (bbolt values are only valid for the transaction).
func kvGet(tx *bbolt.Tx, key string) *storage.Entry {
	v := tx.Bucket(kvBucket).Get([]byte(key))
	if v == nil {
		return nil
	}
	return &storage.Entry{Key: key, Value: append([]byte(nil), v...)}
}

// kvList returns the immediate children of prefix, with the semantics of
// [storage.Backend.List]. bbolt iterates in byte order, so one cursor seek
// bounds the scan to the subtree.
func kvList(tx *bbolt.Tx, prefix string) []string {
	out := []string{}
	c := tx.Bucket(kvBucket).Cursor()
	p := []byte(prefix)
	for k, _ := c.Seek(p); k != nil && strings.HasPrefix(string(k), prefix); k, _ = c.Next() {
		child, ok := childUnder(prefix, string(k))
		if !ok {
			continue
		}
		if n := len(out); n > 0 && out[n-1] == child {
			continue
		}
		out = append(out, child)
	}
	sort.Strings(out)
	return dedupe(out)
}

func dedupe(s []string) []string {
	out := s[:0]
	for i, v := range s {
		if i > 0 && v == s[i-1] {
			continue
		}
		out = append(out, v)
	}
	return out
}

// childUnder mirrors the unexported helper in package storage: the immediate
// child of prefix on the path to key, with a trailing "/" for a subtree.
func childUnder(prefix, key string) (string, bool) {
	if !strings.HasPrefix(key, prefix) {
		return "", false
	}
	rest := key[len(prefix):]
	if rest == "" {
		return "", false
	}
	if i := strings.IndexByte(rest, '/'); i >= 0 {
		return rest[:i] + "/", true
	}
	return rest, true
}
