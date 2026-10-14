package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	"github.com/cwolsen7905/ubixvault/internal/snapshot"
	"github.com/cwolsen7905/ubixvault/internal/storage"
)

// The MySQL -> Raft migration (docs/DEPLOYMENT.md, "Migrating from MySQL to
// Raft") needs two things the API snapshot does not give: a physical export
// from a database no server is running against, and a digest that compares the
// two ends. Both are offline and never touch the barrier, so neither needs the
// unseal keys.

// snapEntries reads a snapshot into a map, leaving out runtime coordination
// records that differ by backend (the HA holder, Raft's internal join-token
// records), so a snapshot of the source and of the migrated cluster compare.
func snapEntries(r io.Reader) (map[string][]byte, error) {
	br := bufio.NewReaderSize(r, 1<<20)
	head, err := br.ReadString('\n')
	if err != nil {
		return nil, fmt.Errorf("read snapshot header: %w", err)
	}
	if !strings.HasPrefix(head, "ubixvault-snapshot ") {
		return nil, fmt.Errorf("not a snapshot: header %q", strings.TrimSpace(head))
	}
	type kv struct {
		Key   string `json:"key"`
		Value []byte `json:"value"`
	}
	all := map[string][]byte{}
	dec := json.NewDecoder(br)
	for {
		var e kv
		if err := dec.Decode(&e); err != nil {
			if errors.Is(err, io.EOF) {
				return all, nil
			}
			return nil, fmt.Errorf("decode snapshot entry: %w", err)
		}
		if strings.HasPrefix(e.Key, "core/ha/") || strings.HasPrefix(e.Key, "raft-internal/") {
			continue
		}
		all[e.Key] = e.Value
	}
}

// snapshotDigest returns the entry count and a SHA-256 over a snapshot's
// entries sorted by key.
func snapshotDigest(r io.Reader) (count int, sum string, err error) {
	all, err := snapEntries(r)
	if err != nil {
		return 0, "", err
	}
	keys := make([]string, 0, len(all))
	for k := range all {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	h := sha256.New()
	var n [8]byte
	for _, k := range keys {
		binary.BigEndian.PutUint64(n[:], uint64(len(k)))
		h.Write(n[:])
		h.Write([]byte(k))
		binary.BigEndian.PutUint64(n[:], uint64(len(all[k])))
		h.Write(n[:])
		h.Write(all[k])
	}
	return len(keys), fmt.Sprintf("%x", h.Sum(nil)), nil
}

// compareSnapshots reports what a migrated cluster's snapshot has relative to
// the export it came from: entries it lost, entries whose ciphertext changed,
// and entries it added (a running cluster writes some of its own on start).
func compareSnapshots(export, migrated io.Reader) (missing, changed, added []string, err error) {
	a, err := snapEntries(export)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("export: %w", err)
	}
	b, err := snapEntries(migrated)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("migrated: %w", err)
	}
	for k, v := range a {
		w, ok := b[k]
		switch {
		case !ok:
			missing = append(missing, k)
		case !bytes.Equal(v, w):
			changed = append(changed, k)
		}
	}
	for k := range b {
		if _, ok := a[k]; !ok {
			added = append(added, k)
		}
	}
	sort.Strings(missing)
	sort.Strings(changed)
	sort.Strings(added)
	return missing, changed, added, nil
}

// exportBackend writes b as a snapshot to path and returns its digest.
func exportBackend(ctx context.Context, b storage.Backend, path string) (int, string, error) {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) //nolint:gosec // G304: operator-provided output path
	if err != nil {
		return 0, "", fmt.Errorf("create %q: %w", path, err)
	}
	if err := snapshot.Write(ctx, b, f); err != nil {
		_ = f.Close()
		return 0, "", err
	}
	if err := f.Close(); err != nil {
		return 0, "", err
	}
	g, err := os.Open(path) //nolint:gosec // G304: the file just written
	if err != nil {
		return 0, "", err
	}
	defer func() { _ = g.Close() }()
	return snapshotDigest(g)
}

// operatorRaftExportMySQL is step 3 of the migration: read the ciphertext
// straight out of the database (no unseal), write a snapshot, print its digest.
func operatorRaftExportMySQL(args []string) error {
	fs := flag.NewFlagSet("operator raft export-mysql", flag.ExitOnError)
	dsn := fs.String("storage-mysql-dsn", os.Getenv("UBIXVAULT_STORAGE_DSN"),
		"MySQL/MariaDB DSN to read (or $UBIXVAULT_STORAGE_DSN)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	path := fs.Arg(0)
	if path == "" {
		return errors.New("usage: operator raft export-mysql [-storage-mysql-dsn <dsn>] <file>")
	}
	b, _, err := openStorageBackend("mysql", "", *dsn)
	if err != nil {
		return err
	}
	n, sum, err := exportBackend(context.Background(), b, path)
	if err != nil {
		return err
	}
	fmt.Printf("exported %d entries to %s\nsha256 %s\n", n, path, sum)
	fmt.Println("Stop every server on this database first; a snapshot of a live one is not a cutover.")
	return nil
}

// operatorRaftDigest prints the count and digest of a snapshot file. With
// -against <export> it instead checks the file holds every entry of the export
// (a lost entry fails; changed and added ones are listed).
func operatorRaftDigest(args []string) error {
	fs := flag.NewFlagSet("operator raft digest", flag.ExitOnError)
	against := fs.String("against", "", "export snapshot to compare this snapshot with: every entry of it must be present")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.Arg(0) == "" {
		return errors.New("usage: operator raft digest [-against <export>] <snapshot-file>")
	}
	f, err := os.Open(fs.Arg(0)) //nolint:gosec // G304: operator-provided path
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	if *against == "" {
		n, sum, err := snapshotDigest(f)
		if err != nil {
			return err
		}
		fmt.Printf("entries %d\nsha256 %s\n", n, sum)
		return nil
	}
	g, err := os.Open(*against) //nolint:gosec // G304: operator-provided path
	if err != nil {
		return err
	}
	defer func() { _ = g.Close() }()
	missing, changed, added, err := compareSnapshots(g, f)
	if err != nil {
		return err
	}
	fmt.Printf("missing %d\nchanged %d\nadded %d\n", len(missing), len(changed), len(added))
	for _, k := range missing {
		fmt.Printf("missing: %s\n", k)
	}
	for _, k := range changed {
		fmt.Printf("changed: %s\n", k)
	}
	for _, k := range added {
		fmt.Printf("added: %s\n", k)
	}
	if len(missing) > 0 {
		return fmt.Errorf("%d entries of the export are missing", len(missing))
	}
	return nil
}
