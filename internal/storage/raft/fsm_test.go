package raft

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"testing"

	hraft "github.com/hashicorp/raft"
	"go.etcd.io/bbolt"
)

func newTestFSM(t *testing.T) *fsm {
	t.Helper()
	f, err := openFSM(filepath.Join(t.TempDir(), "fsm.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.close() })
	return f
}

func cmdLog(t *testing.T, idx uint64, c command) *hraft.Log {
	t.Helper()
	data, err := c.encode()
	if err != nil {
		t.Fatal(err)
	}
	return &hraft.Log{Index: idx, Term: 1, Type: hraft.LogCommand, Data: data}
}

func testLog(t *testing.T) []*hraft.Log {
	return []*hraft.Log{
		cmdLog(t, 1, command{Op: opPut, Key: "a", Value: []byte("1")}),
		cmdLog(t, 2, command{Op: opPut, Key: "b/c", Value: []byte("2")}),
		cmdLog(t, 3, command{Op: opPut, Key: "a", Value: []byte("3")}),
		cmdLog(t, 4, command{Op: opDelete, Key: "b/c"}),
		cmdLog(t, 5, command{Op: opPut, Key: "z", Value: []byte("9")}),
	}
}

func dump(t *testing.T, f *fsm) string {
	t.Helper()
	var buf bytes.Buffer
	err := f.db.View(func(tx *bbolt.Tx) error {
		return tx.Bucket(kvBucket).ForEach(func(k, v []byte) error {
			fmt.Fprintf(&buf, "%q=%q\n", k, v)
			return nil
		})
	})
	if err != nil {
		t.Fatal(err)
	}
	return buf.String()
}

func TestFSMDeterministic(t *testing.T) {
	a, b := newTestFSM(t), newTestFSM(t)
	for _, l := range testLog(t) {
		if r := a.Apply(l); r != nil {
			t.Fatalf("Apply a: %v", r)
		}
		if r := b.Apply(l); r != nil {
			t.Fatalf("Apply b: %v", r)
		}
	}
	want := "\"a\"=\"3\"\n\"z\"=\"9\"\n"
	if da, db := dump(t, a), dump(t, b); da != want || db != want {
		t.Fatalf("state differs or wrong:\na=%q\nb=%q\nwant %q", da, db, want)
	}
}

// Re-applying a prefix of the log (as after a crash) must not change state,
// even where the entries would now overwrite newer values.
func TestFSMIdempotentReapply(t *testing.T) {
	f := newTestFSM(t)
	log := testLog(t)
	for _, l := range log {
		f.Apply(l)
	}
	before := dump(t, f)
	for _, l := range log[:3] {
		if r := f.Apply(l); r != nil {
			t.Fatalf("re-apply: %v", r)
		}
	}
	if after := dump(t, f); after != before {
		t.Fatalf("re-apply changed state:\n%s\nvs\n%s", before, after)
	}
}

func TestFSMRefusesUnknownCommand(t *testing.T) {
	cases := map[string][]byte{
		"future-version": []byte(`{"v":2,"op":"put","key":"a"}`),
		"reserved-txn":   []byte(`{"v":1,"op":"txn","key":"a"}`),
		"garbage":        []byte(`not json`),
	}
	for name, data := range cases {
		f := newTestFSM(t)
		r := f.Apply(&hraft.Log{Index: 1, Type: hraft.LogCommand, Data: data})
		if !errors.Is(asErr(r), ErrFailed) {
			t.Errorf("%s: want ErrFailed, got %v", name, r)
		}
		// Fail-stop: later, valid entries are refused rather than applied.
		r = f.Apply(cmdLog(t, 2, command{Op: opPut, Key: "a", Value: []byte("1")}))
		if !errors.Is(asErr(r), ErrFailed) {
			t.Errorf("%s: entry after failure applied: %v", name, r)
		}
		if got := dump(t, f); got != "" {
			t.Errorf("%s: state mutated after failure: %q", name, got)
		}
	}
}

func asErr(v any) error {
	e, _ := v.(error)
	return e
}

func TestFSMSnapshotRestore(t *testing.T) {
	src := newTestFSM(t)
	for _, l := range testLog(t) {
		src.Apply(l)
	}
	var buf bytes.Buffer
	if err := src.writeSnapshot(t.Context(), &buf); err != nil {
		t.Fatal(err)
	}
	dst := newTestFSM(t)
	dst.Apply(cmdLog(t, 1, command{Op: opPut, Key: "gone", Value: []byte("x")}))
	if err := dst.Restore(io.NopCloser(&buf)); err != nil {
		t.Fatalf("Restore: %v", err)
	}
	if got, want := dump(t, dst), dump(t, src); got != want {
		t.Fatalf("restored %q, want %q", got, want)
	}
}

func FuzzDecodeCommand(f *testing.F) {
	f.Add([]byte(`{"v":1,"op":"put","key":"a","value":"AA=="}`))
	f.Add([]byte(`{"v":9}`))
	f.Add([]byte(``))
	f.Fuzz(func(t *testing.T, data []byte) {
		c, err := decodeCommand(data)
		if err != nil {
			if !errors.Is(err, errUnknownCommand) {
				t.Fatalf("error not classified: %v", err)
			}
			return
		}
		if c.Version != commandVersion || (c.Op != opPut && c.Op != opDelete) {
			t.Fatalf("accepted invalid command %+v", c)
		}
	})
}
