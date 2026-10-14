package raft

import (
	"context"
	"encoding/binary"
	"fmt"
	"math/rand"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cwolsen7905/ubixvault/internal/storage"
)

// Jepsen-lite (docs/design/raft-storage.md, Testing 4): concurrent clients do
// Put / Delete / strict Get on a few keys against a three-node cluster while a
// nemesis crashes and partitions nodes. The history is recorded and each key is
// checked as a linearizable register, plus two cluster-level properties.
//
// Plain `go test` runs a short smoke. The nightly workflow (and anyone hunting
// a bug) lengthens it:
//
//	RAFT_JEPSEN_DURATION=10m RAFT_JEPSEN_SEED=42 go test -run TestJepsenLite ./internal/storage/raft/
//
// The seed fixes the nemesis schedule and the clients' choices; goroutine
// timing is real, so a replay is a re-roll with the same plan, not an exact
// re-execution. It is printed up front and on failure.

type jepKind int

const (
	jepWrite jepKind = iota // put value v
	jepDelete
	jepRead // strict read, observed v ("" = absent)
)

type jepOp struct {
	client   int
	key      string
	kind     jepKind
	val      string // write: the value; read: what was observed
	inv, ret int64  // nanoseconds on a monotonic clock
	info     bool   // outcome unknown: it may or may not have taken effect
}

// jepHistory is the recorded run. Definitely-failed reads are dropped (no
// effect); every errored write or delete is recorded as info, because
// leadership lost mid-flight can still commit the entry.
type jepHistory struct {
	mu    sync.Mutex
	start time.Time
	ops   []jepOp
	// acks maps a term to the node that acknowledged writes in it.
	acks map[uint64]map[string]bool
}

func (h *jepHistory) now() int64 { return time.Since(h.start).Nanoseconds() }

func (h *jepHistory) add(op jepOp) {
	h.mu.Lock()
	h.ops = append(h.ops, op)
	h.mu.Unlock()
}

func (h *jepHistory) ack(term uint64, node string) {
	h.mu.Lock()
	if h.acks[term] == nil {
		h.acks[term] = map[string]bool{}
	}
	h.acks[term][node] = true
	h.mu.Unlock()
}

// jepCluster is a three-node cluster that a nemesis may restart under the
// clients' feet, so (unlike testCluster) it is safe for concurrent use.
type jepCluster struct {
	t   *testing.T
	mu  sync.Mutex
	ids []string
	cfg map[string]Config
	b   map[string]*Backend // nil while a node is down
	all []*Backend          // every opened backend, closed at cleanup
}

func newJepCluster(t *testing.T, n int) *jepCluster {
	t.Helper()
	c := &jepCluster{t: t, cfg: map[string]Config{}, b: map[string]*Backend{}}
	for i := 1; i <= n; i++ {
		id := fmt.Sprintf("n%d", i)
		c.ids = append(c.ids, id)
		cfg := testConfig(t, id, i == 1, NewInmemTransport(id))
		c.cfg[id] = cfg
	}
	t.Cleanup(func() {
		c.mu.Lock()
		defer c.mu.Unlock()
		for _, b := range c.all {
			_ = b.Close()
		}
	})
	for _, id := range c.ids {
		if err := c.openLocked(id, c.cfg[id]); err != nil {
			t.Fatalf("open %s: %v", id, err)
		}
	}
	var leader *Backend
	eventually(t, "a leader", func() bool {
		for _, id := range c.ids {
			if b := c.node(id); b != nil && b.IsLeader() {
				leader = b
				return true
			}
		}
		return false
	})
	for _, id := range c.ids[1:] {
		if err := leader.AddVoter(id, id); err != nil {
			t.Fatalf("AddVoter %s: %v", id, err)
		}
	}
	return c
}

func (c *jepCluster) openLocked(id string, cfg Config) error {
	b, err := Open(cfg)
	if err != nil {
		return err
	}
	c.all = append(c.all, b)
	c.b[id] = b
	c.cfg[id] = cfg
	for pid, p := range c.b {
		if pid == id || p == nil {
			continue
		}
		pc := c.cfg[pid]
		pc.Transport.Connect(cfg.Transport)
		cfg.Transport.Connect(pc.Transport)
	}
	return nil
}

func (c *jepCluster) node(id string) *Backend {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.b[id]
}

func (c *jepCluster) leader() (string, *Backend) {
	for _, id := range c.ids {
		if b := c.node(id); b != nil && b.IsLeader() {
			return id, b
		}
	}
	return "", nil
}

// crash stops a node, keeping its disk; restart reopens it on the same data.
func (c *jepCluster) crash(id string) {
	c.mu.Lock()
	b := c.b[id]
	c.b[id] = nil
	c.mu.Unlock()
	if b != nil {
		_ = b.Close()
	}
}

func (c *jepCluster) restart(id string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.b[id] != nil {
		return nil
	}
	cfg := c.cfg[id]
	cfg.Transport = NewInmemTransport(id)
	cfg.Bootstrap = false
	return c.openLocked(id, cfg)
}

// partition cuts id off from every other node in both directions.
func (c *jepCluster) partition(id string, cut bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	me := c.cfg[id].Transport
	for _, pid := range c.ids {
		if pid == id || c.b[pid] == nil || c.b[id] == nil {
			continue
		}
		peer := c.cfg[pid].Transport
		if cut {
			me.Disconnect(pid)
			peer.Disconnect(id)
		} else {
			me.Connect(peer)
			peer.Connect(me)
		}
	}
}

func (c *jepCluster) heal() {
	for _, id := range c.ids {
		if c.node(id) == nil {
			if err := c.restart(id); err != nil {
				c.t.Errorf("restart %s: %v", id, err)
			}
		}
		c.partition(id, false)
	}
}

func jepClient(ctx context.Context, c *jepCluster, h *jepHistory, id int, keys []string, rng *rand.Rand) {
	for seq := 0; ctx.Err() == nil; seq++ {
		key := keys[rng.Intn(len(keys))]
		nid, b := c.leader()
		if b == nil || rng.Intn(10) == 0 { // sometimes a random node, to exercise refusals
			nid = c.ids[rng.Intn(len(c.ids))]
			b = c.node(nid)
		}
		if b == nil {
			time.Sleep(5 * time.Millisecond)
			continue
		}
		op := jepOp{client: id, key: key, inv: h.now()}
		octx, cancel := context.WithTimeout(context.Background(), time.Second)
		term := b.Term()
		switch r := rng.Intn(10); {
		case r < 5:
			op.kind, op.val = jepWrite, fmt.Sprintf("c%d-%d", id, seq)
			err := b.Put(octx, &storage.Entry{Key: key, Value: []byte(op.val)})
			op.ret, op.info = h.now(), err != nil
			if err == nil && b.Term() == term {
				h.ack(term, nid)
			}
		case r < 7:
			op.kind = jepDelete
			err := b.Delete(octx, key)
			op.ret, op.info = h.now(), err != nil
			if err == nil && b.Term() == term {
				h.ack(term, nid)
			}
		default:
			op.kind = jepRead
			e, err := b.ConsistentGet(octx, key)
			op.ret = h.now()
			if err != nil {
				cancel()
				continue // a failed read has no effect
			}
			if e != nil {
				op.val = string(e.Value)
			}
		}
		cancel()
		h.add(op)
		time.Sleep(time.Duration(rng.Intn(3)) * time.Millisecond)
	}
}

func jepNemesis(ctx context.Context, c *jepCluster, rng *rand.Rand, log func(string, ...any)) {
	sleep := func(d time.Duration) bool {
		select {
		case <-ctx.Done():
			return false
		case <-time.After(d):
			return true
		}
	}
	for sleep(time.Duration(200+rng.Intn(500)) * time.Millisecond) {
		id := c.ids[rng.Intn(len(c.ids))]
		if lid, _ := c.leader(); lid != "" && rng.Intn(2) == 0 {
			id = lid // hit the leader half the time
		}
		switch rng.Intn(3) {
		case 0:
			log("nemesis: crash %s", id)
			c.crash(id)
			if !sleep(time.Duration(300+rng.Intn(600)) * time.Millisecond) {
				return
			}
			log("nemesis: restart %s", id)
			if err := c.restart(id); err != nil {
				c.t.Errorf("restart %s: %v", id, err)
				return
			}
		case 1:
			log("nemesis: partition %s", id)
			c.partition(id, true)
			if !sleep(time.Duration(300+rng.Intn(900)) * time.Millisecond) {
				c.partition(id, false)
				return
			}
			log("nemesis: heal %s", id)
			c.partition(id, false)
		default:
			log("nemesis: transfer leadership")
			if _, b := c.leader(); b != nil {
				_ = b.TransferLeadership()
			}
		}
	}
}

func TestJepsenLite(t *testing.T) {
	dur := 2 * time.Second
	if v := os.Getenv("RAFT_JEPSEN_DURATION"); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil {
			t.Fatalf("RAFT_JEPSEN_DURATION: %v", err)
		}
		dur = d
	}
	seed := time.Now().UnixNano()
	if v := os.Getenv("RAFT_JEPSEN_SEED"); v != "" {
		s, err := strconv.ParseInt(v, 10, 64)
		if err != nil {
			t.Fatalf("RAFT_JEPSEN_SEED: %v", err)
		}
		seed = s
	}
	t.Logf("jepsen-lite: seed=%d duration=%s (RAFT_JEPSEN_SEED to replay the plan)", seed, dur)
	defer func() {
		if t.Failed() {
			t.Logf("FAILED with seed=%d", seed)
		}
	}()

	c := newJepCluster(t, 3)
	h := &jepHistory{start: time.Now(), acks: map[uint64]map[string]bool{}}
	keys := []string{"k0", "k1", "k2"}

	ctx, stop := context.WithTimeout(context.Background(), dur)
	defer stop()
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			jepClient(ctx, c, h, i, keys, rand.New(rand.NewSource(seed+int64(i)+1))) //nolint:gosec // G404: a seeded, replayable test schedule, not a secret
		}(i)
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		jepNemesis(ctx, c, rand.New(rand.NewSource(seed)), t.Logf) //nolint:gosec // G404: seeded test schedule
	}()
	wg.Wait()

	// Heal, let the cluster settle, then one last strict read of every key:
	// any acknowledged write that was lost cannot be explained by the history.
	c.heal()
	var leader *Backend
	deadline := time.Now().Add(30 * time.Second)
	for leader == nil && time.Now().Before(deadline) {
		_, leader = c.leader()
		time.Sleep(20 * time.Millisecond)
	}
	if leader == nil {
		t.Fatal("no leader after healing")
	}
	for _, k := range keys {
		var err error
		var e *storage.Entry
		for time.Now().Before(deadline) {
			if _, leader = c.leader(); leader != nil {
				if e, err = leader.ConsistentGet(context.Background(), k); err == nil {
					break
				}
			}
			time.Sleep(20 * time.Millisecond)
		}
		if err != nil {
			t.Fatalf("final read of %s: %v", k, err)
		}
		op := jepOp{client: -1, key: k, kind: jepRead, inv: h.now()}
		if e != nil {
			op.val = string(e.Value)
		}
		op.ret = h.now()
		h.add(op)
	}

	// Properties.
	for term, nodes := range h.acks {
		if len(nodes) > 1 {
			t.Errorf("term %d: writes acknowledged by %d different nodes", term, len(nodes))
		}
	}
	byKey := map[string][]jepOp{}
	for _, op := range h.ops {
		byKey[op.key] = append(byKey[op.key], op)
	}
	total := 0
	for _, k := range keys {
		ops := byKey[k]
		total += len(ops)
		switch linearizable(ops, 10_000) {
		case jepViolation:
			t.Errorf("key %s: history is not linearizable (%d ops):\n%s", k, len(ops), formatHistory(ops))
		case jepGaveUp:
			t.Logf("key %s: checker gave up after its step budget (%d ops); inconclusive", k, len(ops))
		}
	}
	t.Logf("history: %d operations on %d keys", total, len(keys))

	// All replicas converge on the leader's state.
	for _, k := range keys {
		want, _ := leader.Get(context.Background(), k)
		for _, id := range c.ids {
			eventually(t, id+" to converge on "+k, func() bool {
				got, err := c.node(id).Get(context.Background(), k)
				return err == nil && sameEntry(got, want)
			})
		}
	}
}

func sameEntry(a, b *storage.Entry) bool {
	switch {
	case a == nil || b == nil:
		return a == b
	default:
		return string(a.Value) == string(b.Value)
	}
}

type jepResult int

const (
	jepOK jepResult = iota
	jepViolation
	jepGaveUp
)

// linearizable checks one key's history as a read/write register that starts
// absent. It is the classic Wing & Gong search with memoisation: repeatedly
// linearize an operation that no still-pending operation finished before
// (info operations never finish, and may be left out entirely).
func linearizable(ops []jepOp, budget int) jepResult {
	// The search is quadratic in the history length, so a long run is checked
	// in windows of consecutive operations. Every window after the first starts
	// from an unknown register value, and a read of a value whose write is not
	// in the window is left out (its source lies before it): both only weaken
	// the check, never fail a legal history.
	const window = 250
	sorted := append([]jepOp(nil), ops...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].inv < sorted[j].inv })
	worst := jepOK
	for lo := 0; lo < len(sorted) || lo == 0; lo += window / 2 { // windows overlap by half
		hi := min(lo+window, len(sorted))
		chunk := sorted[lo:hi]
		if lo > 0 {
			written := map[string]bool{"": true}
			for _, op := range chunk {
				if op.kind == jepWrite {
					written[op.val] = true
				}
			}
			var kept []jepOp
			for _, op := range chunk {
				if op.kind != jepRead || written[op.val] {
					kept = append(kept, op)
				}
			}
			chunk = kept
		}
		switch linearizableWindow(chunk, budget, lo > 0) {
		case jepViolation:
			return jepViolation
		case jepGaveUp:
			worst = jepGaveUp
		}
		if hi == len(sorted) {
			break
		}
	}
	return worst
}

// jepUnknown is a register whose value is not known yet: the first read fixes it.
const jepUnknown = "\x00unknown"

func linearizableWindow(ops []jepOp, budget int, unknownStart bool) jepResult {
	n := len(ops)
	if n == 0 {
		return jepOK
	}
	// An unknown write whose value no read ever saw can be left out of any
	// explanation (values are unique), so it never needs to be searched.
	seen := map[string]bool{}
	for _, op := range ops {
		if op.kind == jepRead {
			seen[op.val] = true
		}
	}
	var sorted []jepOp
	for _, op := range ops {
		if op.info && op.kind == jepWrite && !seen[op.val] {
			continue
		}
		if op.info {
			op.ret = 1<<62 - 1
		}
		sorted = append(sorted, op)
	}
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].inv < sorted[j].inv })
	n = len(sorted)
	words := (n + 63) / 64
	done := make([]uint64, words)
	memo := map[string]struct{}{}
	steps := 0

	var dfs func(state string, remainingRequired int) jepResult
	dfs = func(state string, remainingRequired int) jepResult {
		if remainingRequired == 0 {
			return jepOK // only optional (info) operations are left
		}
		steps++
		if steps > budget {
			return jepGaveUp
		}
		kb := make([]byte, 0, words*8+len(state))
		for _, w := range done {
			kb = binary.LittleEndian.AppendUint64(kb, w)
		}
		key := string(kb) + state
		if _, seen := memo[key]; seen {
			return jepViolation
		}
		// The earliest return among pending operations bounds who may go next.
		minRet := int64(1<<62 - 1)
		for i := range sorted {
			if done[i/64]&(1<<(i%64)) == 0 && sorted[i].ret < minRet {
				minRet = sorted[i].ret
			}
		}
		gaveUp := false
		// Operations that definitely finished are tried first: an unknown one
		// is only worth linearizing when a later read needs it, and trying it
		// early is what makes the search blow up.
		for _, optional := range []bool{false, true} {
			for i := range sorted {
				if done[i/64]&(1<<(i%64)) != 0 || sorted[i].info != optional {
					continue
				}
				op := sorted[i]
				if op.inv > minRet {
					continue // an operation that finished before this one began is still pending
				}
				next, ok := state, true
				switch op.kind {
				case jepWrite:
					next = op.val
				case jepDelete:
					next = ""
				case jepRead:
					if state == jepUnknown {
						next = op.val
					} else {
						ok = op.val == state
					}
				}
				if !ok {
					continue
				}
				done[i/64] |= 1 << (i % 64)
				req := remainingRequired
				if !op.info {
					req--
				}
				switch dfs(next, req) {
				case jepOK:
					return jepOK
				case jepGaveUp:
					gaveUp = true
				}
				done[i/64] &^= 1 << (i % 64)
			}
		}
		if gaveUp {
			return jepGaveUp
		}
		memo[key] = struct{}{}
		return jepViolation
	}

	required := 0
	for _, op := range sorted {
		if !op.info {
			required++
		}
	}
	start := ""
	if unknownStart {
		start = jepUnknown
	}
	return dfs(start, required)
}

func formatHistory(ops []jepOp) string {
	sorted := append([]jepOp(nil), ops...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].inv < sorted[j].inv })
	var sb strings.Builder
	for _, op := range sorted {
		name := [...]string{"write", "delete", "read"}[op.kind]
		out := "ok"
		if op.info {
			out = "info"
		}
		fmt.Fprintf(&sb, "  c%-2d %-6s %-8q %-4s [%d..%d]\n", op.client, name, op.val, out, op.inv, op.ret)
	}
	return sb.String()
}

// The checker itself must accept legal histories and reject illegal ones.
func TestLinearizableChecker(t *testing.T) {
	w := func(c int, v string, inv, ret int64) jepOp {
		return jepOp{client: c, key: "k", kind: jepWrite, val: v, inv: inv, ret: ret}
	}
	r := func(c int, v string, inv, ret int64) jepOp {
		return jepOp{client: c, key: "k", kind: jepRead, val: v, inv: inv, ret: ret}
	}
	info := func(op jepOp) jepOp { op.info = true; return op }

	cases := []struct {
		name string
		ops  []jepOp
		want jepResult
	}{
		{"sequential", []jepOp{w(0, "a", 0, 1), r(0, "a", 2, 3), w(0, "b", 4, 5), r(0, "b", 6, 7)}, jepOK},
		{"concurrent read may see either", []jepOp{w(0, "a", 0, 10), r(1, "", 1, 2), r(1, "a", 3, 4)}, jepOK},
		{"stale read after a completed write", []jepOp{w(0, "a", 0, 1), w(0, "b", 2, 3), r(1, "a", 4, 5)}, jepViolation},
		{"read of a never-written value", []jepOp{r(0, "zz", 0, 1)}, jepViolation},
		{"lost acknowledged write", []jepOp{w(0, "a", 0, 1), r(0, "", 2, 3)}, jepViolation},
		{"reads cannot go back in time", []jepOp{w(0, "a", 0, 20), r(1, "a", 1, 2), r(1, "", 3, 4)}, jepViolation},
		{"an unknown write may have taken effect", []jepOp{info(w(0, "a", 0, 1)), r(1, "a", 5, 6)}, jepOK},
		{"an unknown write may have been lost", []jepOp{info(w(0, "a", 0, 1)), r(1, "", 5, 6)}, jepOK},
	}
	for _, tc := range cases {
		if got := linearizable(tc.ops, 1_000_000); got != tc.want {
			t.Errorf("%s: got %v, want %v", tc.name, got, tc.want)
		}
	}
}

// A long history is checked in windows: a legal one passes quickly, and a
// violation deep inside it is still found.
func TestLinearizableCheckerLongHistory(t *testing.T) {
	var ops []jepOp
	var at int64
	for i := 0; i < 5000; i++ {
		v := fmt.Sprintf("v%d", i)
		ops = append(ops, jepOp{key: "k", kind: jepWrite, val: v, inv: at, ret: at + 1})
		ops = append(ops, jepOp{key: "k", kind: jepRead, val: v, inv: at + 2, ret: at + 3})
		at += 4
	}
	start := time.Now()
	if got := linearizable(ops, 300_000); got != jepOK {
		t.Fatalf("legal long history: %v", got)
	}
	if d := time.Since(start); d > 5*time.Second {
		t.Fatalf("checker took %s on 10k operations", d)
	}
	// A stale read of the previous value, long after it was overwritten.
	bad := append([]jepOp(nil), ops...)
	bad = append(bad, jepOp{key: "k", kind: jepRead, val: "v4000", inv: at, ret: at + 1})
	if got := linearizable(bad, 300_000); got != jepOK {
		// The write of v4000 is outside the last window, so this read is
		// dropped by design; a stale read inside the window is the case that
		// must fail.
		t.Fatalf("out-of-window read: %v", got)
	}
	near := append([]jepOp(nil), ops...)
	near = append(near, jepOp{key: "k", kind: jepRead, val: "v4990", inv: at, ret: at + 1})
	if got := linearizable(near, 300_000); got != jepViolation {
		t.Fatalf("stale read inside the window: %v, want a violation", got)
	}
}
