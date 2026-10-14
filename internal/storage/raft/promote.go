package raft

import (
	"context"
	"errors"
	"sync"
	"time"

	hraft "github.com/hashicorp/raft"
)

// LeafIssuer mints the bridge credential handed to a joiner: a leaf from the
// cluster CA for its Raft transport while it is still sealed and cannot issue
// its own (docs/design/raft-storage.md "Join"). cluster.Certs implements it.
type LeafIssuer interface {
	IssueBridge(ctx context.Context) (caPEM, certPEM, keyPEM []byte, notAfter time.Time, err error)
}

// Bridge is the credential returned by [Backend.AcceptJoin].
type Bridge struct {
	CAPEM, CertPEM, KeyPEM []byte
	NotAfter               time.Time
}

// AcceptJoin is the leader side of a join with a bridge credential. The leaf is
// issued before the token is burned, so a CA that is not ready does not spend
// the operator's token.
func (b *Backend) AcceptJoin(ctx context.Context, issuer LeafIssuer, token, id, addr string) (*Bridge, error) {
	if issuer == nil {
		return nil, errors.New("raft: join requires a leaf issuer")
	}
	if !b.IsLeader() {
		return nil, mapErr(hraft.ErrNotLeader)
	}
	ca, cert, key, notAfter, err := issuer.IssueBridge(ctx)
	if err != nil {
		return nil, err
	}
	if err := b.JoinNode(ctx, token, id, addr); err != nil {
		return nil, err
	}
	return &Bridge{CAPEM: ca, CertPEM: cert, KeyPEM: key, NotAfter: notAfter}, nil
}

// AppliedIndex is the last log index this node's state machine has applied; a
// joiner reports it to the leader (the consensus library does not expose
// per-follower match indexes).
func (b *Backend) AppliedIndex() uint64 { return b.r.AppliedIndex() }

// Promotion tunes [Backend.RunPromotion]. Zero fields take the defaults.
type Promotion struct {
	// Threshold is how many entries a non-voter may trail the leader and still
	// count as caught up. Default 16.
	Threshold uint64
	// Stabilization is how long it must stay within Threshold. Default 10s.
	Stabilization time.Duration
	// Interval is how often the leader evaluates. Default 1s.
	Interval time.Duration
	// MaxReportAge is how old a reported index may be. Default 5×Interval.
	MaxReportAge time.Duration
}

type appliedReport struct {
	index uint64
	at    time.Time
}

type promoter struct {
	mu       sync.Mutex
	reports  map[string]appliedReport
	caughtUp map[string]time.Time // since when a node has been within threshold
}

// ReportApplied records a non-voter's applied index, as reported by that node.
// It is only meaningful on the leader and is cheap everywhere else. Reports
// from nodes not in the configuration are ignored at evaluation time.
func (b *Backend) ReportApplied(id string, index uint64) {
	b.promo.mu.Lock()
	defer b.promo.mu.Unlock()
	if b.promo.reports == nil {
		b.promo.reports = map[string]appliedReport{}
	}
	b.promo.reports[id] = appliedReport{index: index, at: time.Now()}
}

// RunPromotion promotes non-voters to voters once they have stayed caught up
// for the stabilization window, until ctx ends. Only the leader acts. It
// returns the IDs it promoted through onPromote (may be nil).
func (b *Backend) RunPromotion(ctx context.Context, p Promotion, onPromote func(id string)) {
	if p.Threshold == 0 {
		p.Threshold = 16
	}
	if p.Stabilization <= 0 {
		p.Stabilization = 10 * time.Second
	}
	if p.Interval <= 0 {
		p.Interval = time.Second
	}
	if p.MaxReportAge <= 0 {
		p.MaxReportAge = 5 * p.Interval
	}
	t := time.NewTicker(p.Interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		b.promoteOnce(p, time.Now(), onPromote)
	}
}

func (b *Backend) promoteOnce(p Promotion, now time.Time, onPromote func(string)) {
	st := &b.promo
	st.mu.Lock()
	var due []Server
	defer func() {
		st.mu.Unlock()
		for _, s := range due {
			// AddVoter on an existing non-voter promotes it.
			if err := b.AddVoter(s.ID, s.Address); err != nil {
				continue
			}
			st.mu.Lock()
			delete(st.reports, s.ID)
			st.mu.Unlock()
			if onPromote != nil {
				onPromote(s.ID)
			}
		}
	}()
	if st.caughtUp == nil {
		st.caughtUp = map[string]time.Time{}
	}
	if !b.IsLeader() {
		clear(st.caughtUp)
		return
	}
	servers, err := b.Configuration()
	if err != nil {
		return
	}
	leaderIdx := b.r.LastIndex()
	seen := map[string]bool{}
	for _, s := range servers {
		if s.Voter {
			continue
		}
		seen[s.ID] = true
		rep, ok := st.reports[s.ID]
		fresh := ok && now.Sub(rep.at) <= p.MaxReportAge
		behind := leaderIdx > rep.index && leaderIdx-rep.index > p.Threshold
		if !fresh || behind {
			delete(st.caughtUp, s.ID)
			continue
		}
		since, ok := st.caughtUp[s.ID]
		if !ok {
			st.caughtUp[s.ID] = now
			continue
		}
		if now.Sub(since) < p.Stabilization {
			continue
		}
		delete(st.caughtUp, s.ID)
		due = append(due, s)
	}
	for id := range st.caughtUp {
		if !seen[id] {
			delete(st.caughtUp, id)
		}
	}
}

// Stats is a point-in-time view for metrics and the operator API.
type Stats struct {
	Term         uint64
	LastIndex    uint64
	AppliedIndex uint64
	Leader       bool
	Voters       int
	Nonvoters    int
	Failed       bool
}

// Stats returns the node's current counters.
func (b *Backend) Stats() Stats {
	s := Stats{
		Term: b.Term(), LastIndex: b.r.LastIndex(), AppliedIndex: b.r.AppliedIndex(),
		Leader: b.IsLeader(), Failed: b.fsm.failed.Load(),
	}
	if servers, err := b.Configuration(); err == nil {
		for _, sv := range servers {
			if sv.Voter {
				s.Voters++
			} else {
				s.Nonvoters++
			}
		}
	}
	return s
}
