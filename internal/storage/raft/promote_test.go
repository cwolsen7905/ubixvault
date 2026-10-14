package raft

import (
	"context"
	"errors"
	"testing"
	"time"
)

type fakeIssuer struct{ err error }

func (f fakeIssuer) IssueBridge(context.Context) ([]byte, []byte, []byte, time.Time, error) {
	if f.err != nil {
		return nil, nil, nil, time.Time{}, f.err
	}
	return []byte("ca"), []byte("cert"), []byte("key"), time.Now().Add(24 * time.Hour), nil
}

func isVoter(b *Backend, id string) bool {
	s, _ := b.Configuration()
	for _, x := range s {
		if x.ID == id {
			return x.Voter
		}
	}
	return false
}

func TestAcceptJoinAndPromotion(t *testing.T) {
	c := newCluster(t, 1, nil)
	leader := c.waitLeader()
	ctx := ctxT(t)

	tok, _, err := leader.MintJoinToken(ctx, 0)
	if err != nil {
		t.Fatal(err)
	}
	joiner := c.start("n2", false, nil)
	br, err := leader.AcceptJoin(ctx, fakeIssuer{}, tok, "n2", joiner.cfg.Transport.Addr())
	if err != nil || string(br.CertPEM) != "cert" {
		t.Fatalf("AcceptJoin = %v, %v", br, err)
	}
	if isVoter(leader, "n2") {
		t.Fatal("joiner must start as a non-voter")
	}
	// The token is burned.
	if _, err := leader.AcceptJoin(ctx, fakeIssuer{}, tok, "n3", "x"); !errors.Is(err, ErrTokenUsed) {
		t.Fatalf("reuse = %v, want ErrTokenUsed", err)
	}

	p := Promotion{Threshold: 4, Stabilization: 100 * time.Millisecond, Interval: 20 * time.Millisecond}
	pctx, cancel := context.WithCancel(ctx)
	defer cancel()
	promoted := make(chan string, 1)
	go leader.RunPromotion(pctx, p, func(id string) { promoted <- id })

	// No report: never promoted.
	time.Sleep(300 * time.Millisecond)
	if isVoter(leader, "n2") {
		t.Fatal("promoted without a report")
	}
	// Reports must keep arriving and stay within the threshold.
	go func() {
		for pctx.Err() == nil {
			leader.ReportApplied("n2", joiner.b.AppliedIndex())
			time.Sleep(20 * time.Millisecond)
		}
	}()
	select {
	case id := <-promoted:
		if id != "n2" {
			t.Fatalf("promoted %q", id)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("not promoted")
	}
	if !isVoter(leader, "n2") {
		t.Fatal("n2 not a voter after promotion")
	}
}

func TestAcceptJoinIssuerFailureKeepsToken(t *testing.T) {
	c := newCluster(t, 1, nil)
	leader := c.waitLeader()
	ctx := ctxT(t)
	tok, _, _ := leader.MintJoinToken(ctx, 0)
	if _, err := leader.AcceptJoin(ctx, fakeIssuer{err: errors.New("no CA")}, tok, "n2", "x"); err == nil {
		t.Fatal("want error")
	}
	if err := leader.RedeemJoinToken(ctx, tok); err != nil {
		t.Fatalf("token was spent by a failed issue: %v", err)
	}
}

func TestStaleReportIsNotCaughtUp(t *testing.T) {
	c := newCluster(t, 1, nil)
	leader := c.waitLeader()
	joiner := c.start("n2", false, nil)
	if err := leader.AddNonvoter("n2", joiner.cfg.Transport.Addr()); err != nil {
		t.Fatal(err)
	}
	p := Promotion{Threshold: 4, Stabilization: time.Millisecond, MaxReportAge: time.Second}
	now := time.Now()
	leader.ReportApplied("n2", joiner.b.AppliedIndex())
	leader.promoteOnce(p, now, nil)                     // starts the window
	leader.promoteOnce(p, now.Add(10*time.Second), nil) // report is now stale
	if isVoter(leader, "n2") {
		t.Fatal("promoted on a stale report")
	}
}
