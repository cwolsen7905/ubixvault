package core

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cwolsen7905/ubixvault/internal/storage"
)

// haLockName is the one HA lock a vault's replicas contend for.
const haLockName = "active"

// ErrHANotConfigured is returned by [Core.RunHA] when HA is off.
var ErrHANotConfigured = errors.New("core: HA is not configured")

// HAConfig enables active/standby high availability (ADR D-021,
// docs/design/ha-active-standby.md): replicas sharing Backend all unseal, and
// the one holding its lock is active.
type HAConfig struct {
	Backend   storage.HABackend
	HolderID  string // unique per replica process
	Advertise string // URL other replicas reach this one on
	Lock      storage.LockOptions
}

// WithHA enables active/standby HA. The core's storage must be Backend (or a
// wrapper of it), so the lock fences the core's own writes.
func WithHA(cfg HAConfig) Option {
	return func(c *Core) { c.ha.cfg = cfg }
}

// ha is the core's active/standby state. Its zero value means HA is off.
type ha struct {
	cfg    HAConfig
	lock   storage.Lock // this replica's handle on the HA lock
	active atomic.Bool

	mu           sync.Mutex
	activeHooks  []func()
	standbyHooks []func()
}

func (h *ha) init() {
	if h.cfg.Backend != nil {
		h.lock = h.cfg.Backend.HALock(haLockName, h.cfg.HolderID, h.cfg.Advertise, h.cfg.Lock)
	}
}

func (h *ha) enabled() bool { return h.lock != nil }

// acquireForInit takes the HA lock for the duration of an Initialize, through a
// handle of its own so the RunHA loop cannot mistake it for its acquisition.
func (h *ha) acquireForInit(ctx context.Context) (release func(), err error) {
	l := h.cfg.Backend.HALock(haLockName, h.cfg.HolderID+"/init", h.cfg.Advertise, h.cfg.Lock)
	if _, err := l.Acquire(ctx); err != nil {
		return nil, fmt.Errorf("core: acquire HA lock to initialize: %w", err)
	}
	return func() {
		rctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = l.Release(rctx)
	}, nil
}

// HAEnabled reports whether this core runs in active/standby mode.
func (c *Core) HAEnabled() bool { return c.ha.enabled() }

// Active reports whether this replica should serve requests: unsealed and, with
// HA, holding the lock. Without HA, unsealed is enough.
func (c *Core) Active() bool {
	if c.barrier.Sealed() {
		return false
	}
	return !c.ha.enabled() || c.ha.active.Load()
}

// Standby reports whether this replica is unsealed but not active (HA only).
func (c *Core) Standby() bool {
	return c.ha.enabled() && !c.barrier.Sealed() && !c.ha.active.Load()
}

// Leader reports the replica currently holding the HA lock, if any.
func (c *Core) Leader(ctx context.Context) (storage.Holder, error) {
	if !c.ha.enabled() {
		return storage.Holder{}, ErrHANotConfigured
	}
	return c.ha.lock.Holder(ctx)
}

// OnActive registers fn to run each time this replica becomes active, before
// it serves requests as active.
func (c *Core) OnActive(fn func()) {
	c.ha.mu.Lock()
	defer c.ha.mu.Unlock()
	c.ha.activeHooks = append(c.ha.activeHooks, fn)
}

// OnStandby registers fn to run each time this replica stops being active
// (lost the lock, sealed, or shutting down), before the lock is released.
func (c *Core) OnStandby(fn func()) {
	c.ha.mu.Lock()
	defer c.ha.mu.Unlock()
	c.ha.standbyHooks = append(c.ha.standbyHooks, fn)
}

func (c *Core) runHooks(active bool) {
	c.ha.mu.Lock()
	hooks := slices.Clone(c.ha.standbyHooks)
	if active {
		hooks = slices.Clone(c.ha.activeHooks)
	}
	c.ha.mu.Unlock()
	for _, fn := range hooks {
		fn()
	}
}

// notifyLocked wakes everyone waiting on stateChanged. The caller holds c.mu.
func (c *Core) notifyLocked() {
	close(c.stateCh)
	c.stateCh = make(chan struct{})
}

// stateChanged returns a channel closed at the next seal or unseal.
func (c *Core) stateChanged() <-chan struct{} {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.stateCh
}

// waitUnsealed blocks until the barrier is unsealed or ctx ends.
func (c *Core) waitUnsealed(ctx context.Context) error {
	for {
		changed := c.stateChanged()
		if !c.barrier.Sealed() {
			return nil
		}
		select {
		case <-changed:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

// RunHA runs this replica's side of the election until ctx ends: whenever the
// vault is unsealed it waits for the HA lock, becomes active on getting it, and
// steps down — releasing the lock so a standby takes over at once — when the
// lock is lost, the vault is sealed, or ctx ends. logf reports transitions.
// It returns nil when ctx ends, after stepping down.
func (c *Core) RunHA(ctx context.Context, logf func(format string, args ...any)) error {
	if !c.ha.enabled() {
		return ErrHANotConfigured
	}
	for {
		if err := c.waitUnsealed(ctx); err != nil {
			return nil
		}
		changed := c.stateChanged()
		if c.barrier.Sealed() {
			continue
		}

		// Wait for the lock, giving up if the vault is sealed meanwhile.
		acqCtx, cancel := context.WithCancel(ctx)
		go func(sealed <-chan struct{}) {
			select {
			case <-sealed:
				cancel()
			case <-acqCtx.Done():
			}
		}(changed)
		lost, err := c.ha.lock.Acquire(acqCtx)
		if err != nil {
			cancel()
			if ctx.Err() != nil {
				return nil
			}
			if !errors.Is(err, context.Canceled) {
				logf("WARNING: HA lock: %v", err)
				if ctxSleep(ctx, time.Second) != nil {
					return nil
				}
			}
			continue
		}

		changed = c.stateChanged()
		if c.barrier.Sealed() { // sealed while acquiring
			c.releaseHA(logf)
			cancel()
			continue
		}
		c.ha.active.Store(true)
		c.runHooks(true)
		logf("HA: active (%s)", c.ha.cfg.HolderID)

		var reason string
		select {
		case <-lost:
			reason = "lost the HA lock"
		case <-changed:
			reason = "sealed"
		case <-ctx.Done():
			reason = "shutting down"
		}
		c.ha.active.Store(false)
		c.runHooks(false)
		logf("HA: standby (%s)", reason)
		c.releaseHA(logf)
		cancel()
		if ctx.Err() != nil {
			return nil
		}
	}
}

func (c *Core) releaseHA(logf func(string, ...any)) {
	rctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := c.ha.lock.Release(rctx); err != nil {
		logf("WARNING: HA lock release: %v (a standby takes over when the lease expires)", err)
	}
}

func ctxSleep(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}
