// Package core orchestrates initialization and the seal/unseal lifecycle: it
// ties the Shamir secret-sharing scheme to the encryption barrier (docs/DESIGN.md
// §3.1). It is the logic behind the operator init / unseal / seal / status
// commands.
//
// Chain of protection: unseal shares -> master key -> barrier key -> data.
//   - Initialize generates a random master key, hands it to the barrier, splits
//     it into k-of-n Shamir shares, returns the shares, and discards the key.
//   - Unseal collects shares one at a time; once the threshold is reached it
//     reconstructs the master key and unseals the barrier.
//
// The number of shares and the threshold are persisted (unencrypted, since they
// are needed before unseal and are not secret) so Unseal knows how many shares
// to expect.
package core

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"sync"

	"github.com/cwolsen7905/ubixvault/internal/barrier"
	"github.com/cwolsen7905/ubixvault/internal/shamir"
	"github.com/cwolsen7905/ubixvault/internal/storage"
	"github.com/cwolsen7905/ubixvault/internal/token"
)

// masterKeySize is the length of the generated master key (AES-256).
const masterKeySize = 32

// sealConfigPath is where the (non-secret) share/threshold configuration lives.
// It sits in the barrier's reserved "core/" namespace and is written through the
// physical backend directly, so it remains readable while the barrier is sealed.
const sealConfigPath = "core/seal-config"

// Errors returned by Core.
var (
	ErrAlreadyInitialized = errors.New("core: already initialized")
	ErrNotInitialized     = errors.New("core: not initialized")
	ErrInvalidConfig      = errors.New("core: invalid share configuration")
	ErrInvalidShare       = errors.New("core: invalid unseal share")
	ErrUnsealFailed       = errors.New("core: unseal failed (shares did not reconstruct the master key)")
)

// InitConfig parameterizes [Core.Initialize].
type InitConfig struct {
	SecretShares    int // total shares to generate (2..255)
	SecretThreshold int // shares required to unseal (2..SecretShares)
}

// InitResult is returned by [Core.Initialize]. Keys are the unseal shares and
// RootToken is the initial root token; both are shown to the operator once.
type InitResult struct {
	Keys      [][]byte
	RootToken string
}

// SealStatus describes the current lifecycle state.
type SealStatus struct {
	Initialized bool
	Sealed      bool
	Shares      int
	Threshold   int
	Progress    int // shares supplied so far toward the current unseal
}

// sealConfig is the persisted share/threshold configuration.
type sealConfig struct {
	Shares    int `json:"shares"`
	Threshold int `json:"threshold"`
}

// Core manages initialization and seal/unseal over a storage backend.
type Core struct {
	phys    storage.Backend
	barrier *barrier.Barrier
	tokens  *token.Store

	mu       sync.Mutex
	progress [][]byte // unseal shares gathered so far (in-memory only)
}

// New returns a Core over phys.
func New(phys storage.Backend) *Core {
	b := barrier.New(phys)
	return &Core{phys: phys, barrier: b, tokens: token.NewStore(b)}
}

// Barrier returns the underlying barrier, for use by upper layers once unsealed.
func (c *Core) Barrier() *barrier.Barrier { return c.barrier }

// Tokens returns the token store, for authentication by upper layers.
func (c *Core) Tokens() *token.Store { return c.tokens }

// Initialized reports whether the vault has been initialized.
func (c *Core) Initialized(ctx context.Context) (bool, error) {
	return c.barrier.Initialized(ctx)
}

// Initialize sets up a new vault: it generates a master key, initializes the
// barrier with it, splits it into cfg.SecretShares Shamir shares (cfg.Secret-
// Threshold required to reconstruct), persists the share configuration, and
// returns the shares. The vault is left sealed; callers must Unseal.
func (c *Core) Initialize(ctx context.Context, cfg InitConfig) (*InitResult, error) {
	if cfg.SecretShares < 2 || cfg.SecretShares > 255 ||
		cfg.SecretThreshold < 2 || cfg.SecretThreshold > cfg.SecretShares {
		return nil, ErrInvalidConfig
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	initialized, err := c.barrier.Initialized(ctx)
	if err != nil {
		return nil, err
	}
	if initialized {
		return nil, ErrAlreadyInitialized
	}

	masterKey := make([]byte, masterKeySize)
	if _, err := rand.Read(masterKey); err != nil {
		return nil, fmt.Errorf("core: generate master key: %w", err)
	}
	defer zero(masterKey)

	if err := c.barrier.Initialize(ctx, masterKey); err != nil {
		return nil, fmt.Errorf("core: initialize barrier: %w", err)
	}

	// Briefly unseal to persist the initial root token, then re-seal. The
	// operator must still unseal with the returned shares to use the vault.
	if err := c.barrier.Unseal(ctx, masterKey); err != nil {
		return nil, fmt.Errorf("core: unseal for init: %w", err)
	}
	root, err := c.tokens.CreateRoot(ctx)
	if err != nil {
		c.barrier.Seal()
		return nil, fmt.Errorf("core: create root token: %w", err)
	}
	c.barrier.Seal()

	shares, err := shamir.Split(masterKey, cfg.SecretShares, cfg.SecretThreshold)
	if err != nil {
		return nil, fmt.Errorf("core: split master key: %w", err)
	}

	if err := c.writeSealConfig(ctx, sealConfig{Shares: cfg.SecretShares, Threshold: cfg.SecretThreshold}); err != nil {
		return nil, err
	}

	return &InitResult{Keys: shares, RootToken: root.ID}, nil
}

// Unseal supplies one unseal share. It returns the resulting status. When the
// number of distinct shares reaches the threshold, it reconstructs the master
// key and unseals the barrier; if the shares do not reconstruct a valid key, the
// gathered progress is discarded and [ErrUnsealFailed] is returned.
func (c *Core) Unseal(ctx context.Context, share []byte) (*SealStatus, error) {
	if len(share) != masterKeySize+1 {
		return nil, ErrInvalidShare
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	cfg, err := c.readSealConfig(ctx)
	if err != nil {
		return nil, err
	}

	if !c.barrier.Sealed() {
		return c.statusLocked(cfg, false), nil // already unsealed
	}

	// Ignore a share that has already been supplied.
	if !containsShare(c.progress, share) {
		c.progress = append(c.progress, append([]byte(nil), share...))
	}

	if len(c.progress) < cfg.Threshold {
		return c.statusLocked(cfg, true), nil
	}

	masterKey, err := shamir.Combine(c.progress)
	if err != nil {
		c.resetProgress()
		return nil, fmt.Errorf("core: combine shares: %w", err)
	}
	defer zero(masterKey)

	if err := c.barrier.Unseal(ctx, masterKey); err != nil {
		// Wrong/inconsistent shares reconstruct the wrong key and fail barrier
		// authentication. Discard progress so the operator can start over.
		c.resetProgress()
		if errors.Is(err, barrier.ErrInvalidKey) {
			return nil, ErrUnsealFailed
		}
		return nil, fmt.Errorf("core: unseal barrier: %w", err)
	}

	c.resetProgress()
	return c.statusLocked(cfg, false), nil
}

// Seal re-seals the barrier and discards any in-progress unseal shares.
func (c *Core) Seal() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.barrier.Seal()
	c.resetProgress()
}

// Status returns the current seal status.
func (c *Core) Status(ctx context.Context) (*SealStatus, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	cfg, err := c.readSealConfig(ctx)
	if errors.Is(err, ErrNotInitialized) {
		return &SealStatus{Initialized: false, Sealed: true}, nil
	}
	if err != nil {
		return nil, err
	}
	return c.statusLocked(cfg, c.barrier.Sealed()), nil
}

// statusLocked builds a SealStatus. The caller must hold c.mu.
func (c *Core) statusLocked(cfg *sealConfig, sealed bool) *SealStatus {
	return &SealStatus{
		Initialized: true,
		Sealed:      sealed,
		Shares:      cfg.Shares,
		Threshold:   cfg.Threshold,
		Progress:    len(c.progress),
	}
}

func (c *Core) resetProgress() {
	for _, s := range c.progress {
		zero(s)
	}
	c.progress = nil
}

func (c *Core) writeSealConfig(ctx context.Context, cfg sealConfig) error {
	data, err := json.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("core: marshal seal config: %w", err)
	}
	if err := c.phys.Put(ctx, &storage.Entry{Key: sealConfigPath, Value: data}); err != nil {
		return fmt.Errorf("core: persist seal config: %w", err)
	}
	return nil
}

func (c *Core) readSealConfig(ctx context.Context) (*sealConfig, error) {
	entry, err := c.phys.Get(ctx, sealConfigPath)
	if err != nil {
		return nil, fmt.Errorf("core: read seal config: %w", err)
	}
	if entry == nil {
		return nil, ErrNotInitialized
	}
	var cfg sealConfig
	if err := json.Unmarshal(entry.Value, &cfg); err != nil {
		return nil, fmt.Errorf("core: parse seal config: %w", err)
	}
	return &cfg, nil
}

func containsShare(list [][]byte, s []byte) bool {
	for _, x := range list {
		if bytes.Equal(x, s) {
			return true
		}
	}
	return false
}

// zero overwrites b with zeros (best-effort key hygiene).
func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
