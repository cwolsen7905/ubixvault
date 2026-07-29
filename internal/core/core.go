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
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sync"

	"io"

	"github.com/cwolsen7905/ubixvault/internal/barrier"
	"github.com/cwolsen7905/ubixvault/internal/seal"
	"github.com/cwolsen7905/ubixvault/internal/shamir"
	"github.com/cwolsen7905/ubixvault/internal/snapshot"
	"github.com/cwolsen7905/ubixvault/internal/storage"
	"github.com/cwolsen7905/ubixvault/internal/token"
)

// masterKeySize is the length of the generated master key (AES-256).
const masterKeySize = 32

// Storage locations in the barrier's reserved "core/" namespace, written through
// the physical backend directly so they remain readable while sealed.
const (
	sealConfigPath       = "core/seal-config"
	wrappedMasterKeyPath = "core/auto-master" // auto-unseal: master key wrapped by the KEK
)

// Seal types recorded in the seal config.
const (
	SealTypeShamir  = "shamir"
	SealTypeAuto    = "auto"    // auto-unseal with a locally-held KEK
	SealTypeTransit = "transit" // auto-unseal via a remote Transit engine
)

// isAutoSeal reports whether a seal type is one of the auto-unseal modes (which
// share the recovery-key and root-regeneration behaviour), as opposed to Shamir.
func isAutoSeal(t string) bool { return t == SealTypeAuto || t == SealTypeTransit }

// Errors returned by Core.
var (
	ErrAlreadyInitialized      = errors.New("core: already initialized")
	ErrNotInitialized          = errors.New("core: not initialized")
	ErrInvalidConfig           = errors.New("core: invalid share configuration")
	ErrInvalidShare            = errors.New("core: invalid unseal share")
	ErrUnsealFailed            = errors.New("core: unseal failed (shares did not reconstruct the master key)")
	ErrAutoUnsealNotConfigured = errors.New("core: auto-unseal is not configured")
	ErrNotAutoUnseal           = errors.New("core: vault uses Shamir unseal, not auto-unseal")
	ErrAutoUnsealShamir        = errors.New("core: vault uses auto-unseal; manual unseal not applicable")
	ErrRootGenNotStarted       = errors.New("core: no root-generation attempt in progress")
	ErrRootGenNonce            = errors.New("core: nonce does not match the current attempt")
	ErrRootGenSealed           = errors.New("core: unseal the vault before regenerating root")
	ErrRootGenNotShamir        = errors.New("core: root regeneration requires Shamir unseal")
	ErrRootGenNoRecovery       = errors.New("core: this auto-unseal vault has no recovery keys (initialized before recovery-key support)")
)

// recoveryKeySize is the length of the generated recovery key (auto-unseal mode).
const recoveryKeySize = 32

// RootGenStatus describes a root-token regeneration attempt.
type RootGenStatus struct {
	Started   bool
	Nonce     string
	Progress  int
	Required  int
	Complete  bool
	RootToken string // set only on the update that completes the attempt
}

// rootGen holds the in-progress attempt state.
type rootGen struct {
	nonce    string
	progress [][]byte
}

// InitConfig parameterizes [Core.Initialize].
type InitConfig struct {
	SecretShares    int // total shares to generate (2..255)
	SecretThreshold int // shares required to unseal (2..SecretShares)
}

// InitResult is returned by [Core.Initialize]. In Shamir mode Keys holds the
// unseal shares. In auto-unseal mode Keys is empty and RecoveryKeys holds the
// recovery shares (which authorize root-token regeneration, not unseal).
// RootToken is the initial root token. All are shown to the operator once.
type InitResult struct {
	Keys         [][]byte
	RecoveryKeys [][]byte
	RootToken    string
}

// SealStatus describes the current lifecycle state.
type SealStatus struct {
	Initialized bool
	Sealed      bool
	Type        string // "shamir" or "auto"
	Shares      int
	Threshold   int
	Progress    int // shares supplied so far toward the current unseal
}

// sealConfig is the persisted seal configuration. In Shamir mode Shares and
// Threshold describe the unseal shares. In auto-unseal mode the master key is
// wrapped by the KEK instead, and these describe the *recovery* shares:
// RecoveryHash is the SHA-256 of a random recovery key that k-of-n recovery
// shares reconstruct, used to authorize root-token regeneration.
type sealConfig struct {
	Type         string `json:"type"`
	Shares       int    `json:"shares"`
	Threshold    int    `json:"threshold"`
	RecoveryHash []byte `json:"recovery_hash,omitempty"`
}

// Core manages initialization and seal/unseal over a storage backend.
type Core struct {
	phys    storage.Backend
	barrier *barrier.Barrier
	tokens  *token.Store
	seal    seal.Seal // auto-unseal seal; nil means Shamir mode

	mu          sync.Mutex
	progress    [][]byte // unseal shares gathered so far (in-memory only)
	rootAttempt *rootGen // in-progress root regeneration, if any
}

// Option configures a Core.
type Option func(*Core)

// WithSeal enables auto-unseal, using s to wrap and unwrap the master key
// instead of Shamir shares.
func WithSeal(s seal.Seal) Option {
	return func(c *Core) { c.seal = s }
}

// WithAutoUnsealKey enables auto-unseal with a locally-held 32-byte KEK — a
// convenience for WithSeal(seal.NewStaticKEK(kek)).
func WithAutoUnsealKey(kek []byte) Option {
	return WithSeal(seal.NewStaticKEK(kek))
}

// New returns a Core over phys.
func New(phys storage.Backend, opts ...Option) *Core {
	b := barrier.New(phys)
	c := &Core{phys: phys, barrier: b, tokens: token.NewStore(b)}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

// AutoUnsealEnabled reports whether the core is configured for auto-unseal.
func (c *Core) AutoUnsealEnabled() bool { return c.seal != nil }

// Barrier returns the underlying barrier, for use by upper layers once unsealed.
func (c *Core) Barrier() *barrier.Barrier { return c.barrier }

// Snapshot streams a consistent copy of the entire encrypted store to w. The
// values are ciphertext, so the snapshot never contains plaintext; a restored
// copy still requires the unseal shares (or the auto-unseal KEK).
func (c *Core) Snapshot(ctx context.Context, w io.Writer) error {
	return snapshot.Write(ctx, c.phys, w)
}

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
	// In auto-unseal mode the shares configure the *recovery* keys; default to
	// 5-of-3 when unspecified so callers that don't care still get recovery keys.
	if c.seal != nil && cfg.SecretShares == 0 && cfg.SecretThreshold == 0 {
		cfg.SecretShares, cfg.SecretThreshold = 5, 3
	}
	// Both modes need a valid k-of-n configuration (unseal shares for Shamir,
	// recovery shares for auto-unseal).
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

	// Unseal to persist the initial root token. In Shamir mode we re-seal after
	// (the operator must unseal with the shares); in auto mode we leave it
	// unsealed, since the master key is recoverable from the KEK.
	if err := c.barrier.Unseal(ctx, masterKey); err != nil {
		return nil, fmt.Errorf("core: unseal for init: %w", err)
	}
	root, err := c.tokens.CreateRoot(ctx)
	if err != nil {
		c.barrier.Seal()
		return nil, fmt.Errorf("core: create root token: %w", err)
	}

	if c.seal != nil {
		// Auto-unseal: wrap the master key with the seal and store it, leaving
		// the barrier unsealed.
		wrapped, err := c.seal.Wrap(ctx, masterKey)
		if err != nil {
			c.barrier.Seal()
			return nil, err
		}
		if err := c.phys.Put(ctx, &storage.Entry{Key: wrappedMasterKeyPath, Value: wrapped}); err != nil {
			c.barrier.Seal()
			return nil, fmt.Errorf("core: persist wrapped master key: %w", err)
		}

		// Generate recovery keys: a random recovery key split into k-of-n shares,
		// with only its hash persisted. The KEK unseals; the recovery shares
		// authorize root-token regeneration (the sole recovery path when the
		// operator holds no unseal shares).
		recoveryKey := make([]byte, recoveryKeySize)
		if _, err := rand.Read(recoveryKey); err != nil {
			c.barrier.Seal()
			return nil, fmt.Errorf("core: generate recovery key: %w", err)
		}
		defer zero(recoveryKey)
		recoveryShares, err := shamir.Split(recoveryKey, cfg.SecretShares, cfg.SecretThreshold)
		if err != nil {
			c.barrier.Seal()
			return nil, fmt.Errorf("core: split recovery key: %w", err)
		}
		hash := sha256.Sum256(recoveryKey)
		if err := c.writeSealConfig(ctx, sealConfig{
			Type:         c.seal.Type(),
			Shares:       cfg.SecretShares,
			Threshold:    cfg.SecretThreshold,
			RecoveryHash: hash[:],
		}); err != nil {
			return nil, err
		}
		return &InitResult{RootToken: root.ID, RecoveryKeys: recoveryShares}, nil
	}

	// Shamir mode: re-seal, split the master key, and return the shares.
	c.barrier.Seal()
	shares, err := shamir.Split(masterKey, cfg.SecretShares, cfg.SecretThreshold)
	if err != nil {
		return nil, fmt.Errorf("core: split master key: %w", err)
	}
	if err := c.writeSealConfig(ctx, sealConfig{Type: SealTypeShamir, Shares: cfg.SecretShares, Threshold: cfg.SecretThreshold}); err != nil {
		return nil, err
	}
	return &InitResult{Keys: shares, RootToken: root.ID}, nil
}

// AutoUnseal unseals the barrier using the configured KEK, without operator
// interaction. It is a no-op if already unsealed.
func (c *Core) AutoUnseal(ctx context.Context) error {
	if c.seal == nil {
		return ErrAutoUnsealNotConfigured
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	if !c.barrier.Sealed() {
		return nil
	}
	cfg, err := c.readSealConfig(ctx)
	if err != nil {
		return err
	}
	if !isAutoSeal(cfg.Type) {
		return ErrNotAutoUnseal
	}

	entry, err := c.phys.Get(ctx, wrappedMasterKeyPath)
	if err != nil {
		return fmt.Errorf("core: read wrapped master key: %w", err)
	}
	if entry == nil {
		return fmt.Errorf("core: wrapped master key missing")
	}
	masterKey, err := c.seal.Unwrap(ctx, entry.Value)
	if err != nil {
		return err
	}
	defer zero(masterKey)

	if err := c.barrier.Unseal(ctx, masterKey); err != nil {
		return fmt.Errorf("core: auto-unseal barrier: %w", err)
	}
	return nil
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
	if isAutoSeal(cfg.Type) {
		return nil, ErrAutoUnsealShamir
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

// GenerateRootInit starts a root-token regeneration attempt and returns its
// nonce. Providing a quorum of unseal shares to GenerateRootUpdate then mints a
// new root token — the recovery path for a lost root token (docs/DESIGN.md §8.3).
// Only Shamir-unseal vaults are supported, and the vault must be unsealed (so the
// new token can be persisted).
func (c *Core) GenerateRootInit(ctx context.Context) (*RootGenStatus, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	cfg, err := c.readSealConfig(ctx)
	if err != nil {
		return nil, err
	}
	// Shamir vaults verify against the master key; auto-unseal vaults verify
	// against the recovery keys generated at init.
	if isAutoSeal(cfg.Type) && len(cfg.RecoveryHash) == 0 {
		return nil, ErrRootGenNoRecovery
	}
	if c.barrier.Sealed() {
		return nil, ErrRootGenSealed
	}

	nonce, err := randomNonce()
	if err != nil {
		return nil, err
	}
	c.rootAttempt = &rootGen{nonce: nonce}
	return &RootGenStatus{Started: true, Nonce: nonce, Progress: 0, Required: cfg.Threshold}, nil
}

// GenerateRootUpdate supplies one unseal share to the attempt identified by
// nonce. When the threshold is reached it reconstructs the master key, verifies
// it, and (if valid) returns a freshly minted root token in the status.
func (c *Core) GenerateRootUpdate(ctx context.Context, nonce string, share []byte) (*RootGenStatus, error) {
	if len(share) != masterKeySize+1 {
		return nil, ErrInvalidShare
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	if c.rootAttempt == nil {
		return nil, ErrRootGenNotStarted
	}
	if nonce != c.rootAttempt.nonce {
		return nil, ErrRootGenNonce
	}
	cfg, err := c.readSealConfig(ctx)
	if err != nil {
		return nil, err
	}

	if !containsShare(c.rootAttempt.progress, share) {
		c.rootAttempt.progress = append(c.rootAttempt.progress, append([]byte(nil), share...))
	}
	if len(c.rootAttempt.progress) < cfg.Threshold {
		return &RootGenStatus{Started: true, Nonce: nonce, Progress: len(c.rootAttempt.progress), Required: cfg.Threshold}, nil
	}

	combined, err := shamir.Combine(c.rootAttempt.progress)
	if err != nil {
		c.rootAttempt = nil
		return nil, fmt.Errorf("core: combine shares: %w", err)
	}
	defer zero(combined)

	// Shamir: the combined value is the master key, verified against the barrier.
	// Auto-unseal: it is the recovery key, verified against its stored hash.
	var ok bool
	if isAutoSeal(cfg.Type) {
		got := sha256.Sum256(combined)
		ok = subtle.ConstantTimeCompare(got[:], cfg.RecoveryHash) == 1
	} else {
		ok, err = c.barrier.VerifyMasterKey(ctx, combined)
		if err != nil {
			c.rootAttempt = nil
			return nil, err
		}
	}
	if !ok {
		c.rootAttempt = nil
		return nil, ErrUnsealFailed
	}

	root, err := c.tokens.CreateRoot(ctx)
	if err != nil {
		c.rootAttempt = nil
		return nil, fmt.Errorf("core: create root token: %w", err)
	}
	c.rootAttempt = nil
	return &RootGenStatus{Started: false, Complete: true, Required: cfg.Threshold, RootToken: root.ID}, nil
}

// GenerateRootCancel discards any in-progress attempt.
func (c *Core) GenerateRootCancel() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.rootAttempt = nil
}

// GenerateRootStatus reports the current attempt.
func (c *Core) GenerateRootStatus(ctx context.Context) (*RootGenStatus, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.rootAttempt == nil {
		return &RootGenStatus{Started: false}, nil
	}
	cfg, err := c.readSealConfig(ctx)
	if err != nil {
		return nil, err
	}
	return &RootGenStatus{
		Started:  true,
		Nonce:    c.rootAttempt.nonce,
		Progress: len(c.rootAttempt.progress),
		Required: cfg.Threshold,
	}, nil
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
		Type:        cfg.Type,
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
	if cfg.Type == "" {
		cfg.Type = SealTypeShamir // configs written before seal types existed
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

// randomNonce returns a random hex nonce for a root-generation attempt.
func randomNonce() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("core: generate nonce: %w", err)
	}
	return hex.EncodeToString(b), nil
}

// zero overwrites b with zeros (best-effort key hygiene).
func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
