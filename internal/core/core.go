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
	"crypto/aes"
	"crypto/cipher"
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

// Storage locations in the barrier's reserved "core/" namespace, written through
// the physical backend directly so they remain readable while sealed.
const (
	sealConfigPath       = "core/seal-config"
	wrappedMasterKeyPath = "core/auto-master" // auto-unseal: master key wrapped by the KEK
)

// Seal types recorded in the seal config.
const (
	SealTypeShamir = "shamir"
	SealTypeAuto   = "auto"
)

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
	Type        string // "shamir" or "auto"
	Shares      int
	Threshold   int
	Progress    int // shares supplied so far toward the current unseal
}

// sealConfig is the persisted seal configuration.
type sealConfig struct {
	Type      string `json:"type"`
	Shares    int    `json:"shares"`
	Threshold int    `json:"threshold"`
}

// Core manages initialization and seal/unseal over a storage backend.
type Core struct {
	phys    storage.Backend
	barrier *barrier.Barrier
	tokens  *token.Store
	autoKEK []byte // key-encryption key for auto-unseal; nil means Shamir mode

	mu       sync.Mutex
	progress [][]byte // unseal shares gathered so far (in-memory only)
}

// Option configures a Core.
type Option func(*Core)

// WithAutoUnsealKey enables auto-unseal, protecting the master key with the
// given 32-byte key-encryption key instead of Shamir shares. In production this
// key comes from a KMS/HSM; here it is supplied directly.
func WithAutoUnsealKey(kek []byte) Option {
	return func(c *Core) { c.autoKEK = kek }
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
func (c *Core) AutoUnsealEnabled() bool { return c.autoKEK != nil }

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
	if c.autoKEK == nil {
		// Shamir mode requires a valid share configuration.
		if cfg.SecretShares < 2 || cfg.SecretShares > 255 ||
			cfg.SecretThreshold < 2 || cfg.SecretThreshold > cfg.SecretShares {
			return nil, ErrInvalidConfig
		}
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

	if c.autoKEK != nil {
		// Auto-unseal: wrap the master key under the KEK and store it, leaving
		// the barrier unsealed.
		wrapped, err := wrapKey(c.autoKEK, masterKey)
		if err != nil {
			c.barrier.Seal()
			return nil, err
		}
		if err := c.phys.Put(ctx, &storage.Entry{Key: wrappedMasterKeyPath, Value: wrapped}); err != nil {
			c.barrier.Seal()
			return nil, fmt.Errorf("core: persist wrapped master key: %w", err)
		}
		if err := c.writeSealConfig(ctx, sealConfig{Type: SealTypeAuto}); err != nil {
			return nil, err
		}
		return &InitResult{RootToken: root.ID}, nil
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
	if c.autoKEK == nil {
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
	if cfg.Type != SealTypeAuto {
		return ErrNotAutoUnseal
	}

	entry, err := c.phys.Get(ctx, wrappedMasterKeyPath)
	if err != nil {
		return fmt.Errorf("core: read wrapped master key: %w", err)
	}
	if entry == nil {
		return fmt.Errorf("core: wrapped master key missing")
	}
	masterKey, err := unwrapKey(c.autoKEK, entry.Value)
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
	if cfg.Type == SealTypeAuto {
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

// zero overwrites b with zeros (best-effort key hygiene).
func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// wrapKey encrypts the master key under the auto-unseal KEK (AES-256-GCM). The
// output is nonce || ciphertext+tag.
func wrapKey(kek, masterKey []byte) ([]byte, error) {
	aead, err := newAEAD(kek)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("core: wrap nonce: %w", err)
	}
	return aead.Seal(nonce, nonce, masterKey, nil), nil
}

// unwrapKey reverses wrapKey. A wrong KEK fails the GCM authentication.
func unwrapKey(kek, wrapped []byte) ([]byte, error) {
	aead, err := newAEAD(kek)
	if err != nil {
		return nil, err
	}
	if len(wrapped) < aead.NonceSize() {
		return nil, fmt.Errorf("core: wrapped master key malformed")
	}
	nonce, ct := wrapped[:aead.NonceSize()], wrapped[aead.NonceSize():]
	master, err := aead.Open(nil, nonce, ct, nil)
	if err != nil {
		return nil, fmt.Errorf("core: auto-unseal key incorrect: %w", err)
	}
	return master, nil
}

// newAEAD builds an AES-256-GCM AEAD from a 32-byte key.
func newAEAD(key []byte) (cipher.AEAD, error) {
	if len(key) != masterKeySize {
		return nil, fmt.Errorf("core: auto-unseal key must be %d bytes", masterKeySize)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("core: cipher: %w", err)
	}
	return cipher.NewGCM(block)
}
