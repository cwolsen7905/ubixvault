// Package transit implements encryption-as-a-service (docs/DESIGN.md §3.6): named
// keys that never leave the vault, used to encrypt/decrypt data supplied by
// callers. Applications send plaintext and receive ciphertext (and vice versa)
// without ever handling key material.
//
// Keys are versioned: rotating a key adds a new version used for new encryptions
// while older versions remain able to decrypt existing ciphertext. Ciphertext is
// self-describing — "ubix:v<N>:<base64>" — so decryption selects the right key
// version. The key name is bound as additional authenticated data, so ciphertext
// produced under one key cannot be decrypted under another.
//
// Key material is stored through the barrier, so it is encrypted at rest.
package transit

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/cwolsen7905/ubixvault/internal/storage"
)

// keySize selects AES-256.
const keySize = 32

// cipherPrefix marks a transit ciphertext.
const cipherPrefix = "ubix:"

// Errors.
var (
	ErrKeyNotFound       = errors.New("transit: key not found")
	ErrKeyExists         = errors.New("transit: key already exists")
	ErrInvalidName       = errors.New("transit: invalid key name")
	ErrInvalidCiphertext = errors.New("transit: invalid ciphertext")
)

// Storage is the subset of a backend the engine needs.
type Storage interface {
	Get(ctx context.Context, key string) (*storage.Entry, error)
	Put(ctx context.Context, entry *storage.Entry) error
	Delete(ctx context.Context, key string) error
	List(ctx context.Context, prefix string) ([]string, error)
}

// keyData is the persisted form of a transit key, including its version material.
type keyData struct {
	Name          string         `json:"name"`
	Versions      map[int][]byte `json:"versions"` // version -> AES-256 key
	LatestVersion int            `json:"latest_version"`
	CreatedTime   time.Time      `json:"created_time"`
}

// KeyInfo is the non-secret metadata for a key.
type KeyInfo struct {
	Name          string    `json:"name"`
	LatestVersion int       `json:"latest_version"`
	Versions      []int     `json:"versions"`
	CreatedTime   time.Time `json:"created_time"`
}

// Engine is a transit secrets engine mounted at a storage prefix.
type Engine struct {
	store  Storage
	prefix string
	now    func() time.Time
}

// New returns a transit engine storing under prefix (e.g. "transit").
func New(store Storage, prefix string) *Engine {
	return &Engine{
		store:  store,
		prefix: strings.Trim(prefix, "/"),
		now:    func() time.Time { return time.Now().UTC() },
	}
}

func (e *Engine) keyPath(name string) string { return e.prefix + "/key/" + name }

func (e *Engine) validateName(name string) error {
	if name == "" || strings.Contains(name, "/") {
		return ErrInvalidName
	}
	if storage.ValidateKey(e.keyPath(name)) != nil {
		return ErrInvalidName
	}
	return nil
}

// CreateKey creates a new key with a single version. It fails with [ErrKeyExists]
// if the name is already in use.
func (e *Engine) CreateKey(ctx context.Context, name string) (*KeyInfo, error) {
	if err := e.validateName(name); err != nil {
		return nil, err
	}
	if _, err := e.load(ctx, name); err == nil {
		return nil, ErrKeyExists
	} else if !errors.Is(err, ErrKeyNotFound) {
		return nil, err
	}

	material, err := randomKey()
	if err != nil {
		return nil, err
	}
	k := &keyData{
		Name:          name,
		Versions:      map[int][]byte{1: material},
		LatestVersion: 1,
		CreatedTime:   e.now(),
	}
	if err := e.save(ctx, k); err != nil {
		return nil, err
	}
	return info(k), nil
}

// Rotate adds a new key version, which becomes the version used for encryption.
func (e *Engine) Rotate(ctx context.Context, name string) (*KeyInfo, error) {
	k, err := e.load(ctx, name)
	if err != nil {
		return nil, err
	}
	material, err := randomKey()
	if err != nil {
		return nil, err
	}
	k.LatestVersion++
	k.Versions[k.LatestVersion] = material
	if err := e.save(ctx, k); err != nil {
		return nil, err
	}
	return info(k), nil
}

// ReadKey returns a key's metadata (never its material).
func (e *Engine) ReadKey(ctx context.Context, name string) (*KeyInfo, error) {
	k, err := e.load(ctx, name)
	if err != nil {
		return nil, err
	}
	return info(k), nil
}

// ListKeys returns the names of all keys.
func (e *Engine) ListKeys(ctx context.Context) ([]string, error) {
	names, err := e.store.List(ctx, e.prefix+"/key/")
	if err != nil {
		return nil, fmt.Errorf("transit: list keys: %w", err)
	}
	return names, nil
}

// DeleteKey removes a key and all its versions.
func (e *Engine) DeleteKey(ctx context.Context, name string) error {
	if err := e.validateName(name); err != nil {
		return err
	}
	if err := e.store.Delete(ctx, e.keyPath(name)); err != nil {
		return fmt.Errorf("transit: delete key: %w", err)
	}
	return nil
}

// Encrypt encrypts plaintext with the key's latest version and returns a
// self-describing ciphertext string.
func (e *Engine) Encrypt(ctx context.Context, name string, plaintext []byte) (string, error) {
	k, err := e.load(ctx, name)
	if err != nil {
		return "", err
	}
	aead, err := newAEAD(k.Versions[k.LatestVersion])
	if err != nil {
		return "", err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", fmt.Errorf("transit: nonce: %w", err)
	}
	sealed := aead.Seal(nonce, nonce, plaintext, []byte(name))
	return fmt.Sprintf("%sv%d:%s", cipherPrefix, k.LatestVersion, base64.StdEncoding.EncodeToString(sealed)), nil
}

// Decrypt reverses Encrypt, selecting the key version named in the ciphertext.
func (e *Engine) Decrypt(ctx context.Context, name, ciphertext string) ([]byte, error) {
	version, blob, err := parseCiphertext(ciphertext)
	if err != nil {
		return nil, err
	}
	k, err := e.load(ctx, name)
	if err != nil {
		return nil, err
	}
	material, ok := k.Versions[version]
	if !ok {
		return nil, ErrInvalidCiphertext
	}
	aead, err := newAEAD(material)
	if err != nil {
		return nil, err
	}
	if len(blob) < aead.NonceSize() {
		return nil, ErrInvalidCiphertext
	}
	nonce, ct := blob[:aead.NonceSize()], blob[aead.NonceSize():]
	plaintext, err := aead.Open(nil, nonce, ct, []byte(name))
	if err != nil {
		return nil, ErrInvalidCiphertext
	}
	return plaintext, nil
}

func (e *Engine) load(ctx context.Context, name string) (*keyData, error) {
	if err := e.validateName(name); err != nil {
		return nil, err
	}
	entry, err := e.store.Get(ctx, e.keyPath(name))
	if err != nil {
		return nil, fmt.Errorf("transit: read key: %w", err)
	}
	if entry == nil {
		return nil, ErrKeyNotFound
	}
	var k keyData
	if err := json.Unmarshal(entry.Value, &k); err != nil {
		return nil, fmt.Errorf("transit: unmarshal key: %w", err)
	}
	return &k, nil
}

func (e *Engine) save(ctx context.Context, k *keyData) error {
	blob, err := json.Marshal(k)
	if err != nil {
		return fmt.Errorf("transit: marshal key: %w", err)
	}
	if err := e.store.Put(ctx, &storage.Entry{Key: e.keyPath(k.Name), Value: blob}); err != nil {
		return fmt.Errorf("transit: persist key: %w", err)
	}
	return nil
}

func info(k *keyData) *KeyInfo {
	versions := make([]int, 0, len(k.Versions))
	for v := range k.Versions {
		versions = append(versions, v)
	}
	sort.Ints(versions)
	return &KeyInfo{
		Name:          k.Name,
		LatestVersion: k.LatestVersion,
		Versions:      versions,
		CreatedTime:   k.CreatedTime,
	}
}

func randomKey() ([]byte, error) {
	b := make([]byte, keySize)
	if _, err := rand.Read(b); err != nil {
		return nil, fmt.Errorf("transit: generate key: %w", err)
	}
	return b, nil
}

func newAEAD(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("transit: cipher: %w", err)
	}
	return cipher.NewGCM(block)
}

// parseCiphertext splits "ubix:v<N>:<base64>" into its version and raw bytes.
func parseCiphertext(s string) (int, []byte, error) {
	rest, ok := strings.CutPrefix(s, cipherPrefix)
	if !ok {
		return 0, nil, ErrInvalidCiphertext
	}
	verStr, b64, ok := strings.Cut(rest, ":")
	if !ok || !strings.HasPrefix(verStr, "v") {
		return 0, nil, ErrInvalidCiphertext
	}
	version, err := strconv.Atoi(strings.TrimPrefix(verStr, "v"))
	if err != nil || version < 1 {
		return 0, nil, ErrInvalidCiphertext
	}
	blob, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return 0, nil, ErrInvalidCiphertext
	}
	return version, blob, nil
}
