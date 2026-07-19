// Package audit records a tamper-aware log of who accessed what, when, and
// whether it succeeded (docs/DESIGN.md §3.7).
//
// An [Entry] is fanned out by a [Broker] to one or more [Device]s. Auditing is
// fail-closed: if a device cannot record a request entry, the broker returns an
// error and the caller refuses the request, so nothing proceeds unaudited.
//
// Devices never write the client token in the clear. Sensitive fields are
// HMAC'd with a per-device key, so the log can correlate activity by token
// without exposing the credential itself.
package audit

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"
)

// Entry is a single audited event. The engine populates it; the device decides
// how to render it (in particular, it HMACs ClientToken rather than writing it).
type Entry struct {
	Time        time.Time
	Type        string // "request" or "response"
	Operation   string // read / create / update / delete / list
	Path        string
	ClientToken string // raw token; HMAC'd by the device, never written in the clear
	RemoteAddr  string
	StatusCode  int // response entries only
}

// Device records audit entries somewhere durable.
type Device interface {
	Log(ctx context.Context, e *Entry) error
	Close() error
}

// logLine is the on-disk JSON shape. Note the absence of a raw-token field.
type logLine struct {
	Time       string `json:"time"`
	Type       string `json:"type"`
	Operation  string `json:"operation,omitempty"`
	Path       string `json:"path,omitempty"`
	TokenHMAC  string `json:"token_hmac,omitempty"`
	RemoteAddr string `json:"remote_addr,omitempty"`
	StatusCode int    `json:"status_code,omitempty"`
}

// FileDevice appends newline-delimited JSON entries to a file.
type FileDevice struct {
	mu      sync.Mutex
	f       *os.File
	hmacKey []byte
}

// NewFileDevice opens (or creates) path for appending and generates a per-device
// HMAC key used to hash tokens. The key lives for the process lifetime; a
// persisted salt for cross-restart correlation is a future extension.
func NewFileDevice(path string) (*FileDevice, error) {
	// path is an operator-provided configuration value (a server flag), not
	// attacker-controlled input.
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600) //nolint:gosec // G304: operator-configured audit log path
	if err != nil {
		return nil, fmt.Errorf("audit: open %q: %w", path, err)
	}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("audit: hmac key: %w", err)
	}
	return &FileDevice{f: f, hmacKey: key}, nil
}

// Log writes one entry as a JSON line, HMACing the client token.
func (d *FileDevice) Log(_ context.Context, e *Entry) error {
	line := logLine{
		Time:       e.Time.UTC().Format(time.RFC3339Nano),
		Type:       e.Type,
		Operation:  e.Operation,
		Path:       e.Path,
		RemoteAddr: e.RemoteAddr,
		StatusCode: e.StatusCode,
	}
	if e.ClientToken != "" {
		line.TokenHMAC = d.hmacToken(e.ClientToken)
	}
	data, err := json.Marshal(line)
	if err != nil {
		return fmt.Errorf("audit: marshal: %w", err)
	}
	data = append(data, '\n')

	d.mu.Lock()
	defer d.mu.Unlock()
	if _, err := d.f.Write(data); err != nil {
		return fmt.Errorf("audit: write: %w", err)
	}
	return nil
}

// Close closes the underlying file.
func (d *FileDevice) Close() error { return d.f.Close() }

func (d *FileDevice) hmacToken(token string) string {
	mac := hmac.New(sha256.New, d.hmacKey)
	_, _ = mac.Write([]byte(token))
	return hex.EncodeToString(mac.Sum(nil))
}

// Broker fans an entry out to every configured device. It is safe for concurrent
// use (devices must be too).
type Broker struct {
	devices []Device
	now     func() time.Time
}

// NewBroker returns a broker over the given devices.
func NewBroker(devices ...Device) *Broker {
	return &Broker{devices: devices, now: func() time.Time { return time.Now().UTC() }}
}

// LogRequest records a request entry. It is fail-closed: if any device errors,
// the error is returned and the request must be refused.
func (b *Broker) LogRequest(ctx context.Context, e *Entry) error {
	e.Type = "request"
	return b.log(ctx, e)
}

// LogResponse records a response entry.
func (b *Broker) LogResponse(ctx context.Context, e *Entry) error {
	e.Type = "response"
	return b.log(ctx, e)
}

func (b *Broker) log(ctx context.Context, e *Entry) error {
	if e.Time.IsZero() {
		e.Time = b.now()
	}
	for _, d := range b.devices {
		if err := d.Log(ctx, e); err != nil {
			return err
		}
	}
	return nil
}

// Close closes every device, returning the first error.
func (b *Broker) Close() error {
	var firstErr error
	for _, d := range b.devices {
		if err := d.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}
