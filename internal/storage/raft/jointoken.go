package raft

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"
)

// DefaultJoinTokenTTL is the lifetime of a join token minted with ttl <= 0
// (docs/design/raft-storage.md "Join").
const DefaultJoinTokenTTL = 15 * time.Minute

// Join-token errors, returned by [Backend.RedeemJoinToken]. They are
// application results, not failures of the state machine.
var (
	ErrTokenInvalid = errors.New("raft: join token invalid")
	ErrTokenExpired = errors.New("raft: join token expired")
	ErrTokenUsed    = errors.New("raft: join token already used")
)

const (
	tokenPrefix = "raft-internal/join-token/"
	tokenScheme = "ubxj."

	tokenFresh byte = 0
	tokenSpent byte = 1
)

// tokenRecord is value = state(1) || expiry unix-nanos(8, big-endian).
func encodeTokenRecord(state byte, expiry int64) []byte {
	var buf bytes.Buffer
	buf.WriteByte(state)
	_ = binary.Write(&buf, binary.BigEndian, expiry) // bytes.Buffer cannot fail
	return buf.Bytes()
}

func decodeTokenRecord(b []byte) (state byte, expiry int64, ok bool) {
	if len(b) != 9 {
		return 0, 0, false
	}
	if err := binary.Read(bytes.NewReader(b[1:]), binary.BigEndian, &expiry); err != nil {
		return 0, 0, false
	}
	return b[0], expiry, true
}

func tokenKey(token string) (string, bool) {
	raw, ok := strings.CutPrefix(token, tokenScheme)
	if !ok {
		return "", false
	}
	secret, err := base64.RawURLEncoding.Strict().DecodeString(raw) // canonical only: no malleable aliases of a token
	if err != nil || len(secret) != 32 {
		return "", false
	}
	h := sha256.Sum256(secret)
	return tokenPrefix + hex.EncodeToString(h[:]), true
}

// MintJoinToken issues a single-use token valid for ttl (default
// [DefaultJoinTokenTTL]). Only its SHA-256 is replicated; the token itself is
// returned once and cannot be recovered. It must run on the leader.
func (b *Backend) MintJoinToken(ctx context.Context, ttl time.Duration) (token string, expires time.Time, err error) {
	if ttl <= 0 {
		ttl = DefaultJoinTokenTTL
	}
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return "", time.Time{}, fmt.Errorf("raft: mint join token: %w", err)
	}
	token = tokenScheme + base64.RawURLEncoding.EncodeToString(secret)
	key, _ := tokenKey(token)
	now := time.Now()
	expires = now.Add(ttl)
	// Now travels in the command: the FSM must be deterministic and cannot
	// read a clock, and it uses it to prune records long expired.
	c := command{Op: opTokenMint, Key: key, Value: encodeTokenRecord(tokenFresh, expires.UnixNano()), Now: now.UnixNano()}
	if err := b.propose(ctx, c); err != nil {
		return "", time.Time{}, err
	}
	return token, expires, nil
}

// RedeemJoinToken verifies token and burns it in one committed step, so two
// redemptions (even racing across a leader change) cannot both succeed. It
// returns [ErrTokenInvalid], [ErrTokenExpired] or [ErrTokenUsed].
func (b *Backend) RedeemJoinToken(ctx context.Context, token string) error {
	key, ok := tokenKey(token)
	if !ok {
		return ErrTokenInvalid
	}
	return b.propose(ctx, command{Op: opTokenBurn, Key: key, Now: time.Now().UnixNano()})
}

// JoinNode is the leader side of a join: it burns token, then adds the node as
// a non-voter. The node is promoted with [Backend.AddVoter] once caught up.
func (b *Backend) JoinNode(ctx context.Context, token, id, addr string) error {
	if id == "" || addr == "" {
		return errors.New("raft: join requires node id and address")
	}
	if err := b.RedeemJoinToken(ctx, token); err != nil {
		return err
	}
	return b.AddNonvoter(id, addr)
}
