package raft

import (
	"encoding/json"
	"errors"
	"fmt"
)

// commandVersion is the version of the log-entry encoding this build proposes
// and understands. A node refuses any other version rather than guess: skipping
// an entry it cannot interpret would silently fork its state.
const commandVersion = 1

type op string

const (
	opPut    op = "put"
	opDelete op = "delete"
	// Join-token lifecycle (jointoken.go). Burn is a single committed step so
	// a token cannot be spent twice.
	opTokenMint op = "token-mint"
	opTokenBurn op = "token-burn"
	// opTxn is reserved for conditional multi-key transactions
	// (docs/design/raft-storage.md "CAS and transactions"). It is never
	// proposed, and a node that meets one refuses it.
)

// command is one replicated state change. It is the payload of a Raft log entry.
type command struct {
	Version int    `json:"v"`
	Op      op     `json:"op"`
	Key     string `json:"key"`
	Value   []byte `json:"value,omitempty"`
	// Now is the proposer's clock (unix nanos) for token ops; the FSM has none.
	Now int64 `json:"now,omitempty"`
}

func (c command) encode() ([]byte, error) {
	c.Version = commandVersion
	return json.Marshal(c)
}

// errUnknownCommand is returned for a log entry this build cannot apply.
var errUnknownCommand = errors.New("raft: unknown command")

func decodeCommand(data []byte) (command, error) {
	var c command
	if err := json.Unmarshal(data, &c); err != nil {
		return command{}, fmt.Errorf("%w: decode: %v", errUnknownCommand, err)
	}
	if c.Version != commandVersion {
		return command{}, fmt.Errorf("%w: version %d (this build speaks %d)", errUnknownCommand, c.Version, commandVersion)
	}
	switch c.Op {
	case opPut, opDelete, opTokenMint, opTokenBurn:
	default:
		return command{}, fmt.Errorf("%w: op %q", errUnknownCommand, c.Op)
	}
	return c, nil
}
