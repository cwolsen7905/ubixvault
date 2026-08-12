package storage

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sort"
	"time"

	_ "github.com/go-sql-driver/mysql" // MySQL/MariaDB driver (the project's sole dependency, D-010)
)

// MySQL/MariaDB backend schema. Values are opaque barrier ciphertext, so the
// database never sees plaintext (docs/design/sql-storage-backend.md, ADR D-014).
const (
	mysqlKVTable       = "ubixvault_kv"
	mysqlSchemaTable   = "ubixvault_schema"
	mysqlSchemaVersion = 1
	// mysqlMaxKeyLen bounds a key to the VARBINARY(768) primary key. Keys are
	// paths, so this is generous; longer keys are rejected rather than truncated.
	mysqlMaxKeyLen = 768
)

// MySQLBackend is a [Backend] over a MySQL/MariaDB database. It stores each entry
// as one row in a VARBINARY-keyed table — VARBINARY (not VARCHAR) so keys compare
// byte-for-byte, matching the file and in-memory backends rather than MySQL's
// case-insensitive default collation.
//
// Exactly one active vault process may write to a given database: barrier, lease,
// and unseal state live in memory, so this provides durable, replaceable-node
// storage, not multi-writer HA (ADR D-014).
type MySQLBackend struct {
	db *sql.DB
}

// NewMySQLBackend opens a connection pool to the server described by dsn (a
// go-sql-driver DSN), verifies connectivity, and ensures the schema exists.
func NewMySQLBackend(dsn string) (*MySQLBackend, error) {
	db, err := sql.Open("mysql", dsn)
	if err != nil {
		return nil, fmt.Errorf("storage: open mysql: %w", err)
	}
	db.SetMaxOpenConns(10)
	db.SetMaxIdleConns(5)
	db.SetConnMaxLifetime(3 * time.Minute)

	b := &MySQLBackend{db: db}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("storage: connect mysql: %w", err)
	}
	if err := b.ensureSchema(ctx); err != nil {
		_ = db.Close()
		return nil, err
	}
	return b, nil
}

func (b *MySQLBackend) ensureSchema(ctx context.Context) error {
	stmts := []string{
		"CREATE TABLE IF NOT EXISTS " + mysqlKVTable + " (" +
			"vault_key VARBINARY(768) NOT NULL, " +
			"value LONGBLOB NOT NULL, " +
			"PRIMARY KEY (vault_key)) ENGINE=InnoDB ROW_FORMAT=DYNAMIC",
		"CREATE TABLE IF NOT EXISTS " + mysqlSchemaTable + " (" +
			"version INT NOT NULL, PRIMARY KEY (version))",
	}
	for _, s := range stmts {
		if _, err := b.db.ExecContext(ctx, s); err != nil {
			return fmt.Errorf("storage: ensure schema: %w", err)
		}
	}
	if _, err := b.db.ExecContext(ctx,
		"INSERT IGNORE INTO "+mysqlSchemaTable+" (version) VALUES (?)", mysqlSchemaVersion); err != nil {
		return fmt.Errorf("storage: record schema version: %w", err)
	}
	return nil
}

// Close releases the connection pool.
func (b *MySQLBackend) Close() error { return b.db.Close() }

func (b *MySQLBackend) checkKey(key string) error {
	if err := ValidateKey(key); err != nil {
		return err
	}
	if len(key) > mysqlMaxKeyLen {
		return fmt.Errorf("%w: key exceeds %d bytes", ErrInvalidKey, mysqlMaxKeyLen)
	}
	return nil
}

// Get returns the entry at key, or (nil, nil) if it does not exist.
func (b *MySQLBackend) Get(ctx context.Context, key string) (*Entry, error) {
	if err := b.checkKey(key); err != nil {
		return nil, err
	}
	var value []byte
	err := b.db.QueryRowContext(ctx,
		"SELECT value FROM "+mysqlKVTable+" WHERE vault_key = ?", []byte(key)).Scan(&value)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("storage: mysql get: %w", err)
	}
	return &Entry{Key: key, Value: value}, nil
}

// Put stores entry, overwriting any existing value at entry.Key.
func (b *MySQLBackend) Put(ctx context.Context, entry *Entry) error {
	if err := b.checkKey(entry.Key); err != nil {
		return err
	}
	_, err := b.db.ExecContext(ctx,
		"INSERT INTO "+mysqlKVTable+" (vault_key, value) VALUES (?, ?) "+
			"ON DUPLICATE KEY UPDATE value = VALUES(value)", []byte(entry.Key), entry.Value)
	if err != nil {
		return fmt.Errorf("storage: mysql put: %w", err)
	}
	return nil
}

// Delete removes the value at key. It is a no-op if key does not exist.
func (b *MySQLBackend) Delete(ctx context.Context, key string) error {
	if err := b.checkKey(key); err != nil {
		return err
	}
	if _, err := b.db.ExecContext(ctx,
		"DELETE FROM "+mysqlKVTable+" WHERE vault_key = ?", []byte(key)); err != nil {
		return fmt.Errorf("storage: mysql delete: %w", err)
	}
	return nil
}

// List returns the immediate children under prefix. It range-scans the primary
// key for rows sharing the prefix, then reduces them to immediate children with
// the same logic the file and in-memory backends use, so the semantics are
// identical.
func (b *MySQLBackend) List(ctx context.Context, prefix string) ([]string, error) {
	if err := validatePrefix(prefix); err != nil {
		return nil, err
	}

	var rows *sql.Rows
	var err error
	if prefix == "" {
		rows, err = b.db.QueryContext(ctx, "SELECT vault_key FROM "+mysqlKVTable)
	} else if hi := prefixSuccessor([]byte(prefix)); hi != nil {
		rows, err = b.db.QueryContext(ctx,
			"SELECT vault_key FROM "+mysqlKVTable+" WHERE vault_key >= ? AND vault_key < ?", []byte(prefix), hi)
	} else {
		rows, err = b.db.QueryContext(ctx,
			"SELECT vault_key FROM "+mysqlKVTable+" WHERE vault_key >= ?", []byte(prefix))
	}
	if err != nil {
		return nil, fmt.Errorf("storage: mysql list: %w", err)
	}
	defer func() { _ = rows.Close() }()

	seen := make(map[string]struct{})
	children := make([]string, 0) // non-nil: an empty result must DeepEqual []string{}, not nil
	for rows.Next() {
		var kb []byte
		if err := rows.Scan(&kb); err != nil {
			return nil, fmt.Errorf("storage: mysql list scan: %w", err)
		}
		child, ok := childUnder(prefix, string(kb))
		if !ok {
			continue
		}
		if _, dup := seen[child]; dup {
			continue
		}
		seen[child] = struct{}{}
		children = append(children, child)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("storage: mysql list rows: %w", err)
	}
	sort.Strings(children)
	return children, nil
}

// prefixSuccessor returns the smallest byte string greater than every string
// with prefix p — p with its last non-0xFF byte incremented and the rest
// truncated. It returns nil when p is all 0xFF bytes (no finite upper bound).
func prefixSuccessor(p []byte) []byte {
	s := append([]byte(nil), p...)
	for i := len(s) - 1; i >= 0; i-- {
		if s[i] != 0xFF {
			s[i]++
			return s[:i+1]
		}
	}
	return nil
}
