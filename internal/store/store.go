package store

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/ssh-proxy-core/ssh-proxy-core/internal/dbx"
	"github.com/ssh-proxy-core/ssh-proxy-core/internal/secrets"
)

// Sentinel errors callers are expected to branch on.
var (
	ErrNotFound = errors.New("store: not found")
	ErrConflict = errors.New("store: already exists")
)

// Store is the handle onto the data-plane database.
type Store struct {
	db      *sql.DB
	dialect dbx.Dialect
	// ownsDB records whether Close should shut the pool down; a Store built
	// around a borrowed handle must not.
	ownsDB bool
	now    func() time.Time
	// sealer encrypts credential material. When absent the secret APIs refuse
	// rather than falling back to storing plaintext.
	sealer *secrets.Sealer
}

// Open connects to the database, applies migrations, and seeds built-in roles.
func Open(driver, dsn string) (*Store, error) {
	db, dialect, err := dbx.Open(driver, dsn)
	if err != nil {
		return nil, err
	}
	s, err := newStore(db, dialect, true)
	if err != nil {
		_ = db.Close()
		return nil, err
	}
	return s, nil
}

// Attach builds a Store around an existing pool, for callers that already
// manage connections and want the two to share a transaction-visible view.
func Attach(db *sql.DB, dialect dbx.Dialect) (*Store, error) {
	return newStore(db, dialect, false)
}

func newStore(db *sql.DB, dialect dbx.Dialect, ownsDB bool) (*Store, error) {
	s := &Store{db: db, dialect: dialect, ownsDB: ownsDB, now: func() time.Time { return time.Now().UTC() }}
	if err := dbx.Migrate(db, dialect, component, migrations); err != nil {
		return nil, err
	}
	if err := s.seedBuiltinRoles(); err != nil {
		return nil, err
	}
	return s, nil
}

// Close releases the pool when this Store owns it.
func (s *Store) Close() error {
	if s == nil || s.db == nil || !s.ownsDB {
		return nil
	}
	return s.db.Close()
}

// DB exposes the underlying handle for callers that need to share it.
func (s *Store) DB() *sql.DB { return s.db }

// Dialect reports the SQL flavour in use.
func (s *Store) Dialect() dbx.Dialect { return s.dialect }

// SchemaVersion returns the applied migration version.
func (s *Store) SchemaVersion() (int, error) {
	return dbx.SchemaVersion(s.db, s.dialect, component)
}

// SetClock overrides the time source. Tests use it to make expiry deterministic.
func (s *Store) SetClock(now func() time.Time) {
	if now != nil {
		s.now = now
	}
}

func (s *Store) bind(i int) string      { return dbx.Bind(s.dialect, i) }
func (s *Store) binds(n int) string     { return dbx.Binds(s.dialect, n) }
func (s *Store) clock() time.Time       { return s.now() }
func (s *Store) unix(t time.Time) int64 { return dbx.Unix(t) }

func fromUnix(sec int64) time.Time { return dbx.FromUnix(sec) }

// BuiltinRoles are always present so that authorization has a stable vocabulary
// even in a freshly initialised database.
var BuiltinRoles = []Role{
	{Name: "admin", Description: "Full administrative control", Builtin: true},
	{Name: "operator", Description: "Day-to-day operations, no policy changes", Builtin: true},
	{Name: "viewer", Description: "Read-only access", Builtin: true},
}

func (s *Store) seedBuiltinRoles() error {
	query := fmt.Sprintf(`
		INSERT INTO dp_roles(name, description, builtin, created_at)
		VALUES (%s)
		ON CONFLICT(name) DO NOTHING
	`, s.binds(4))
	now := s.unix(s.clock())
	for _, role := range BuiltinRoles {
		if _, err := s.db.Exec(query, role.Name, role.Description, true, now); err != nil {
			return fmt.Errorf("store: seed role %q: %w", role.Name, err)
		}
	}
	return nil
}

// NewID returns a random 128-bit identifier with a type prefix, which keeps
// identifiers self-describing in logs and audit records.
func NewID(prefix string) string {
	var buf [16]byte
	if _, err := rand.Read(buf[:]); err != nil {
		// crypto/rand failing means the process cannot make security decisions
		// at all; there is no safe fallback.
		panic("store: crypto/rand unavailable: " + err.Error())
	}
	id := hex.EncodeToString(buf[:])
	if prefix == "" {
		return id
	}
	return prefix + "-" + id
}

// --------------------------------------------------------------------------
// JSON column helpers
// --------------------------------------------------------------------------

func encodeJSON(v interface{}) (string, error) {
	if v == nil {
		return "null", nil
	}
	raw, err := json.Marshal(v)
	if err != nil {
		return "", fmt.Errorf("store: encode json column: %w", err)
	}
	return string(raw), nil
}

func encodeStringSlice(values []string) string {
	if len(values) == 0 {
		return "[]"
	}
	raw, err := json.Marshal(values)
	if err != nil {
		return "[]"
	}
	return string(raw)
}

func decodeStringSlice(raw string) []string {
	raw = strings.TrimSpace(raw)
	if raw == "" || raw == "null" {
		return nil
	}
	var values []string
	if err := json.Unmarshal([]byte(raw), &values); err != nil {
		return nil
	}
	return values
}

func encodeStringMap(values map[string]string) string {
	if len(values) == 0 {
		return "{}"
	}
	raw, err := json.Marshal(values)
	if err != nil {
		return "{}"
	}
	return string(raw)
}

func decodeStringMap(raw string) map[string]string {
	raw = strings.TrimSpace(raw)
	if raw == "" || raw == "null" {
		return nil
	}
	var values map[string]string
	if err := json.Unmarshal([]byte(raw), &values); err != nil {
		return nil
	}
	return values
}

func decodeTimeWindows(raw string) []TimeWindow {
	raw = strings.TrimSpace(raw)
	if raw == "" || raw == "null" || raw == "[]" {
		return nil
	}
	var windows []TimeWindow
	if err := json.Unmarshal([]byte(raw), &windows); err != nil {
		return nil
	}
	return windows
}

// rowsAffected normalises "the statement matched nothing" into ErrNotFound.
func rowsAffected(result sql.Result) (int64, error) {
	if result == nil {
		return 0, nil
	}
	return result.RowsAffected()
}

func requireAffected(result sql.Result, err error) error {
	if err != nil {
		return err
	}
	n, err := rowsAffected(result)
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}
