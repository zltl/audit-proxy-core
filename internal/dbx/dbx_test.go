package dbx

import (
	"database/sql"
	"path/filepath"
	"strings"
	"testing"
)

func openTestDB(t *testing.T) (*sql.DB, Dialect) {
	t.Helper()
	db, dialect, err := Open("sqlite", filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db, dialect
}

func TestDialectForDriver(t *testing.T) {
	cases := map[string]Dialect{
		"pgx": Postgres, "postgres": Postgres, "postgresql": Postgres,
		"sqlite": SQLite, "sqlite3": SQLite, " SQLite ": SQLite,
	}
	for driver, want := range cases {
		got, err := DialectForDriver(driver)
		if err != nil {
			t.Errorf("DialectForDriver(%q): %v", driver, err)
			continue
		}
		if got != want {
			t.Errorf("DialectForDriver(%q) = %v, want %v", driver, got, want)
		}
	}
	if _, err := DialectForDriver("mysql"); err == nil {
		t.Error("an unsupported driver should be rejected rather than defaulted")
	}
}

func TestBindPlaceholders(t *testing.T) {
	if got := Bind(Postgres, 3); got != "$3" {
		t.Errorf("Bind(Postgres, 3) = %q", got)
	}
	if got := Bind(SQLite, 3); got != "?" {
		t.Errorf("Bind(SQLite, 3) = %q", got)
	}
	if got := Binds(Postgres, 3); got != "$1, $2, $3" {
		t.Errorf("Binds(Postgres, 3) = %q", got)
	}
	if got := Binds(SQLite, 3); got != "?, ?, ?" {
		t.Errorf("Binds(SQLite, 3) = %q", got)
	}
	if got := Binds(SQLite, 0); got != "" {
		t.Errorf("Binds(_, 0) = %q, want empty", got)
	}
}

func TestMigrateAppliesOnlyNewVersions(t *testing.T) {
	db, dialect := openTestDB(t)

	first := []Migration{
		{Version: 1, Statements: []string{`CREATE TABLE t1 (id TEXT PRIMARY KEY);`}},
	}
	if err := Migrate(db, dialect, "example", first); err != nil {
		t.Fatalf("Migrate v1: %v", err)
	}
	if v, _ := SchemaVersion(db, dialect, "example"); v != 1 {
		t.Fatalf("version = %d, want 1", v)
	}

	// Re-running the same set must be a no-op rather than replaying the DDL,
	// which would fail on the second CREATE.
	if err := Migrate(db, dialect, "example", first); err != nil {
		t.Fatalf("re-running an applied migration should be a no-op: %v", err)
	}

	second := append(first, Migration{
		Version:    2,
		Statements: []string{`ALTER TABLE t1 ADD COLUMN name TEXT NOT NULL DEFAULT '';`},
	})
	if err := Migrate(db, dialect, "example", second); err != nil {
		t.Fatalf("Migrate v2: %v", err)
	}
	if v, _ := SchemaVersion(db, dialect, "example"); v != 2 {
		t.Fatalf("version = %d, want 2", v)
	}
	if _, err := db.Exec(`INSERT INTO t1(id, name) VALUES ('a', 'b')`); err != nil {
		t.Fatalf("the v2 column was not added: %v", err)
	}
}

func TestMigrateIsAtomicPerVersion(t *testing.T) {
	db, dialect := openTestDB(t)

	broken := []Migration{{
		Version: 1,
		Statements: []string{
			`CREATE TABLE good (id TEXT PRIMARY KEY);`,
			`THIS IS NOT SQL;`,
		},
	}}
	err := Migrate(db, dialect, "example", broken)
	if err == nil {
		t.Fatal("a migration with an invalid statement should fail")
	}
	if !strings.Contains(err.Error(), "example migration 1") {
		t.Errorf("the error should identify the component and version, got: %v", err)
	}

	// The version must not advance, and the partial DDL must be rolled back, so
	// that a corrected migration can be applied cleanly on the next start.
	if v, _ := SchemaVersion(db, dialect, "example"); v != 0 {
		t.Fatalf("version advanced to %d despite a failed migration", v)
	}
	if _, err := db.Exec(`INSERT INTO good(id) VALUES ('a')`); err == nil {
		t.Fatal("the table created before the failing statement was not rolled back")
	}
}

func TestMigrateComponentsAreIndependent(t *testing.T) {
	db, dialect := openTestDB(t)

	if err := Migrate(db, dialect, "alpha", []Migration{
		{Version: 1, Statements: []string{`CREATE TABLE alpha_t (id TEXT);`}},
	}); err != nil {
		t.Fatalf("Migrate alpha: %v", err)
	}
	if err := Migrate(db, dialect, "beta", []Migration{
		{Version: 1, Statements: []string{`CREATE TABLE beta_t (id TEXT);`}},
		{Version: 2, Statements: []string{`CREATE TABLE beta_t2 (id TEXT);`}},
	}); err != nil {
		t.Fatalf("Migrate beta: %v", err)
	}

	if v, _ := SchemaVersion(db, dialect, "alpha"); v != 1 {
		t.Errorf("alpha version = %d, want 1", v)
	}
	if v, _ := SchemaVersion(db, dialect, "beta"); v != 2 {
		t.Errorf("beta version = %d, want 2", v)
	}
	if v, _ := SchemaVersion(db, dialect, "never-migrated"); v != 0 {
		t.Errorf("an unmigrated component should report 0, got %d", v)
	}
}

func TestMigrateSkipsBlankStatements(t *testing.T) {
	db, dialect := openTestDB(t)
	if err := Migrate(db, dialect, "example", []Migration{
		{Version: 1, Statements: []string{"", "   ", `CREATE TABLE t (id TEXT);`, "\n"}},
	}); err != nil {
		t.Fatalf("blank statements should be skipped: %v", err)
	}
}

func TestUnixConversionsHandleZeroTime(t *testing.T) {
	if got := Unix(FromUnix(0)); got != 0 {
		t.Errorf("zero time round trip = %d, want 0", got)
	}
	if !FromUnix(0).IsZero() {
		t.Error("FromUnix(0) should be the zero time, not the epoch")
	}
	if !FromUnix(-5).IsZero() {
		t.Error("a negative timestamp should be treated as unset")
	}
	const sec int64 = 1767225600
	if got := Unix(FromUnix(sec)); got != sec {
		t.Errorf("round trip = %d, want %d", got, sec)
	}
}

func TestOpenRejectsUnknownDriver(t *testing.T) {
	if _, _, err := Open("mysql", "dsn"); err == nil {
		t.Fatal("Open should reject an unsupported driver")
	}
}
