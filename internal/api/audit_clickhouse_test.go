package api

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/zltl/audit-proxy-core/internal/models"
)

func TestAuditStoreUsesClickHouse(t *testing.T) {
	for _, name := range []string{"clickhouse", "ClickHouse", "  clickhouse  "} {
		if !auditStoreUsesClickHouse(name) {
			t.Errorf("auditStoreUsesClickHouse(%q) = false", name)
		}
	}
	for _, name := range []string{"", "file", "postgres", "elasticsearch", "clickhous"} {
		if auditStoreUsesClickHouse(name) {
			t.Errorf("auditStoreUsesClickHouse(%q) = true", name)
		}
	}
	// A ClickHouse backend must not also be treated as SQL or search, or two
	// stores would be constructed for the same events.
	if auditStoreUsesSQL("clickhouse") || auditStoreUsesSearch("clickhouse") {
		t.Fatal("clickhouse should be dispatched to exactly one backend")
	}
}

func TestClickHouseOptionsFromDSN(t *testing.T) {
	cfg := &Config{}

	t.Run("full dsn", func(t *testing.T) {
		options, err := clickHouseOptions("clickhouse://analytics:pw@ch.internal:9000/audit", cfg)
		if err != nil {
			t.Fatalf("clickHouseOptions: %v", err)
		}
		if options.Auth.Database != "audit" {
			t.Errorf("database = %q", options.Auth.Database)
		}
		if options.Auth.Username != "analytics" {
			t.Errorf("username = %q", options.Auth.Username)
		}
		if options.Compression == nil {
			t.Error("compression should be enabled; audit rows are highly repetitive")
		}
	})

	t.Run("bare host and port", func(t *testing.T) {
		// Configuring a plain address is a reasonable thing to do and should
		// not be rejected for missing a scheme.
		options, err := clickHouseOptions("ch.internal:9000", cfg)
		if err != nil {
			t.Fatalf("clickHouseOptions: %v", err)
		}
		if options.Auth.Database != "default" {
			t.Errorf("database = %q, want the default", options.Auth.Database)
		}
	})

	t.Run("credentials from config override the dsn", func(t *testing.T) {
		// Keeping the password out of the DSN means it does not end up in
		// config exports, diffs, or process listings.
		withCreds := &Config{AuditStoreUsername: "svc", AuditStorePassword: "from-config"}
		options, err := clickHouseOptions("clickhouse://ch.internal:9000/audit", withCreds)
		if err != nil {
			t.Fatalf("clickHouseOptions: %v", err)
		}
		if options.Auth.Username != "svc" || options.Auth.Password != "from-config" {
			t.Fatalf("auth = %q/%q", options.Auth.Username, options.Auth.Password)
		}
	})

	t.Run("insecure tls is opt in", func(t *testing.T) {
		strict, err := clickHouseOptions("clickhouse://ch.internal:9440/audit?secure=true", cfg)
		if err != nil {
			t.Fatalf("clickHouseOptions: %v", err)
		}
		if strict.TLS != nil && strict.TLS.InsecureSkipVerify {
			t.Error("certificate verification was disabled without being asked for")
		}

		relaxed, err := clickHouseOptions("clickhouse://ch.internal:9440/audit?secure=true",
			&Config{AuditStoreInsecureTLS: true})
		if err != nil {
			t.Fatalf("clickHouseOptions: %v", err)
		}
		if relaxed.TLS == nil || !relaxed.TLS.InsecureSkipVerify {
			t.Error("audit_store_insecure_tls was not honoured")
		}
	})

	t.Run("unusable address", func(t *testing.T) {
		if _, err := clickHouseOptions("://not a dsn", cfg); err == nil {
			t.Fatal("an unparseable address should be reported")
		}
	})
}

func TestNewAuditClickHouseStoreRequiresAnAddress(t *testing.T) {
	if _, err := newAuditClickHouseStore(&Config{}); err == nil {
		t.Fatal("a ClickHouse store without an address should be refused at startup")
	} else if !strings.Contains(err.Error(), "audit_store_database_url") {
		t.Errorf("the error should name the missing setting, got %v", err)
	}
	if _, err := newAuditClickHouseStore(nil); err == nil {
		t.Fatal("a nil configuration should be refused")
	}
}

func TestRedactClickHouseDSN(t *testing.T) {
	redacted := redactClickHouseDSN("clickhouse://analytics:hunter2@ch.internal:9000/audit")
	if strings.Contains(redacted, "hunter2") {
		t.Fatalf("the password survived redaction: %s", redacted)
	}
	if !strings.Contains(redacted, "analytics") || !strings.Contains(redacted, "ch.internal") {
		t.Fatalf("redaction removed too much: %s", redacted)
	}
	// An address with no credentials should pass through unchanged.
	plain := "clickhouse://ch.internal:9000/audit"
	if got := redactClickHouseDSN(plain); got != plain {
		t.Fatalf("redactClickHouseDSN(%q) = %q", plain, got)
	}
}

// TestClickHouseIngestion exercises the store against a real server.
//
// It is skipped unless CLICKHOUSE_DSN points at one, because a column store is
// not something to fake: the parts worth testing here are the schema, the
// deduplication behaviour, and batching, none of which a stub would exercise.
func TestClickHouseIngestion(t *testing.T) {
	dsn := strings.TrimSpace(os.Getenv("CLICKHOUSE_DSN"))
	if dsn == "" {
		t.Skip("set CLICKHOUSE_DSN to run the ClickHouse integration test")
	}

	dir := t.TempDir()
	store, err := newAuditClickHouseStore(&Config{
		AuditStoreDatabaseURL: dsn,
		AuditRetentionDays:    7,
	})
	if err != nil {
		t.Fatalf("newAuditClickHouseStore: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	writeEvents := func(path string, events []models.AuditEvent) {
		t.Helper()
		var lines []string
		for _, event := range events {
			raw, err := json.Marshal(event)
			if err != nil {
				t.Fatalf("marshal event: %v", err)
			}
			lines = append(lines, string(raw))
		}
		if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
			t.Fatalf("write audit file: %v", err)
		}
	}

	now := time.Now().UTC().Truncate(time.Millisecond)
	path := filepath.Join(dir, "audit-test.jsonl")
	writeEvents(path, []models.AuditEvent{
		{ID: "ch-1", Timestamp: now, EventType: "session_start", Username: "alice", SourceIP: "10.0.0.1"},
		{ID: "ch-2", Timestamp: now.Add(time.Second), EventType: "command", Username: "alice", Details: "uptime"},
	})

	if err := store.SyncDir(dir); err != nil {
		t.Fatalf("SyncDir: %v", err)
	}
	events, err := store.ListEvents()
	if err != nil {
		t.Fatalf("ListEvents: %v", err)
	}
	if countEventIDs(events, "ch-1", "ch-2") != 2 {
		t.Fatalf("expected both events to be indexed, got %d", len(events))
	}

	// Re-syncing must not duplicate: offsets and inserts are not one atomic
	// operation, so replay has to be harmless.
	if err := store.SyncDir(dir); err != nil {
		t.Fatalf("second SyncDir: %v", err)
	}
	events, err = store.ListEvents()
	if err != nil {
		t.Fatalf("ListEvents: %v", err)
	}
	if got := countEventIDs(events, "ch-1"); got != 1 {
		t.Fatalf("event ch-1 appears %d times after a replay", got)
	}

	// Appending picks up from the recorded offset rather than re-reading.
	file, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatalf("open for append: %v", err)
	}
	appended, _ := json.Marshal(models.AuditEvent{
		ID: "ch-3", Timestamp: now.Add(2 * time.Second), EventType: "session_end", Username: "alice",
	})
	if _, err := file.Write(append(appended, '\n')); err != nil {
		t.Fatalf("append: %v", err)
	}
	_ = file.Close()

	if err := store.SyncDir(dir); err != nil {
		t.Fatalf("third SyncDir: %v", err)
	}
	events, err = store.ListEvents()
	if err != nil {
		t.Fatalf("ListEvents: %v", err)
	}
	if countEventIDs(events, "ch-3") != 1 {
		t.Fatal("the appended event was not ingested")
	}
}

func countEventIDs(events []models.AuditEvent, ids ...string) int {
	wanted := make(map[string]bool, len(ids))
	for _, id := range ids {
		wanted[id] = true
	}
	count := 0
	for _, event := range events {
		if wanted[event.ID] {
			count++
		}
	}
	return count
}
