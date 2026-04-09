package api

import (
	"database/sql"
	"path/filepath"
	"testing"
	"time"

	"github.com/ssh-proxy-core/ssh-proxy-core/internal/models"
)

func TestCleanedDatabaseURLs(t *testing.T) {
	got := cleanedDatabaseURLs([]string{
		" postgres://writer , postgres://reader-1\npostgres://reader-2 ",
		"postgres://reader-1",
		"",
	})
	want := []string{
		"postgres://writer",
		"postgres://reader-1",
		"postgres://reader-2",
	}
	if len(got) != len(want) {
		t.Fatalf("cleanedDatabaseURLs length = %d, want %d (%v)", len(got), len(want), got)
	}
	for index := range want {
		if got[index] != want[index] {
			t.Fatalf("cleanedDatabaseURLs[%d] = %q, want %q", index, got[index], want[index])
		}
	}
}

func TestSQLDBClusterReadDBPrefersWriterAfterWrite(t *testing.T) {
	writer := &sql.DB{}
	readerA := &sql.DB{}
	readerB := &sql.DB{}
	cluster := &sqlDBCluster{
		writer:               writer,
		readers:              []*sql.DB{readerA, readerB},
		readAfterWriteWindow: 40 * time.Millisecond,
	}

	if got := cluster.readDB(); got != readerA {
		t.Fatalf("first readDB() = %p, want readerA %p", got, readerA)
	}
	if got := cluster.readDB(); got != readerB {
		t.Fatalf("second readDB() = %p, want readerB %p", got, readerB)
	}

	cluster.markWriteObserved()
	if got := cluster.readDB(); got != writer {
		t.Fatalf("readDB() after write = %p, want writer %p", got, writer)
	}

	time.Sleep(60 * time.Millisecond)
	if got := cluster.readDB(); got != readerA {
		t.Fatalf("readDB() after grace = %p, want readerA %p", got, readerA)
	}
}

func TestSQLStorageReadReplicaFallsBackToWriterForRecentWrites(t *testing.T) {
	tempDir := t.TempDir()
	writerPath := filepath.Join(tempDir, "writer.db")
	readerPath := filepath.Join(tempDir, "reader.db")

	readerStore, err := newSQLStorage("sqlite", readerPath)
	if err != nil {
		t.Fatalf("newSQLStorage(reader sqlite) error = %v", err)
	}
	_ = readerStore.Close()

	store, err := newSQLStorageWithOptions("sqlite", writerPath, []string{readerPath}, sqlPoolSettings{
		MaxOpenConns:         1,
		MaxIdleConns:         1,
		ReadAfterWriteWindow: 50 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("newSQLStorageWithOptions(sqlite replicas) error = %v", err)
	}
	defer func() {
		_ = store.Close()
	}()

	if err := store.CreateUser(models.User{
		Username: "alice",
		Role:     "admin",
		Enabled:  true,
	}); err != nil {
		t.Fatalf("CreateUser() error = %v", err)
	}

	user, ok, err := store.GetUser("alice")
	if err != nil {
		t.Fatalf("GetUser(immediate) error = %v", err)
	}
	if !ok || user.Username != "alice" {
		t.Fatalf("GetUser(immediate) = %#v, %v; want alice, true", user, ok)
	}

	time.Sleep(80 * time.Millisecond)

	_, ok, err = store.GetUser("alice")
	if err != nil {
		t.Fatalf("GetUser(after grace) error = %v", err)
	}
	if ok {
		t.Fatalf("GetUser(after grace) unexpectedly hit writer instead of stale replica")
	}
}
