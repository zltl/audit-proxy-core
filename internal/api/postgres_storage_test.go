package api

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ssh-proxy-core/ssh-proxy-core/internal/models"
)

func enableSQLitePostgresBackends(t *testing.T, api *API, useUsers, useConfig bool) {
	t.Helper()

	store, err := newSQLStorage("sqlite", filepath.Join(t.TempDir(), "postgres-backend.db"))
	if err != nil {
		t.Fatalf("newSQLStorage(sqlite) error = %v", err)
	}
	api.storageDB = store
	api.config.PostgresDatabaseURL = "sqlite-test"

	if useUsers {
		api.config.UserStoreBackend = "postgres"
		users, err := newUserStore(dataFilePath(api.config.DataDir, "users.json"), store, true)
		if err != nil {
			t.Fatalf("newUserStore(postgres) error = %v", err)
		}
		api.users = users
	}
	if useConfig {
		api.config.ConfigStoreBackend = "postgres"
		if err := api.bootstrapConfigStore(); err != nil {
			t.Fatalf("bootstrapConfigStore(postgres) error = %v", err)
		}
	}
}

func TestSQLStorageRoundTripsConfigAndUsers(t *testing.T) {
	store, err := newSQLStorage("sqlite", filepath.Join(t.TempDir(), "storage.db"))
	if err != nil {
		t.Fatalf("newSQLStorage(sqlite) error = %v", err)
	}
	defer func() { _ = store.Close() }()

	updatedAt := time.Unix(1700000000, 0).UTC()
	entry := &ConfigStoreEntry{
		Version:   "v1",
		ChangeID:  "chg-1",
		Requester: "admin",
		Source:    "node-1",
		UpdatedAt: updatedAt,
		Snapshot:  json.RawMessage(`{"listen_port":4444}`),
	}
	if err := store.SaveCurrentConfig(entry); err != nil {
		t.Fatalf("SaveCurrentConfig() error = %v", err)
	}
	current, err := store.LoadCurrentConfig()
	if err != nil {
		t.Fatalf("LoadCurrentConfig() error = %v", err)
	}
	if current == nil || current.Version != "v1" || string(current.Snapshot) != `{"listen_port":4444}` {
		t.Fatalf("LoadCurrentConfig() = %#v", current)
	}

	if err := store.SaveConfigVersion("v1", []byte(`{"listen_port":4444}`), updatedAt); err != nil {
		t.Fatalf("SaveConfigVersion() error = %v", err)
	}
	versionData, err := store.LoadConfigVersion("v1")
	if err != nil {
		t.Fatalf("LoadConfigVersion() error = %v", err)
	}
	if string(versionData) != `{"listen_port":4444}` {
		t.Fatalf("LoadConfigVersion() = %s", string(versionData))
	}
	versions, err := store.ListConfigVersions()
	if err != nil {
		t.Fatalf("ListConfigVersions() error = %v", err)
	}
	if len(versions) != 1 || versions[0]["version"] != "v1" {
		t.Fatalf("ListConfigVersions() = %#v", versions)
	}

	user := models.User{
		Username:   "alice",
		Role:       "admin",
		PassHash:   "hash",
		Enabled:    true,
		AllowedIPs: []string{"10.0.0.0/24"},
		CreatedAt:  updatedAt,
		UpdatedAt:  updatedAt,
	}
	if err := store.CreateUser(user); err != nil {
		t.Fatalf("CreateUser() error = %v", err)
	}
	fetched, ok, err := store.GetUser("alice")
	if err != nil {
		t.Fatalf("GetUser() error = %v", err)
	}
	if !ok || fetched.Username != "alice" || len(fetched.AllowedIPs) != 1 || fetched.AllowedIPs[0] != "10.0.0.0/24" {
		t.Fatalf("GetUser() = %#v, %v", fetched, ok)
	}
	fetched.Email = "alice@example.com"
	fetched.UpdatedAt = updatedAt.Add(time.Minute)
	if err := store.UpdateUser(fetched); err != nil {
		t.Fatalf("UpdateUser() error = %v", err)
	}
	users, err := store.ListUsers()
	if err != nil {
		t.Fatalf("ListUsers() error = %v", err)
	}
	if len(users) != 1 || users[0].Email != "alice@example.com" {
		t.Fatalf("ListUsers() = %#v", users)
	}
	if err := store.DeleteUser("alice"); err != nil {
		t.Fatalf("DeleteUser() error = %v", err)
	}
	_, ok, err = store.GetUser("alice")
	if err != nil {
		t.Fatalf("GetUser(after delete) error = %v", err)
	}
	if ok {
		t.Fatal("expected alice to be deleted")
	}
}

func TestCreateAndGetUserWithPostgresBackend(t *testing.T) {
	api, mux, _ := setupTestAPI(t)
	enableSQLitePostgresBackends(t, api, true, false)

	rr := doRequest(mux, "POST", "/api/v2/users", map[string]interface{}{
		"username":     "pguser",
		"display_name": "PG User",
		"email":        "pg@example.com",
		"password":     "securepassword123",
		"role":         "operator",
		"allowed_ips":  []string{"10.10.0.0/16"},
	})
	if rr.Code != 201 {
		t.Fatalf("expected 201, got %d: %s", rr.Code, rr.Body.String())
	}

	rr = doRequest(mux, "GET", "/api/v2/users/pguser", nil)
	if rr.Code != 200 {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
	resp := parseResponse(t, rr)
	data := resp.Data.(map[string]interface{})
	if data["username"] != "pguser" || data["role"] != "operator" {
		t.Fatalf("unexpected user payload: %#v", data)
	}
	if _, err := os.Stat(filepath.Join(api.config.DataDir, "users.json")); !os.IsNotExist(err) {
		t.Fatalf("expected postgres-backed user writes to avoid users.json, stat err = %v", err)
	}
}

func TestGetConfigFallsBackToPostgresCentralStoreWhenConfigFileMissing(t *testing.T) {
	api, mux, dp := setupTestAPI(t)
	dp.config = map[string]interface{}{"listen_port": 9999}
	enableSQLitePostgresBackends(t, api, false, true)

	err := api.storageDB.SaveCurrentConfig(&ConfigStoreEntry{
		Version:   "stored-v1",
		ChangeID:  "chg-1",
		Requester: "admin",
		Source:    "node-1",
		UpdatedAt: time.Now().UTC(),
		Snapshot:  json.RawMessage(`{"listen_port":4444}`),
	})
	if err != nil {
		t.Fatalf("SaveCurrentConfig() error = %v", err)
	}
	if err := os.Remove(api.config.ConfigFile); err != nil {
		t.Fatalf("Remove(config file) error = %v", err)
	}

	rr := doRequest(mux, "GET", "/api/v2/config", nil)
	if rr.Code != 200 {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
	resp := parseResponse(t, rr)
	data := resp.Data.(map[string]interface{})
	if data["listen_port"] != float64(4444) {
		t.Fatalf("expected listen_port 4444, got %#v", data["listen_port"])
	}
}

func TestBootstrapConfigStoreImportsVersionFilesIntoPostgres(t *testing.T) {
	api, _, _ := setupTestAPI(t)
	version := "20240102-150405.000000000"
	if err := os.MkdirAll(api.config.ConfigVerDir, 0o700); err != nil {
		t.Fatalf("MkdirAll(config versions) error = %v", err)
	}
	if err := os.WriteFile(filepath.Join(api.config.ConfigVerDir, version+".json"), []byte(`{"listen_port":3333}`), 0o600); err != nil {
		t.Fatalf("WriteFile(version) error = %v", err)
	}

	enableSQLitePostgresBackends(t, api, false, true)

	versions, err := api.listConfigVersions()
	if err != nil {
		t.Fatalf("listConfigVersions() error = %v", err)
	}
	if len(versions) == 0 || versions[0]["version"] != version {
		t.Fatalf("listConfigVersions() = %#v", versions)
	}
	data, err := api.loadConfigVersionSnapshot(version)
	if err != nil {
		t.Fatalf("loadConfigVersionSnapshot() error = %v", err)
	}
	if string(data) != `{"listen_port":3333}` {
		t.Fatalf("loadConfigVersionSnapshot() = %s", string(data))
	}
}
