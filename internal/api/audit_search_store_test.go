package api

import (
	"bufio"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
)

type fakeAuditSearchServer struct {
	t          *testing.T
	authHeader string

	mu      sync.Mutex
	indices map[string]map[string]auditSearchDocument
}

func newFakeAuditSearchServer(t *testing.T, authHeader string) (*fakeAuditSearchServer, *httptest.Server) {
	t.Helper()
	handler := &fakeAuditSearchServer{
		t:          t,
		authHeader: authHeader,
		indices:    map[string]map[string]auditSearchDocument{},
	}
	server := httptest.NewServer(http.HandlerFunc(handler.ServeHTTP))
	return handler, server
}

func (s *fakeAuditSearchServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if s.authHeader != "" && r.Header.Get("Authorization") != s.authHeader {
		http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
		return
	}

	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if len(parts) == 0 || parts[0] == "" {
		http.NotFound(w, r)
		return
	}
	index := parts[0]

	switch {
	case r.Method == http.MethodPut && len(parts) == 1:
		s.handleCreateIndex(w, index)
	case r.Method == http.MethodPost && len(parts) == 2 && parts[1] == "_bulk":
		s.handleBulk(w, r, index)
	case r.Method == http.MethodPost && len(parts) == 2 && parts[1] == "_search":
		s.handleSearch(w, r, index)
	default:
		http.NotFound(w, r)
	}
}

func (s *fakeAuditSearchServer) handleCreateIndex(w http.ResponseWriter, index string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.indices[index]; exists {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":{"type":"resource_already_exists_exception","reason":"index already exists"}}`))
		return
	}
	s.indices[index] = map[string]auditSearchDocument{}
	writeTestJSON(w, http.StatusOK, map[string]any{"acknowledged": true})
}

func (s *fakeAuditSearchServer) handleBulk(w http.ResponseWriter, r *http.Request, index string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.indices[index]; !exists {
		s.indices[index] = map[string]auditSearchDocument{}
	}

	reader := bufio.NewReader(r.Body)
	items := make([]map[string]map[string]any, 0)
	for {
		actionLine, err := reader.ReadBytes('\n')
		if err != nil && err != io.EOF {
			s.t.Fatalf("bulk read action error = %v", err)
		}
		actionLine = []byte(strings.TrimSpace(string(actionLine)))
		if len(actionLine) == 0 {
			break
		}

		sourceLine, sourceErr := reader.ReadBytes('\n')
		if sourceErr != nil && sourceErr != io.EOF {
			s.t.Fatalf("bulk read source error = %v", sourceErr)
		}

		var action map[string]map[string]string
		if unmarshalErr := json.Unmarshal(actionLine, &action); unmarshalErr != nil {
			s.t.Fatalf("bulk action decode error = %v", unmarshalErr)
		}
		var doc auditSearchDocument
		if unmarshalErr := json.Unmarshal(sourceLine, &doc); unmarshalErr != nil {
			s.t.Fatalf("bulk doc decode error = %v", unmarshalErr)
		}
		if doc.ID == "" {
			doc.ID = action["index"]["_id"]
		}
		s.indices[index][doc.ID] = doc
		items = append(items, map[string]map[string]any{
			"index": map[string]any{"status": 201},
		})

		if err == io.EOF || sourceErr == io.EOF {
			break
		}
	}

	writeTestJSON(w, http.StatusOK, map[string]any{
		"errors": false,
		"items":  items,
	})
}

func (s *fakeAuditSearchServer) handleSearch(w http.ResponseWriter, r *http.Request, index string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	docsByID, exists := s.indices[index]
	if !exists {
		http.Error(w, `{"error":"index_not_found_exception"}`, http.StatusNotFound)
		return
	}

	var query struct {
		Size        int           `json:"size"`
		SearchAfter []interface{} `json:"search_after"`
	}
	if err := json.NewDecoder(r.Body).Decode(&query); err != nil {
		s.t.Fatalf("search query decode error = %v", err)
	}
	if query.Size <= 0 {
		query.Size = auditSearchPageSize
	}

	docs := make([]auditSearchDocument, 0, len(docsByID))
	for _, doc := range docsByID {
		docs = append(docs, doc)
	}
	sort.Slice(docs, func(i, j int) bool {
		if docs[i].EventUnix == docs[j].EventUnix {
			return docs[i].ID > docs[j].ID
		}
		return docs[i].EventUnix > docs[j].EventUnix
	})

	start := 0
	if len(query.SearchAfter) >= 2 {
		afterUnix, _ := query.SearchAfter[0].(float64)
		afterID, _ := query.SearchAfter[1].(string)
		for i, doc := range docs {
			if doc.EventUnix == int64(afterUnix) && doc.ID == afterID {
				start = i + 1
				break
			}
		}
	}
	if start > len(docs) {
		start = len(docs)
	}
	end := start + query.Size
	if end > len(docs) {
		end = len(docs)
	}

	hits := make([]map[string]any, 0, end-start)
	for _, doc := range docs[start:end] {
		hits = append(hits, map[string]any{
			"_id":     doc.ID,
			"_source": doc,
			"sort":    []any{doc.EventUnix, doc.ID},
		})
	}

	writeTestJSON(w, http.StatusOK, map[string]any{
		"hits": map[string]any{
			"hits": hits,
		},
	})
}

func (s *fakeAuditSearchServer) documentCount(index string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.indices[index])
}

func writeTestJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func enableSearchAuditStore(t *testing.T, api *API, backend, endpoint, token string) {
	t.Helper()
	api.config.AuditStoreBackend = backend
	api.config.AuditStoreEndpoint = endpoint
	api.config.AuditStoreToken = token
	api.config.AuditStoreIndex = "ssh-proxy-audit-test"
	store, err := newAuditSearchStore(api.config)
	if err != nil {
		t.Fatalf("newAuditSearchStore() error = %v", err)
	}
	api.auditStore = store
}

func TestElasticAuditStoreServesEventsAfterFilesRemoved(t *testing.T) {
	fake, server := newFakeAuditSearchServer(t, "Bearer secret-token")
	defer server.Close()

	api, mux, _ := setupTestAPI(t)
	enableSearchAuditStore(t, api, "elasticsearch", server.URL, "secret-token")

	rr := doRequest(mux, http.MethodGet, "/api/v2/audit/events", nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
	resp := parseResponse(t, rr)
	if resp.Total != 3 {
		t.Fatalf("expected 3 events, got %d", resp.Total)
	}
	if fake.documentCount(api.config.AuditStoreIndex) != 3 {
		t.Fatalf("indexed document count = %d, want 3", fake.documentCount(api.config.AuditStoreIndex))
	}

	entries, err := os.ReadDir(api.config.AuditLogDir)
	if err != nil {
		t.Fatalf("ReadDir(audit) error = %v", err)
	}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		if err := os.Remove(filepath.Join(api.config.AuditLogDir, entry.Name())); err != nil {
			t.Fatalf("Remove(%s) error = %v", entry.Name(), err)
		}
	}

	rr = doRequest(mux, http.MethodGet, "/api/v2/audit/events", nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 after file removal, got %d: %s", rr.Code, rr.Body.String())
	}
	resp = parseResponse(t, rr)
	if resp.Total != 3 {
		t.Fatalf("expected persisted 3 events after file removal, got %d", resp.Total)
	}
}

func TestOpenSearchAuditStoreNormalizesLegacyAuditLogs(t *testing.T) {
	_, server := newFakeAuditSearchServer(t, "")
	defer server.Close()

	api, mux, _ := setupTestAPI(t)
	enableSearchAuditStore(t, api, "opensearch", server.URL, "")

	legacyAuditPath := filepath.Join(api.config.AuditLogDir, "audit_20240115.log")
	if err := os.WriteFile(legacyAuditPath, []byte(`{"timestamp":"2024-01-15T13:00:00Z","type":"AUTH_SUCCESS","session":42,"user":"carol","client":"10.0.0.3","target":"srv3"}`+"\n"), 0o600); err != nil {
		t.Fatalf("WriteFile(legacy audit) error = %v", err)
	}
	commandAuditPath := filepath.Join(api.config.AuditLogDir, "commands_20240115.log")
	if err := os.WriteFile(commandAuditPath, []byte(`{"timestamp":1705323600,"session":42,"user":"carol","upstream":"srv3","type":"command","command":"whoami"}`+"\n"), 0o600); err != nil {
		t.Fatalf("WriteFile(command audit) error = %v", err)
	}

	rr := doRequest(mux, http.MethodGet, "/api/v2/audit/events", nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
	resp := parseResponse(t, rr)
	if resp.Total != 5 {
		t.Fatalf("expected 5 events after legacy import, got %d", resp.Total)
	}

	entries, err := os.ReadDir(api.config.AuditLogDir)
	if err != nil {
		t.Fatalf("ReadDir(audit) error = %v", err)
	}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		if err := os.Remove(filepath.Join(api.config.AuditLogDir, entry.Name())); err != nil {
			t.Fatalf("Remove(%s) error = %v", entry.Name(), err)
		}
	}

	rr = doRequest(mux, http.MethodGet, "/api/v2/audit/search?q=whoami", nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 search, got %d: %s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "whoami") || !strings.Contains(rr.Body.String(), "command") {
		t.Fatalf("expected normalized command audit event, got %s", rr.Body.String())
	}

	rr = doRequest(mux, http.MethodGet, "/api/v2/audit/search?q=carol", nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 search, got %d: %s", rr.Code, rr.Body.String())
	}
	resp = parseResponse(t, rr)
	if resp.Total != 2 {
		t.Fatalf("expected 2 normalized legacy events for carol, got %d", resp.Total)
	}
}
