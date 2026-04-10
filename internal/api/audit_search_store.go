package api

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/ssh-proxy-core/ssh-proxy-core/internal/models"
)

const (
	defaultAuditSearchIndex  = "ssh-proxy-audit"
	auditSearchBulkBatchSize = 200
	auditSearchPageSize      = 500
)

type auditSearchStore struct {
	backend  string
	endpoint string
	token    string
	username string
	password string
	index    string
	client   *http.Client

	statePath string
	stateMu   sync.Mutex
	offsets   map[string]int64

	ensureIndexMu sync.Mutex
	indexReady    bool
}

type auditSearchSyncState struct {
	Backend  string           `json:"backend"`
	Endpoint string           `json:"endpoint"`
	Index    string           `json:"index"`
	Offsets  map[string]int64 `json:"offsets"`
}

type auditSearchDocument struct {
	ID         string `json:"id"`
	EventUnix  int64  `json:"event_unix"`
	Timestamp  string `json:"timestamp"`
	EventType  string `json:"event_type"`
	Username   string `json:"username"`
	SourceIP   string `json:"source_ip,omitempty"`
	TargetHost string `json:"target_host,omitempty"`
	Details    string `json:"details,omitempty"`
	SessionID  string `json:"session_id,omitempty"`
	SourceFile string `json:"source_file,omitempty"`
}

func newAuditSearchStore(cfg *Config) (*auditSearchStore, error) {
	if cfg == nil || !auditStoreUsesSearch(cfg.AuditStoreBackend) {
		return nil, nil
	}
	index := strings.TrimSpace(cfg.AuditStoreIndex)
	if index == "" {
		index = defaultAuditSearchIndex
	}
	store := &auditSearchStore{
		backend:  strings.TrimSpace(cfg.AuditStoreBackend),
		endpoint: strings.TrimRight(strings.TrimSpace(cfg.AuditStoreEndpoint), "/"),
		token:    strings.TrimSpace(cfg.AuditStoreToken),
		username: strings.TrimSpace(cfg.AuditStoreUsername),
		password: cfg.AuditStorePassword,
		index:    index,
		client: &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: cfg.AuditStoreInsecureTLS}, // #nosec G402 -- explicit operator opt-in for private/self-signed Elasticsearch/OpenSearch clusters.
			},
			Timeout: 10 * time.Second,
		},
		statePath: dataFilePath(cfg.DataDir, "audit_store_offsets.json"),
		offsets:   map[string]int64{},
	}
	if err := store.loadState(); err != nil {
		return nil, err
	}
	return store, nil
}

func (s *auditSearchStore) Close() error {
	return nil
}

func (s *auditSearchStore) ListEvents() ([]models.AuditEvent, error) {
	events := make([]models.AuditEvent, 0)
	var searchAfter []interface{}
	for {
		docs, next, err := s.searchPage(searchAfter)
		if err != nil {
			return nil, err
		}
		if len(docs) == 0 {
			break
		}
		for _, doc := range docs {
			events = append(events, doc.toAuditEvent())
		}
		if next == nil {
			break
		}
		searchAfter = next
	}
	return events, nil
}

func (s *auditSearchStore) SyncDir(dir string) error {
	if strings.TrimSpace(dir) == "" {
		return fmt.Errorf("audit log directory not configured")
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("failed to read audit directory: %w", err)
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if !strings.HasSuffix(name, ".jsonl") && !strings.HasSuffix(name, ".log") {
			continue
		}

		path := filepath.Join(dir, name)
		info, err := entry.Info()
		if err != nil {
			return err
		}
		offset := s.fileOffset(path)
		if info.Size() < offset {
			offset = 0
		}
		nextOffset, err := s.syncFile(path, offset)
		if err != nil {
			return err
		}
		if err := s.saveFileOffset(path, nextOffset); err != nil {
			return err
		}
	}
	return nil
}

func (s *auditSearchStore) syncFile(path string, offset int64) (int64, error) {
	file, err := os.Open(path)
	if err != nil {
		return offset, err
	}
	defer file.Close()

	if _, err := file.Seek(offset, io.SeekStart); err != nil {
		return offset, err
	}

	reader := bufio.NewReader(file)
	currentOffset := offset
	docs := make([]auditSearchDocument, 0, auditSearchBulkBatchSize)
	flush := func() error {
		if len(docs) == 0 {
			return nil
		}
		if err := s.bulkIndex(docs); err != nil {
			return err
		}
		docs = docs[:0]
		return nil
	}

	for {
		lineOffset := currentOffset
		line, readErr := reader.ReadBytes('\n')
		currentOffset += int64(len(line))
		trimmed := bytes.TrimSpace(line)
		if len(trimmed) > 0 {
			event, err := parseAuditLogLine(path, lineOffset, trimmed)
			if err == nil && event != nil {
				docs = append(docs, auditSearchDocumentFromEvent(*event, path))
				if len(docs) >= auditSearchBulkBatchSize {
					if err := flush(); err != nil {
						return offset, err
					}
				}
			}
		}
		if readErr != nil {
			if readErr == io.EOF {
				break
			}
			return offset, readErr
		}
	}
	if err := flush(); err != nil {
		return offset, err
	}
	return currentOffset, nil
}

func auditSearchDocumentFromEvent(event models.AuditEvent, sourceFile string) auditSearchDocument {
	return auditSearchDocument{
		ID:         event.ID,
		EventUnix:  unixTimestamp(event.Timestamp),
		Timestamp:  event.Timestamp.UTC().Format(time.RFC3339),
		EventType:  event.EventType,
		Username:   event.Username,
		SourceIP:   event.SourceIP,
		TargetHost: event.TargetHost,
		Details:    event.Details,
		SessionID:  event.SessionID,
		SourceFile: sourceFile,
	}
}

func (d auditSearchDocument) toAuditEvent() models.AuditEvent {
	timestamp := time.Time{}
	if strings.TrimSpace(d.Timestamp) != "" {
		if parsed, err := time.Parse(time.RFC3339, d.Timestamp); err == nil {
			timestamp = parsed.UTC()
		}
	}
	if timestamp.IsZero() && d.EventUnix > 0 {
		timestamp = time.Unix(d.EventUnix, 0).UTC()
	}
	return models.AuditEvent{
		ID:         d.ID,
		Timestamp:  timestamp,
		EventType:  d.EventType,
		Username:   d.Username,
		SourceIP:   d.SourceIP,
		TargetHost: d.TargetHost,
		Details:    d.Details,
		SessionID:  d.SessionID,
	}
}

func (s *auditSearchStore) bulkIndex(docs []auditSearchDocument) error {
	if len(docs) == 0 {
		return nil
	}
	if err := s.ensureIndex(); err != nil {
		return err
	}

	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	for _, doc := range docs {
		action := map[string]map[string]string{
			"index": {
				"_index": s.index,
				"_id":    doc.ID,
			},
		}
		if err := enc.Encode(action); err != nil {
			return fmt.Errorf("audit search: encode bulk action: %w", err)
		}
		if err := enc.Encode(doc); err != nil {
			return fmt.Errorf("audit search: encode bulk document: %w", err)
		}
	}

	req, err := http.NewRequest(http.MethodPost, s.endpoint+"/"+s.index+"/_bulk", &buf)
	if err != nil {
		return fmt.Errorf("audit search: build bulk request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-ndjson")
	s.applyAuth(req)

	resp, err := s.client.Do(req)
	if err != nil {
		return fmt.Errorf("audit search: execute bulk request: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 300 {
		return fmt.Errorf("audit search: bulk index returned %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	var parsed struct {
		Errors bool `json:"errors"`
		Items  []map[string]struct {
			Status int                    `json:"status"`
			Error  map[string]interface{} `json:"error"`
		} `json:"items"`
	}
	if len(bytes.TrimSpace(body)) == 0 {
		return nil
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		return fmt.Errorf("audit search: decode bulk response: %w", err)
	}
	if !parsed.Errors {
		return nil
	}
	for _, item := range parsed.Items {
		for _, result := range item {
			if result.Status >= 300 {
				raw, _ := json.Marshal(result.Error)
				if len(raw) == 0 {
					return fmt.Errorf("audit search: bulk index item failed with status %d", result.Status)
				}
				return fmt.Errorf("audit search: bulk index item failed with status %d: %s", result.Status, raw)
			}
		}
	}
	return fmt.Errorf("audit search: bulk index reported errors")
}

func (s *auditSearchStore) searchPage(searchAfter []interface{}) ([]auditSearchDocument, []interface{}, error) {
	query := map[string]interface{}{
		"size": auditSearchPageSize,
		"_source": []string{
			"id",
			"event_unix",
			"timestamp",
			"event_type",
			"username",
			"source_ip",
			"target_host",
			"details",
			"session_id",
		},
		"query": map[string]interface{}{
			"match_all": map[string]interface{}{},
		},
		"sort": []map[string]interface{}{
			{"event_unix": map[string]interface{}{"order": "desc", "unmapped_type": "long"}},
			{"id": map[string]interface{}{"order": "desc", "unmapped_type": "keyword"}},
		},
	}
	if len(searchAfter) > 0 {
		query["search_after"] = searchAfter
	}
	body, err := json.Marshal(query)
	if err != nil {
		return nil, nil, fmt.Errorf("audit search: encode search query: %w", err)
	}

	req, err := http.NewRequest(http.MethodPost, s.endpoint+"/"+s.index+"/_search", bytes.NewReader(body))
	if err != nil {
		return nil, nil, fmt.Errorf("audit search: build search request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	s.applyAuth(req)

	resp, err := s.client.Do(req)
	if err != nil {
		return nil, nil, fmt.Errorf("audit search: execute search request: %w", err)
	}
	defer resp.Body.Close()

	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode == http.StatusNotFound {
		return []auditSearchDocument{}, nil, nil
	}
	if resp.StatusCode >= 300 {
		return nil, nil, fmt.Errorf("audit search: search returned %d: %s", resp.StatusCode, strings.TrimSpace(string(raw)))
	}

	var parsed struct {
		Hits struct {
			Hits []struct {
				ID     string              `json:"_id"`
				Sort   []interface{}       `json:"sort"`
				Source auditSearchDocument `json:"_source"`
			} `json:"hits"`
		} `json:"hits"`
	}
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return nil, nil, fmt.Errorf("audit search: decode search response: %w", err)
	}
	if len(parsed.Hits.Hits) == 0 {
		return []auditSearchDocument{}, nil, nil
	}

	docs := make([]auditSearchDocument, 0, len(parsed.Hits.Hits))
	for _, hit := range parsed.Hits.Hits {
		doc := hit.Source
		if doc.ID == "" {
			doc.ID = hit.ID
		}
		docs = append(docs, doc)
	}

	var next []interface{}
	if len(parsed.Hits.Hits) == auditSearchPageSize {
		next = parsed.Hits.Hits[len(parsed.Hits.Hits)-1].Sort
	}
	return docs, next, nil
}

func (s *auditSearchStore) ensureIndex() error {
	s.ensureIndexMu.Lock()
	defer s.ensureIndexMu.Unlock()
	if s.indexReady {
		return nil
	}
	if err := s.createIndex(); err != nil {
		return err
	}
	s.indexReady = true
	return nil
}

func (s *auditSearchStore) createIndex() error {
	body := map[string]interface{}{
		"mappings": map[string]interface{}{
			"properties": map[string]interface{}{
				"id":          map[string]string{"type": "keyword"},
				"event_unix":  map[string]string{"type": "long"},
				"timestamp":   map[string]string{"type": "date"},
				"event_type":  map[string]string{"type": "keyword"},
				"username":    map[string]string{"type": "keyword"},
				"source_ip":   map[string]string{"type": "keyword"},
				"target_host": map[string]string{"type": "keyword"},
				"details":     map[string]string{"type": "text"},
				"session_id":  map[string]string{"type": "keyword"},
				"source_file": map[string]string{"type": "keyword"},
			},
		},
	}
	raw, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("audit search: encode index mapping: %w", err)
	}

	req, err := http.NewRequest(http.MethodPut, s.endpoint+"/"+s.index, bytes.NewReader(raw))
	if err != nil {
		return fmt.Errorf("audit search: build create index request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	s.applyAuth(req)

	resp, err := s.client.Do(req)
	if err != nil {
		return fmt.Errorf("audit search: execute create index request: %w", err)
	}
	defer resp.Body.Close()

	bodyRaw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode < 300 {
		return nil
	}
	lower := strings.ToLower(string(bodyRaw))
	if (resp.StatusCode == http.StatusBadRequest || resp.StatusCode == http.StatusConflict) &&
		(strings.Contains(lower, "resource_already_exists_exception") || strings.Contains(lower, "already exists")) {
		return nil
	}
	return fmt.Errorf("audit search: create index returned %d: %s", resp.StatusCode, strings.TrimSpace(string(bodyRaw)))
}

func (s *auditSearchStore) applyAuth(req *http.Request) {
	if req == nil {
		return
	}
	if s.token != "" {
		req.Header.Set("Authorization", "Bearer "+s.token)
		return
	}
	if s.username != "" {
		req.SetBasicAuth(s.username, s.password)
	}
}

func (s *auditSearchStore) fileOffset(path string) int64 {
	s.stateMu.Lock()
	defer s.stateMu.Unlock()
	return s.offsets[path]
}

func (s *auditSearchStore) saveFileOffset(path string, offset int64) error {
	s.stateMu.Lock()
	defer s.stateMu.Unlock()
	s.offsets[path] = offset
	return s.persistStateLocked()
}

func (s *auditSearchStore) loadState() error {
	if strings.TrimSpace(s.statePath) == "" {
		return nil
	}
	data, err := os.ReadFile(s.statePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("audit search: read sync state: %w", err)
	}
	if len(bytes.TrimSpace(data)) == 0 {
		return nil
	}

	var state auditSearchSyncState
	if err := json.Unmarshal(data, &state); err != nil {
		return fmt.Errorf("audit search: decode sync state: %w", err)
	}
	if strings.TrimSpace(state.Endpoint) != s.endpoint || strings.TrimSpace(state.Index) != s.index || strings.TrimSpace(state.Backend) != s.backend {
		return nil
	}
	if state.Offsets != nil {
		s.offsets = state.Offsets
	}
	return nil
}

func (s *auditSearchStore) persistStateLocked() error {
	if strings.TrimSpace(s.statePath) == "" {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(s.statePath), 0o755); err != nil {
		return fmt.Errorf("audit search: create sync state dir: %w", err)
	}
	state := auditSearchSyncState{
		Backend:  s.backend,
		Endpoint: s.endpoint,
		Index:    s.index,
		Offsets:  s.offsets,
	}
	raw, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return fmt.Errorf("audit search: encode sync state: %w", err)
	}
	tmpPath := s.statePath + ".tmp"
	if err := os.WriteFile(tmpPath, raw, 0o600); err != nil {
		return fmt.Errorf("audit search: write sync state: %w", err)
	}
	if err := os.Rename(tmpPath, s.statePath); err != nil {
		return fmt.Errorf("audit search: persist sync state: %w", err)
	}
	return nil
}
