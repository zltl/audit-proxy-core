package api

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ssh-proxy-core/ssh-proxy-core/internal/models"
)

type fakeS3Object struct {
	body    []byte
	modTime time.Time
}

type fakeS3Server struct {
	mu      sync.Mutex
	objects map[string]fakeS3Object
}

func newFakeS3Server() *fakeS3Server {
	return &fakeS3Server{objects: make(map[string]fakeS3Object)}
}

func (s *fakeS3Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	key, ok := s.parseRequest(r)
	if !ok {
		s.writeError(w, http.StatusNotFound, "NoSuchKey")
		return
	}
	if strings.HasSuffix(r.URL.RawQuery, "location=") || r.URL.Query().Has("location") {
		w.Header().Set("Content-Type", "application/xml")
		_, _ = io.WriteString(w, `<LocationConstraint xmlns="http://s3.amazonaws.com/doc/2006-03-01/">us-east-1</LocationConstraint>`)
		return
	}

	switch r.Method {
	case http.MethodHead:
		s.mu.Lock()
		object, ok := s.objects[key]
		s.mu.Unlock()
		if !ok {
			s.writeError(w, http.StatusNotFound, "NoSuchKey")
			return
		}
		w.Header().Set("Content-Length", fmt.Sprintf("%d", len(object.body)))
		w.Header().Set("Last-Modified", object.modTime.UTC().Format(http.TimeFormat))
		w.WriteHeader(http.StatusOK)
	case http.MethodPut:
		body, err := readObjectBody(r)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		s.mu.Lock()
		s.objects[key] = fakeS3Object{body: body, modTime: time.Now().UTC()}
		s.mu.Unlock()
		w.Header().Set("ETag", `"fake-etag"`)
		w.WriteHeader(http.StatusOK)
	case http.MethodGet:
		s.mu.Lock()
		object, ok := s.objects[key]
		s.mu.Unlock()
		if !ok {
			s.writeError(w, http.StatusNotFound, "NoSuchKey")
			return
		}
		w.Header().Set("Content-Length", fmt.Sprintf("%d", len(object.body)))
		w.Header().Set("Last-Modified", object.modTime.UTC().Format(http.TimeFormat))
		_, _ = w.Write(object.body)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func readObjectBody(r *http.Request) ([]byte, error) {
	if strings.Contains(r.Header.Get("X-Amz-Content-Sha256"), "STREAMING-AWS4-HMAC-SHA256-PAYLOAD") ||
		strings.Contains(r.Header.Get("Content-Encoding"), "aws-chunked") {
		return readAWSChunkedBody(r.Body)
	}
	return io.ReadAll(r.Body)
}

func readAWSChunkedBody(r io.Reader) ([]byte, error) {
	reader := bufio.NewReader(r)
	var body []byte
	for {
		header, err := reader.ReadString('\n')
		if err != nil {
			return nil, err
		}
		header = strings.TrimSpace(header)
		sizeField := header
		if idx := strings.IndexByte(sizeField, ';'); idx >= 0 {
			sizeField = sizeField[:idx]
		}
		size, err := strconv.ParseInt(sizeField, 16, 64)
		if err != nil {
			return nil, err
		}
		if size == 0 {
			if _, err := reader.ReadString('\n'); err != nil {
				return nil, err
			}
			return body, nil
		}

		chunk := make([]byte, size)
		if _, err := io.ReadFull(reader, chunk); err != nil {
			return nil, err
		}
		body = append(body, chunk...)
		if _, err := reader.ReadString('\n'); err != nil {
			return nil, err
		}
	}
}

func (s *fakeS3Server) parseRequest(r *http.Request) (string, bool) {
	path := strings.TrimPrefix(r.URL.Path, "/")
	if path == "" {
		return "", false
	}
	parts := strings.SplitN(path, "/", 2)
	if len(parts) == 0 || parts[0] == "" {
		return "", false
	}
	if len(parts) == 1 || parts[1] == "" {
		return "", true
	}
	return parts[1], true
}

func (s *fakeS3Server) writeError(w http.ResponseWriter, status int, code string) {
	w.Header().Set("Content-Type", "application/xml")
	w.WriteHeader(status)
	_, _ = io.WriteString(w, "<Error><Code>"+code+"</Code></Error>")
}

func (s *fakeS3Server) objectBody(key string) []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]byte(nil), s.objects[key].body...)
}

func TestSessionMetadataSyncDiscoversRecordingPath(t *testing.T) {
	api, _, dp := setupTestAPI(t)
	t.Cleanup(func() { _ = api.Close() })

	recordingPath := filepath.Join(api.config.RecordingDir, "session_s1_20240101_010203.cast")
	if err := os.WriteFile(recordingPath, []byte("{\"version\":2}\n"), 0o600); err != nil {
		t.Fatalf("WriteFile(recording) error = %v", err)
	}
	dp.sessions[0].RecordingFile = ""

	if err := api.syncSessionMetadata(); err != nil {
		t.Fatalf("syncSessionMetadata() error = %v", err)
	}

	session, err := api.sessionMetadata.GetSession("s1")
	if err != nil {
		t.Fatalf("GetSession() error = %v", err)
	}
	if session.RecordingFile != recordingPath {
		t.Fatalf("recording_file = %q, want %q", session.RecordingFile, recordingPath)
	}
}

func TestRecordingArchiveUploadsAndDownloadFallsBackToObjectStorage(t *testing.T) {
	store := newFakeS3Server()
	server := httptest.NewServer(store)
	defer server.Close()

	dir := t.TempDir()
	dp := &mockDP{
		sessions: []models.Session{
			{
				ID:         "s3",
				Username:   "alice",
				SourceIP:   "10.0.0.1",
				TargetHost: "srv3.local",
				TargetPort: 22,
				Status:     "active",
				StartTime:  time.Now().UTC(),
			},
		},
	}

	cfg := &Config{
		AdminUser:                       "admin",
		AdminPassHash:                   "test",
		SessionSecret:                   "secret",
		AuditLogDir:                     filepath.Join(dir, "audit"),
		RecordingDir:                    dir,
		RecordingObjectStorageEnabled:   true,
		RecordingObjectStorageEndpoint:  server.URL,
		RecordingObjectStorageBucket:    "recordings",
		RecordingObjectStorageAccessKey: "access",
		RecordingObjectStorageSecretKey: "secret",
		RecordingObjectStoragePrefix:    "archive",
		DataDir:                         dir,
		ConfigFile:                      filepath.Join(dir, "config.ini"),
		ConfigVerDir:                    filepath.Join(dir, "config_versions"),
	}
	if err := os.WriteFile(cfg.ConfigFile, []byte(`{"listen_port": 2222}`), 0o600); err != nil {
		t.Fatalf("WriteFile(config) error = %v", err)
	}

	api, err := New(dp, cfg)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	t.Cleanup(func() { _ = api.Close() })
	mux := http.NewServeMux()
	api.RegisterRoutes(mux)

	recordingPath := filepath.Join(dir, "session_s3_20240101_010203.cast")
	initial := []byte("{\"version\":2}\n")
	if err := os.WriteFile(recordingPath, initial, 0o600); err != nil {
		t.Fatalf("WriteFile(initial recording) error = %v", err)
	}

	if err := api.syncSessionMetadata(); err != nil {
		t.Fatalf("syncSessionMetadata() error = %v", err)
	}
	if err := api.syncRecordingArchive(context.Background()); err != nil {
		t.Fatalf("syncRecordingArchive(initial) error = %v", err)
	}
	if got := string(store.objectBody("archive/sessions/s3.cast")); got != string(initial) {
		t.Fatalf("archived body = %q, want %q", got, initial)
	}

	updated := []byte("{\"version\":2}\n[0.1,\"o\",\"hello\"]\n")
	if err := os.WriteFile(recordingPath, updated, 0o600); err != nil {
		t.Fatalf("WriteFile(updated recording) error = %v", err)
	}
	time.Sleep(2 * time.Second)
	if err := api.syncRecordingArchive(context.Background()); err != nil {
		t.Fatalf("syncRecordingArchive(updated) error = %v", err)
	}
	if got := string(store.objectBody("archive/sessions/s3.cast")); got != string(updated) {
		t.Fatalf("updated archived body = %q, want %q", got, updated)
	}

	if err := os.Remove(recordingPath); err != nil {
		t.Fatalf("Remove(recording) error = %v", err)
	}

	rr := doRequest(mux, http.MethodGet, "/api/v2/sessions/s3/recording/download", nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("download archived recording: expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
	if body := rr.Body.String(); body != string(updated) {
		t.Fatalf("download body = %q, want %q", body, updated)
	}
	if got := rr.Header().Get("Content-Type"); !strings.Contains(got, "application/x-asciicast") {
		t.Fatalf("unexpected content type %q", got)
	}
}
