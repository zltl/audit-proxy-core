package server

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"testing"
	"time"

	sshproxyv1 "github.com/ssh-proxy-core/ssh-proxy-core/api/proto/sshproxy/v1"
	"github.com/ssh-proxy-core/ssh-proxy-core/internal/config"
	"github.com/ssh-proxy-core/ssh-proxy-core/internal/models"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/types/known/emptypb"
)

func waitForGRPCAddr(t *testing.T, srv *Server) string {
	t.Helper()

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if addr := srv.GRPCAddr(); addr != "" {
			return addr
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("gRPC listener did not become ready")
	return ""
}

func TestControlPlaneGRPCBridge(t *testing.T) {
	const token = "grpc-dp-token"

	sessionStart := time.Date(2026, 4, 8, 9, 0, 0, 0, time.UTC)
	dataPlane, requests := newAuthorizedDataPlaneServer(t, token, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/health":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(models.HealthStatus{
				Status:  "healthy",
				Version: "0.3.0",
				Uptime:  "42m",
			})
		case r.Method == http.MethodGet && r.URL.Path == "/sessions":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode([]models.Session{
				{
					ID:         "sess-active",
					Username:   "alice",
					SourceIP:   "10.0.0.1",
					TargetHost: "db.internal",
					TargetPort: 22,
					StartTime:  sessionStart,
					Duration:   "5m",
					Status:     "active",
				},
				{
					ID:         "sess-closed",
					Username:   "bob",
					SourceIP:   "10.0.0.2",
					TargetHost: "web.internal",
					TargetPort: 22,
					StartTime:  sessionStart.Add(-time.Hour),
					Duration:   "1h",
					Status:     "terminated",
				},
			})
		case r.Method == http.MethodDelete && r.URL.Path == "/sessions/sess-active":
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodGet && r.URL.Path == "/upstreams":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode([]models.Server{
				{
					ID:        "srv-1",
					Name:      "primary-db",
					Host:      "db.internal",
					Port:      22,
					Status:    "online",
					Healthy:   true,
					CheckedAt: sessionStart,
				},
				{
					ID:          "srv-2",
					Name:        "draining-web",
					Host:        "web.internal",
					Port:        22,
					Status:      "draining",
					Healthy:     false,
					Maintenance: true,
					CheckedAt:   sessionStart,
				},
			})
		case r.Method == http.MethodGet && r.URL.Path == "/config":
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"listen_addr":"0.0.0.0:2222","api_token":"top-secret","nested":{"private_key":"super-secret"}}`)
		case r.Method == http.MethodPost && r.URL.Path == "/config/reload":
			w.WriteHeader(http.StatusNoContent)
		default:
			http.NotFound(w, r)
		}
	})

	cfg := &config.Config{
		ListenAddr:     "127.0.0.1:0",
		GRPCListenAddr: "127.0.0.1:0",
		DataPlaneAddr:  dataPlane.URL,
		DataPlaneToken: token,
		SessionSecret:  "grpc-test-secret",
		AdminUser:      "admin",
		AuditLogDir:    t.TempDir(),
		RecordingDir:   t.TempDir(),
		DataDir:        t.TempDir(),
	}

	srv, err := New(cfg)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	errCh := make(chan error, 1)
	go func() {
		errCh <- srv.Start()
	}()

	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := srv.Shutdown(ctx); err != nil {
			t.Fatalf("Shutdown() error = %v", err)
		}
		select {
		case err := <-errCh:
			if err != nil && !errors.Is(err, http.ErrServerClosed) {
				t.Fatalf("Start() error = %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("timed out waiting for Start() to exit")
		}
	})

	grpcAddr := waitForGRPCAddr(t, srv)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	conn, err := grpc.DialContext(ctx, grpcAddr, grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithBlock())
	if err != nil {
		t.Fatalf("grpc.DialContext(%q) error = %v", grpcAddr, err)
	}
	defer conn.Close()

	systemClient := sshproxyv1.NewSystemServiceClient(conn)
	sessionClient := sshproxyv1.NewSessionServiceClient(conn)
	serverClient := sshproxyv1.NewServerServiceClient(conn)
	configClient := sshproxyv1.NewConfigServiceClient(conn)

	health, err := systemClient.GetHealth(ctx, &emptypb.Empty{})
	if err != nil {
		t.Fatalf("GetHealth() error = %v", err)
	}
	if health.GetStatus() != "healthy" || health.GetDataPlane() != "healthy" {
		t.Fatalf("GetHealth() = %+v, want healthy/healthy", health)
	}

	sessions, err := sessionClient.ListSessions(ctx, &sshproxyv1.ListSessionsRequest{Status: "active", Page: 1, PerPage: 10})
	if err != nil {
		t.Fatalf("ListSessions() error = %v", err)
	}
	if len(sessions.GetSessions()) != 1 || sessions.GetSessions()[0].GetId() != "sess-active" {
		t.Fatalf("ListSessions() = %+v, want sess-active only", sessions)
	}

	sessionItem, err := sessionClient.GetSession(ctx, &sshproxyv1.ResourceID{Id: "sess-active"})
	if err != nil {
		t.Fatalf("GetSession() error = %v", err)
	}
	if sessionItem.GetUsername() != "alice" {
		t.Fatalf("GetSession().username = %q, want alice", sessionItem.GetUsername())
	}

	killStatus, err := sessionClient.KillSession(ctx, &sshproxyv1.ResourceID{Id: "sess-active"})
	if err != nil {
		t.Fatalf("KillSession() error = %v", err)
	}
	if killStatus.GetMessage() != "session sess-active terminated" {
		t.Fatalf("KillSession().message = %q", killStatus.GetMessage())
	}

	servers, err := serverClient.ListServers(ctx, &sshproxyv1.ListServersRequest{Page: 1, PerPage: 10})
	if err != nil {
		t.Fatalf("ListServers() error = %v", err)
	}
	if len(servers.GetServers()) != 2 {
		t.Fatalf("ListServers() returned %d servers, want 2", len(servers.GetServers()))
	}

	summary, err := serverClient.GetHealthSummary(ctx, &emptypb.Empty{})
	if err != nil {
		t.Fatalf("GetHealthSummary() error = %v", err)
	}
	if summary.GetHealthy() != 1 || summary.GetUnhealthy() != 1 || summary.GetMaintenance() != 1 {
		t.Fatalf("GetHealthSummary() = %+v, want healthy=1 unhealthy=1 maintenance=1", summary)
	}

	configDoc, err := configClient.GetConfig(ctx, &emptypb.Empty{})
	if err != nil {
		t.Fatalf("GetConfig() error = %v", err)
	}
	configMap := configDoc.GetConfig().AsMap()
	if got := configMap["api_token"]; got != "***REDACTED***" {
		t.Fatalf("config api_token = %#v, want redacted", got)
	}
	nested, _ := configMap["nested"].(map[string]interface{})
	if got := nested["private_key"]; got != "***REDACTED***" {
		t.Fatalf("nested.private_key = %#v, want redacted", got)
	}

	reloadStatus, err := configClient.ReloadConfig(ctx, &emptypb.Empty{})
	if err != nil {
		t.Fatalf("ReloadConfig() error = %v", err)
	}
	if reloadStatus.GetMessage() != "configuration reloaded" {
		t.Fatalf("ReloadConfig().message = %q", reloadStatus.GetMessage())
	}

	if requests.count("GET /health") == 0 || requests.count("GET /sessions") == 0 ||
		requests.count("GET /upstreams") == 0 || requests.count("GET /config") == 0 ||
		requests.count("POST /config/reload") == 0 {
		t.Fatal("expected dataplane bridge requests were not observed")
	}
}
