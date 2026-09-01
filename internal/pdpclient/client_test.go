package pdpclient

import (
	"context"
	"errors"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"

	sshproxyv1 "github.com/ssh-proxy-core/ssh-proxy-core/api/proto/sshproxy/v1"
)

// stubServer is a scriptable decision point.
type stubServer struct {
	sshproxyv1.UnimplementedAccessDecisionServiceServer

	mu sync.Mutex

	sessionResponse *sshproxyv1.AuthorizeSessionResponse
	sessionCalls    int
	sessionErr      error

	channelResponse *sshproxyv1.AuthorizeChannelResponse
	channelErr      error

	commandMessages []*sshproxyv1.AuthorizeCommandResponse
	commandErr      error

	hostKeyResponse *sshproxyv1.ResolveHostKeyResponse
	hostKeyErr      error

	heartbeatResponse *sshproxyv1.HeartbeatSessionResponse
	heartbeatErr      error

	revocations   []*sshproxyv1.Revocation
	revocationErr error
}

func (s *stubServer) AuthorizeSession(context.Context, *sshproxyv1.AuthorizeSessionRequest) (*sshproxyv1.AuthorizeSessionResponse, error) {
	s.mu.Lock()
	s.sessionCalls++
	err, resp := s.sessionErr, s.sessionResponse
	s.mu.Unlock()
	if err != nil {
		return nil, err
	}
	return resp, nil
}

func (s *stubServer) AuthorizeChannel(context.Context, *sshproxyv1.AuthorizeChannelRequest) (*sshproxyv1.AuthorizeChannelResponse, error) {
	if s.channelErr != nil {
		return nil, s.channelErr
	}
	return s.channelResponse, nil
}

func (s *stubServer) AuthorizeCommand(_ *sshproxyv1.AuthorizeCommandRequest, stream sshproxyv1.AccessDecisionService_AuthorizeCommandServer) error {
	if s.commandErr != nil {
		return s.commandErr
	}
	for _, msg := range s.commandMessages {
		if err := stream.Send(msg); err != nil {
			return err
		}
	}
	return nil
}

func (s *stubServer) ResolveHostKey(context.Context, *sshproxyv1.ResolveHostKeyRequest) (*sshproxyv1.ResolveHostKeyResponse, error) {
	if s.hostKeyErr != nil {
		return nil, s.hostKeyErr
	}
	return s.hostKeyResponse, nil
}

func (s *stubServer) HeartbeatSession(context.Context, *sshproxyv1.HeartbeatSessionRequest) (*sshproxyv1.HeartbeatSessionResponse, error) {
	if s.heartbeatErr != nil {
		return nil, s.heartbeatErr
	}
	return s.heartbeatResponse, nil
}

func (s *stubServer) StreamRevocations(_ *sshproxyv1.StreamRevocationsRequest, stream sshproxyv1.AccessDecisionService_StreamRevocationsServer) error {
	if s.revocationErr != nil {
		return s.revocationErr
	}
	for _, rev := range s.revocations {
		if err := stream.Send(rev); err != nil {
			return err
		}
	}
	<-stream.Context().Done()
	return nil
}

func (s *stubServer) callCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.sessionCalls
}

// newTestClient wires a client to a stub over an in-memory connection.
func newTestClient(t *testing.T, stub *stubServer, cfg Config) *Client {
	t.Helper()

	listener := bufconn.Listen(1024 * 1024)
	server := grpc.NewServer()
	sshproxyv1.RegisterAccessDecisionServiceServer(server, stub)
	go func() { _ = server.Serve(listener) }()

	conn, err := grpc.NewClient("passthrough:///bufnet",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return listener.DialContext(ctx)
		}),
		grpc.WithTransportCredentials(insecureCreds()),
	)
	if err != nil {
		t.Fatalf("grpc.NewClient: %v", err)
	}
	t.Cleanup(func() {
		_ = conn.Close()
		server.Stop()
		_ = listener.Close()
	})

	cfg.NodeID = "node-a"
	cfg.Address = "bufnet"
	return NewWithConn(conn, cfg)
}

func TestConfigValidation(t *testing.T) {
	cases := []struct {
		name    string
		cfg     Config
		wantErr string
	}{
		{"missing address", Config{NodeID: "n1"}, "address"},
		{"missing node id", Config{Address: "unix:/tmp/pdp.sock"}, "node id"},
		{"unknown fail mode", Config{Address: "unix:/tmp/p", NodeID: "n1", FailMode: "maybe"}, "fail mode"},
		{"insecure over the network", Config{Address: "pdp.internal:9443", NodeID: "n1", Insecure: true},
			"local unix socket"},
		{"remote without a client certificate", Config{Address: "pdp.internal:9443", NodeID: "n1"},
			"client certificate"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.cfg.Validate()
			if err == nil {
				t.Fatalf("expected an error mentioning %q", tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("error = %v, want it to mention %q", err, tc.wantErr)
			}
		})
	}

	valid := Config{Address: "unix:/run/pdp.sock", NodeID: "n1", Insecure: true}
	if err := valid.Validate(); err != nil {
		t.Fatalf("a local socket with insecure transport should be accepted: %v", err)
	}
}

func TestAuthorizeSessionCaches(t *testing.T) {
	stub := &stubServer{sessionResponse: &sshproxyv1.AuthorizeSessionResponse{
		Allowed: true, TargetHost: "10.0.1.10", TargetPort: 22,
	}}
	client := newTestClient(t, stub, Config{CacheTTL: time.Minute})

	req := &sshproxyv1.AuthorizeSessionRequest{
		Username: "alice", Target: "web-1", UpstreamLogin: "deploy",
		Client: &sshproxyv1.ClientInfo{SourceIp: "10.0.0.5"},
	}
	for i := 0; i < 3; i++ {
		resp, err := client.AuthorizeSession(context.Background(), req)
		if err != nil {
			t.Fatalf("AuthorizeSession: %v", err)
		}
		if !resp.GetAllowed() {
			t.Fatal("expected allow")
		}
	}
	if got := stub.callCount(); got != 1 {
		t.Fatalf("the decision point was called %d times; the cache is not being used", got)
	}

	// A different principal must not be served from another's cached answer.
	other := &sshproxyv1.AuthorizeSessionRequest{
		Username: "bob", Target: "web-1", UpstreamLogin: "deploy",
		Client: &sshproxyv1.ClientInfo{SourceIp: "10.0.0.5"},
	}
	if _, err := client.AuthorizeSession(context.Background(), other); err != nil {
		t.Fatalf("AuthorizeSession: %v", err)
	}
	if got := stub.callCount(); got != 2 {
		t.Fatalf("a different user was answered from the cache (calls = %d)", got)
	}
}

func TestAuthorizeSessionDoesNotCacheRefusals(t *testing.T) {
	stub := &stubServer{sessionResponse: &sshproxyv1.AuthorizeSessionResponse{
		Allowed: false, Reason: "no rule permits this",
	}}
	client := newTestClient(t, stub, Config{CacheTTL: time.Minute})

	req := &sshproxyv1.AuthorizeSessionRequest{Username: "alice", Target: "web-1"}
	for i := 0; i < 2; i++ {
		if _, err := client.AuthorizeSession(context.Background(), req); err != nil {
			t.Fatalf("AuthorizeSession: %v", err)
		}
	}
	if got := stub.callCount(); got != 2 {
		t.Fatalf("a refusal was cached; adding a grant would not take effect for the TTL (calls = %d)", got)
	}
}

func TestFailClosedRefusesWhenUnreachable(t *testing.T) {
	stub := &stubServer{sessionErr: status.Error(codes.Unavailable, "control plane is down")}
	client := newTestClient(t, stub, Config{FailMode: FailClosed})

	resp, err := client.AuthorizeSession(context.Background(), &sshproxyv1.AuthorizeSessionRequest{
		Username: "alice", Target: "web-1",
	})
	if err != nil {
		t.Fatalf("AuthorizeSession: %v", err)
	}
	if resp.GetAllowed() {
		t.Fatal("with the policy unreachable and fail-closed, the session must be refused")
	}
	if healthy, _ := client.Healthy(); healthy {
		t.Error("the client should report itself unhealthy after an unreachable call")
	}
}

func TestFailOpenAdmitsWhenUnreachable(t *testing.T) {
	stub := &stubServer{sessionErr: status.Error(codes.Unavailable, "control plane is down")}
	client := newTestClient(t, stub, Config{FailMode: FailOpen})

	resp, err := client.AuthorizeSession(context.Background(), &sshproxyv1.AuthorizeSessionRequest{
		Username: "alice", Target: "web-1",
	})
	if err != nil {
		t.Fatalf("AuthorizeSession: %v", err)
	}
	if !resp.GetAllowed() {
		t.Fatal("fail-open should admit the session")
	}
	// Even fail-open must not hand out more than the interactive basics.
	features := strings.Join(resp.GetFeatures(), ",")
	if strings.Contains(features, "forward") || strings.Contains(features, "sftp") {
		t.Errorf("fail-open granted more than the basics: %s", features)
	}
}

func TestDeliberateRefusalIsNotSoftenedByFailOpen(t *testing.T) {
	// A refusal is an answer, not an outage. Fail-open must not turn one into
	// an allow, or a deny rule would stop meaning anything under load.
	stub := &stubServer{sessionResponse: &sshproxyv1.AuthorizeSessionResponse{
		Allowed: false, Reason: "denied by policy",
	}}
	client := newTestClient(t, stub, Config{FailMode: FailOpen})

	resp, err := client.AuthorizeSession(context.Background(), &sshproxyv1.AuthorizeSessionRequest{
		Username: "alice", Target: "web-1",
	})
	if err != nil {
		t.Fatalf("AuthorizeSession: %v", err)
	}
	if resp.GetAllowed() {
		t.Fatal("fail-open converted a deliberate denial into an allow")
	}
}

func TestNonTransportErrorsArePropagated(t *testing.T) {
	stub := &stubServer{sessionErr: status.Error(codes.Internal, "database exploded")}
	client := newTestClient(t, stub, Config{FailMode: FailClosed})

	if _, err := client.AuthorizeSession(context.Background(), &sshproxyv1.AuthorizeSessionRequest{
		Username: "alice",
	}); err == nil {
		t.Fatal("a service error should surface rather than being turned into a policy decision")
	}
}

func TestHostKeyIsNeverSoftenedByFailOpen(t *testing.T) {
	stub := &stubServer{hostKeyErr: status.Error(codes.Unavailable, "down")}
	client := newTestClient(t, stub, Config{FailMode: FailOpen})

	resp, err := client.ResolveHostKey(context.Background(), &sshproxyv1.ResolveHostKeyRequest{
		Fingerprint: "SHA256:x",
	})
	if err != nil {
		t.Fatalf("ResolveHostKey: %v", err)
	}
	if resp.GetProceed() {
		t.Fatal("an unverifiable host key was accepted; the recording would not provably be of the intended host")
	}
}

func TestAuthorizeCommandApprovalStages(t *testing.T) {
	stub := &stubServer{commandMessages: []*sshproxyv1.AuthorizeCommandResponse{
		{Decision: sshproxyv1.CommandDecision_COMMAND_DECISION_PENDING_APPROVAL, ApprovalId: "a1"},
		{Decision: sshproxyv1.CommandDecision_COMMAND_DECISION_ALLOW, Reason: "approved by reviewer"},
	}}
	client := newTestClient(t, stub, Config{})

	var seen []sshproxyv1.CommandDecision
	final, err := client.AuthorizeCommand(context.Background(), &sshproxyv1.AuthorizeCommandRequest{
		SessionId: "s1", Command: "systemctl restart nginx",
	}, func(resp *sshproxyv1.AuthorizeCommandResponse) {
		seen = append(seen, resp.GetDecision())
	})
	if err != nil {
		t.Fatalf("AuthorizeCommand: %v", err)
	}
	if len(seen) != 2 || seen[0] != sshproxyv1.CommandDecision_COMMAND_DECISION_PENDING_APPROVAL {
		t.Fatalf("the caller should see the pending stage so it can tell the user: %v", seen)
	}
	if final.GetDecision() != sshproxyv1.CommandDecision_COMMAND_DECISION_ALLOW {
		t.Fatalf("final = %v", final.GetDecision())
	}
}

func TestAuthorizeCommandFailModes(t *testing.T) {
	t.Run("closed denies", func(t *testing.T) {
		stub := &stubServer{commandErr: status.Error(codes.Unavailable, "down")}
		client := newTestClient(t, stub, Config{FailMode: FailClosed})
		resp, err := client.AuthorizeCommand(context.Background(),
			&sshproxyv1.AuthorizeCommandRequest{Command: "rm -rf /"}, nil)
		if err != nil {
			t.Fatalf("AuthorizeCommand: %v", err)
		}
		if resp.GetDecision() != sshproxyv1.CommandDecision_COMMAND_DECISION_DENY {
			t.Fatalf("decision = %v, want DENY", resp.GetDecision())
		}
	})

	t.Run("open allows", func(t *testing.T) {
		stub := &stubServer{commandErr: status.Error(codes.Unavailable, "down")}
		client := newTestClient(t, stub, Config{FailMode: FailOpen})
		resp, err := client.AuthorizeCommand(context.Background(),
			&sshproxyv1.AuthorizeCommandRequest{Command: "ls"}, nil)
		if err != nil {
			t.Fatalf("AuthorizeCommand: %v", err)
		}
		if resp.GetDecision() != sshproxyv1.CommandDecision_COMMAND_DECISION_ALLOW {
			t.Fatalf("decision = %v, want ALLOW", resp.GetDecision())
		}
	})
}

func TestHeartbeatDoesNotCutSessionsOnControlPlaneBlip(t *testing.T) {
	stub := &stubServer{heartbeatErr: status.Error(codes.Unavailable, "down")}
	client := newTestClient(t, stub, Config{FailMode: FailClosed})

	revoked, _, err := client.HeartbeatSession(context.Background(), "s1", 1, 2)
	if err != nil {
		t.Fatalf("HeartbeatSession: %v", err)
	}
	if revoked {
		t.Fatal("a missed heartbeat should not disconnect an established session")
	}
}

func TestHeartbeatSurfacesRevocationAndClearsCache(t *testing.T) {
	stub := &stubServer{
		heartbeatResponse: &sshproxyv1.HeartbeatSessionResponse{Revoked: true, Reason: "kicked"},
		sessionResponse:   &sshproxyv1.AuthorizeSessionResponse{Allowed: true},
	}
	client := newTestClient(t, stub, Config{CacheTTL: time.Minute})

	req := &sshproxyv1.AuthorizeSessionRequest{Username: "alice", Target: "web-1"}
	if _, err := client.AuthorizeSession(context.Background(), req); err != nil {
		t.Fatalf("AuthorizeSession: %v", err)
	}
	if client.cache.Len() == 0 {
		t.Fatal("the allow should have been cached")
	}

	revoked, reason, err := client.HeartbeatSession(context.Background(), "s1", 0, 0)
	if err != nil {
		t.Fatalf("HeartbeatSession: %v", err)
	}
	if !revoked || reason != "kicked" {
		t.Fatalf("heartbeat = (%v, %q)", revoked, reason)
	}
	if client.cache.Len() != 0 {
		t.Fatal("a revocation must invalidate cached decisions, or a stale allow outlives the grant")
	}
}

func TestWatchRevocationsDeliversAndReconnects(t *testing.T) {
	stub := &stubServer{revocations: []*sshproxyv1.Revocation{
		{SessionId: "s1", Reason: "terminated"},
	}}
	client := newTestClient(t, stub, Config{})

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	received := make(chan *sshproxyv1.Revocation, 4)
	go client.WatchRevocations(ctx, func(rev *sshproxyv1.Revocation) { received <- rev })

	select {
	case rev := <-received:
		if rev.GetSessionId() != "s1" {
			t.Fatalf("received %+v", rev)
		}
	case <-ctx.Done():
		t.Fatal("no revocation was delivered")
	}
}

func TestUnreachableClassification(t *testing.T) {
	if !unreachable(status.Error(codes.Unavailable, "down")) {
		t.Error("Unavailable should count as unreachable")
	}
	if !unreachable(context.DeadlineExceeded) {
		t.Error("a timeout should count as unreachable")
	}
	if unreachable(status.Error(codes.PermissionDenied, "no")) {
		t.Error("a permission denial is an answer, not an outage")
	}
	if unreachable(errors.New("some validation problem")) {
		t.Error("an ordinary error should not engage the fail mode")
	}
	if unreachable(nil) {
		t.Error("nil is not an error")
	}
}

func TestCacheExpiry(t *testing.T) {
	cache := newDecisionCache(50 * time.Millisecond)
	base := time.Now()
	cache.now = func() time.Time { return base }

	cache.Put("k", "v")
	if _, ok := cache.Get("k"); !ok {
		t.Fatal("a fresh entry should be readable")
	}
	cache.now = func() time.Time { return base.Add(time.Second) }
	if _, ok := cache.Get("k"); ok {
		t.Fatal("an expired entry was served")
	}

	// A zero TTL disables caching entirely.
	disabled := newDecisionCache(0)
	disabled.Put("k", "v")
	if _, ok := disabled.Get("k"); ok {
		t.Fatal("caching should be off when the TTL is zero")
	}
}

// insecureCreds is the transport used for the in-memory test connection.
func insecureCreds() credentials.TransportCredentials {
	return insecure.NewCredentials()
}
