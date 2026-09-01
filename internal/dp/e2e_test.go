package dp

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"

	sshproxyv1 "github.com/ssh-proxy-core/ssh-proxy-core/api/proto/sshproxy/v1"
	"github.com/ssh-proxy-core/ssh-proxy-core/internal/pdpclient"
)

// scriptedPDP is a decision point whose answers the test controls.
type scriptedPDP struct {
	sshproxyv1.UnimplementedAccessDecisionServiceServer

	mu sync.Mutex

	// authResult decides every Authenticate call.
	authResult sshproxyv1.AuthResult

	sessionAllowed  bool
	sessionReason   string
	sessionFeatures []string
	targetHost      string
	targetPort      int
	upstreamLogin   string
	commandPolicyID string
	recordPolicy    sshproxyv1.RecordPolicy

	// channelDenied names request payloads or channel types to refuse.
	channelDenied map[string]string

	commandResponses map[string]*sshproxyv1.AuthorizeCommandResponse

	hostKeyProceed bool
	hostKeyReason  string
	// seenHostKeys records fingerprints presented, proving the check happened.
	seenHostKeys []string

	credential *sshproxyv1.IssueUpstreamCredentialResponse

	openedSessions  []string
	closedSessions  []*sshproxyv1.CloseSessionRequest
	heartbeatRevoke bool
	heartbeatReason string

	revocations chan *sshproxyv1.Revocation
	events      []*sshproxyv1.AuditEvent
}

func newScriptedPDP() *scriptedPDP {
	return &scriptedPDP{
		authResult:       sshproxyv1.AuthResult_AUTH_RESULT_SUCCESS,
		sessionAllowed:   true,
		sessionFeatures:  []string{"shell", "exec", "pty", "env", "sftp", "subsystem"},
		hostKeyProceed:   true,
		recordPolicy:     sshproxyv1.RecordPolicy_RECORD_POLICY_FULL,
		channelDenied:    make(map[string]string),
		commandResponses: make(map[string]*sshproxyv1.AuthorizeCommandResponse),
		revocations:      make(chan *sshproxyv1.Revocation, 8),
		credential: &sshproxyv1.IssueUpstreamCredentialResponse{
			Kind:     sshproxyv1.CredentialKind_CREDENTIAL_KIND_PASSWORD,
			Password: "upstream-password",
		},
	}
}

func (p *scriptedPDP) Authenticate(_ context.Context, req *sshproxyv1.AuthenticateRequest) (*sshproxyv1.AuthenticateResponse, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.authResult != sshproxyv1.AuthResult_AUTH_RESULT_SUCCESS {
		return &sshproxyv1.AuthenticateResponse{Result: p.authResult, Reason: "refused by test"}, nil
	}
	return &sshproxyv1.AuthenticateResponse{
		Result:   sshproxyv1.AuthResult_AUTH_RESULT_SUCCESS,
		Username: req.GetUsername(),
		Roles:    []string{"operator"},
	}, nil
}

func (p *scriptedPDP) AuthorizeSession(_ context.Context, _ *sshproxyv1.AuthorizeSessionRequest) (*sshproxyv1.AuthorizeSessionResponse, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.sessionAllowed {
		return &sshproxyv1.AuthorizeSessionResponse{Allowed: false, Reason: p.sessionReason}, nil
	}
	return &sshproxyv1.AuthorizeSessionResponse{
		Allowed:         true,
		TargetId:        "tgt-1",
		TargetHost:      p.targetHost,
		TargetPort:      int32(p.targetPort),
		UpstreamLogin:   p.upstreamLogin,
		Features:        p.sessionFeatures,
		RecordPolicy:    p.recordPolicy,
		CommandPolicyId: p.commandPolicyID,
		RuleId:          "rule-1",
	}, nil
}

func (p *scriptedPDP) AuthorizeChannel(_ context.Context, req *sshproxyv1.AuthorizeChannelRequest) (*sshproxyv1.AuthorizeChannelResponse, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	key := req.GetChannelType().String()
	if reason, denied := p.channelDenied[key]; denied {
		return &sshproxyv1.AuthorizeChannelResponse{Allowed: false, Reason: reason}, nil
	}
	key = req.GetRequestType().String()
	if reason, denied := p.channelDenied[key]; denied {
		return &sshproxyv1.AuthorizeChannelResponse{Allowed: false, Reason: reason}, nil
	}
	return &sshproxyv1.AuthorizeChannelResponse{Allowed: true}, nil
}

func (p *scriptedPDP) AuthorizeCommand(req *sshproxyv1.AuthorizeCommandRequest, stream sshproxyv1.AccessDecisionService_AuthorizeCommandServer) error {
	p.mu.Lock()
	resp, ok := p.commandResponses[req.GetCommand()]
	p.mu.Unlock()
	if !ok {
		resp = &sshproxyv1.AuthorizeCommandResponse{
			Decision: sshproxyv1.CommandDecision_COMMAND_DECISION_ALLOW,
		}
	}
	return stream.Send(resp)
}

func (p *scriptedPDP) ResolveHostKey(_ context.Context, req *sshproxyv1.ResolveHostKeyRequest) (*sshproxyv1.ResolveHostKeyResponse, error) {
	p.mu.Lock()
	p.seenHostKeys = append(p.seenHostKeys, req.GetFingerprint())
	proceed, reason := p.hostKeyProceed, p.hostKeyReason
	p.mu.Unlock()
	verdict := sshproxyv1.HostKeyVerdict_HOST_KEY_VERDICT_TRUSTED
	if !proceed {
		verdict = sshproxyv1.HostKeyVerdict_HOST_KEY_VERDICT_REJECTED
	}
	return &sshproxyv1.ResolveHostKeyResponse{Verdict: verdict, Reason: reason, Proceed: proceed}, nil
}

func (p *scriptedPDP) IssueUpstreamCredential(_ context.Context, _ *sshproxyv1.IssueUpstreamCredentialRequest) (*sshproxyv1.IssueUpstreamCredentialResponse, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.credential, nil
}

func (p *scriptedPDP) OpenSession(_ context.Context, _ *sshproxyv1.OpenSessionRequest) (*sshproxyv1.OpenSessionResponse, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	id := fmt.Sprintf("sess-%d", len(p.openedSessions)+1)
	p.openedSessions = append(p.openedSessions, id)
	return &sshproxyv1.OpenSessionResponse{SessionId: id, Allowed: true}, nil
}

func (p *scriptedPDP) HeartbeatSession(_ context.Context, _ *sshproxyv1.HeartbeatSessionRequest) (*sshproxyv1.HeartbeatSessionResponse, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return &sshproxyv1.HeartbeatSessionResponse{Revoked: p.heartbeatRevoke, Reason: p.heartbeatReason}, nil
}

func (p *scriptedPDP) CloseSession(_ context.Context, req *sshproxyv1.CloseSessionRequest) (*sshproxyv1.CloseSessionResponse, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.closedSessions = append(p.closedSessions, req)
	return &sshproxyv1.CloseSessionResponse{}, nil
}

func (p *scriptedPDP) StreamRevocations(_ *sshproxyv1.StreamRevocationsRequest, stream sshproxyv1.AccessDecisionService_StreamRevocationsServer) error {
	for {
		select {
		case <-stream.Context().Done():
			return nil
		case rev := <-p.revocations:
			if err := stream.Send(rev); err != nil {
				return err
			}
		}
	}
}

func (p *scriptedPDP) closedRequests() []*sshproxyv1.CloseSessionRequest {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]*sshproxyv1.CloseSessionRequest(nil), p.closedSessions...)
}

func (p *scriptedPDP) hostKeysSeen() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]string(nil), p.seenHostKeys...)
}

// --------------------------------------------------------------------------
// Harness
// --------------------------------------------------------------------------

type harness struct {
	t        *testing.T
	proxy    *Server
	pdp      *scriptedPDP
	upstream *fakeUpstream
	addr     string
	recDir   string
}

func newHarness(t *testing.T, configure func(*Config, *scriptedPDP)) *harness {
	t.Helper()

	upstream := newFakeUpstream(t)
	host, port := upstream.addr()

	pdp := newScriptedPDP()
	pdp.targetHost = host
	pdp.targetPort = port
	pdp.upstreamLogin = "deploy"

	recDir := t.TempDir()
	cfg := DefaultConfig()
	cfg.NodeID = "node-test"
	cfg.RecordingDir = recDir
	cfg.HostKeyPaths = []string{writeTestHostKey(t)}
	cfg.HeartbeatInterval = 100 * time.Millisecond
	cfg.CaptureKeystrokes = true

	if configure != nil {
		configure(&cfg, pdp)
	}

	client := dialScriptedPDP(t, pdp)
	proxy, err := New(cfg, client)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = proxy.ServeListener(ctx, listener)
	}()
	t.Cleanup(func() {
		cancel()
		_ = proxy.Shutdown(context.Background())
		_ = listener.Close()
		<-done
	})

	return &harness{
		t:        t,
		proxy:    proxy,
		pdp:      pdp,
		upstream: upstream,
		addr:     listener.Addr().String(),
		recDir:   recDir,
	}
}

func dialScriptedPDP(t *testing.T, impl sshproxyv1.AccessDecisionServiceServer) *pdpclient.Client {
	t.Helper()
	listener := bufconn.Listen(1024 * 1024)
	server := grpc.NewServer()
	sshproxyv1.RegisterAccessDecisionServiceServer(server, impl)
	go func() { _ = server.Serve(listener) }()

	conn, err := grpc.NewClient("passthrough:///bufnet",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return listener.DialContext(ctx)
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatalf("grpc.NewClient: %v", err)
	}
	t.Cleanup(func() {
		_ = conn.Close()
		server.Stop()
		_ = listener.Close()
	})
	return pdpclient.NewWithConn(conn, pdpclient.Config{NodeID: "node-test", Address: "bufnet"})
}

func writeTestHostKey(t *testing.T) string {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate host key: %v", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatalf("marshal host key: %v", err)
	}
	path := filepath.Join(t.TempDir(), "host_key")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600); err != nil {
		t.Fatalf("write host key: %v", err)
	}
	return path
}

// connect opens an SSH client connection to the proxy.
func (h *harness) connect(user string) (*ssh.Client, error) {
	return ssh.Dial("tcp", h.addr, &ssh.ClientConfig{
		User:            user,
		Auth:            []ssh.AuthMethod{ssh.Password("client-password")},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         10 * time.Second,
	})
}

func (h *harness) mustConnect(user string) *ssh.Client {
	h.t.Helper()
	client, err := h.connect(user)
	if err != nil {
		h.t.Fatalf("connect as %q: %v", user, err)
	}
	h.t.Cleanup(func() { _ = client.Close() })
	return client
}

// --------------------------------------------------------------------------
// Tests
// --------------------------------------------------------------------------

func TestProxyRelaysExecAndExitStatus(t *testing.T) {
	h := newHarness(t, nil)
	client := h.mustConnect("alice@web-1")

	session, err := client.NewSession()
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}
	defer func() { _ = session.Close() }()

	output, err := session.Output("uptime")
	if err != nil {
		t.Fatalf("Output: %v", err)
	}
	if !strings.Contains(string(output), "ran: uptime") {
		t.Fatalf("output = %q", output)
	}
	if got := h.upstream.recordedExecs(); len(got) != 1 || got[0] != "uptime" {
		t.Fatalf("the upstream saw %v, want [uptime]", got)
	}
	if keys := h.pdp.hostKeysSeen(); len(keys) == 0 {
		t.Fatal("the upstream host key was never checked")
	}
}

func TestProxyRelaysStderrSeparately(t *testing.T) {
	h := newHarness(t, nil)
	client := h.mustConnect("alice@web-1")

	session, err := client.NewSession()
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}
	defer func() { _ = session.Close() }()

	stderr, err := session.StderrPipe()
	if err != nil {
		t.Fatalf("StderrPipe: %v", err)
	}
	if err := session.Start("failing-command"); err != nil {
		t.Fatalf("Start: %v", err)
	}
	data, _ := io.ReadAll(stderr)
	_ = session.Wait()

	// Standard error is a separate SSH stream; a proxy that only copies stdout
	// silently swallows every diagnostic a command produces.
	if !strings.Contains(string(data), "stderr: failing-command") {
		t.Fatalf("stderr = %q", data)
	}
}

func TestProxyHandlesConcurrentChannelsOnOneConnection(t *testing.T) {
	h := newHarness(t, nil)
	client := h.mustConnect("alice@web-1")

	// A single SSH connection routinely carries several channels at once. The
	// previous data plane served only the first, which broke multiplexing.
	const parallel = 8
	var wg sync.WaitGroup
	errs := make(chan error, parallel)
	for i := 0; i < parallel; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			session, err := client.NewSession()
			if err != nil {
				errs <- fmt.Errorf("session %d: %w", i, err)
				return
			}
			defer func() { _ = session.Close() }()
			command := fmt.Sprintf("command-%d", i)
			out, err := session.Output(command)
			if err != nil {
				errs <- fmt.Errorf("session %d output: %w", i, err)
				return
			}
			if !strings.Contains(string(out), "ran: "+command) {
				errs <- fmt.Errorf("session %d got %q", i, out)
			}
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}

	if got := len(h.upstream.recordedExecs()); got != parallel {
		t.Fatalf("the upstream ran %d commands, want %d", got, parallel)
	}
}

func TestProxyRelaysPTYAndShell(t *testing.T) {
	h := newHarness(t, nil)
	client := h.mustConnect("alice@web-1")

	session, err := client.NewSession()
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}
	defer func() { _ = session.Close() }()

	if err := session.RequestPty("xterm", 40, 120, ssh.TerminalModes{}); err != nil {
		t.Fatalf("RequestPty: %v", err)
	}
	stdin, err := session.StdinPipe()
	if err != nil {
		t.Fatalf("StdinPipe: %v", err)
	}
	stdout, err := session.StdoutPipe()
	if err != nil {
		t.Fatalf("StdoutPipe: %v", err)
	}
	if err := session.Shell(); err != nil {
		t.Fatalf("Shell: %v", err)
	}

	buf := make([]byte, len("upstream-shell-ready\n"))
	if _, err := io.ReadFull(stdout, buf); err != nil {
		t.Fatalf("read banner: %v", err)
	}
	if string(buf) != "upstream-shell-ready\n" {
		t.Fatalf("banner = %q", buf)
	}

	if _, err := stdin.Write([]byte("echo hello\n")); err != nil {
		t.Fatalf("write: %v", err)
	}
	echo := make([]byte, len("echo hello\n"))
	if _, err := io.ReadFull(stdout, echo); err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if string(echo) != "echo hello\n" {
		t.Fatalf("echo = %q", echo)
	}

	if h.upstream.ptyCount() != 1 {
		t.Fatalf("the upstream saw %d pty requests, want 1", h.upstream.ptyCount())
	}
	_ = stdin.Close()
}

func TestProxyWritesARecording(t *testing.T) {
	h := newHarness(t, nil)
	client := h.mustConnect("alice@web-1")

	session, err := client.NewSession()
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}
	if _, err := session.Output("uptime"); err != nil {
		t.Fatalf("Output: %v", err)
	}
	_ = session.Close()
	_ = client.Close()

	// The recording is closed when the channel ends; give that a moment.
	var recordings []string
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		entries, err := filepath.Glob(filepath.Join(h.recDir, "*.cast"))
		if err != nil {
			t.Fatalf("glob: %v", err)
		}
		if len(entries) > 0 {
			recordings = entries
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if len(recordings) == 0 {
		t.Fatal("no recording was written")
	}

	data, err := os.ReadFile(recordings[0])
	if err != nil {
		t.Fatalf("read recording: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) < 2 {
		t.Fatalf("recording has %d lines, expected a header and at least one event", len(lines))
	}
	if !strings.Contains(lines[0], `"version":2`) {
		t.Errorf("header = %q, want asciicast v2", lines[0])
	}
	if !strings.Contains(string(data), "ran: uptime") {
		t.Errorf("the recording does not contain the command output:\n%s", data)
	}

	info, err := os.Stat(recordings[0])
	if err != nil {
		t.Fatalf("stat recording: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("recording permissions are %o; a transcript of a privileged session must not be world readable", perm)
	}
}

func TestRecordingDisabledByPolicy(t *testing.T) {
	h := newHarness(t, func(_ *Config, pdp *scriptedPDP) {
		pdp.recordPolicy = sshproxyv1.RecordPolicy_RECORD_POLICY_NONE
	})
	client := h.mustConnect("alice@web-1")

	session, err := client.NewSession()
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}
	if _, err := session.Output("uptime"); err != nil {
		t.Fatalf("Output: %v", err)
	}
	_ = session.Close()

	entries, _ := filepath.Glob(filepath.Join(h.recDir, "*.cast"))
	if len(entries) != 0 {
		t.Fatalf("a recording was written despite the policy saying not to: %v", entries)
	}
}

func TestSessionRefusedWhenPolicyDenies(t *testing.T) {
	h := newHarness(t, func(_ *Config, pdp *scriptedPDP) {
		pdp.sessionAllowed = false
		pdp.sessionReason = "no rule permits this target"
	})

	client, err := h.connect("alice@web-1")
	if err != nil {
		// Refusing during the handshake is acceptable too.
		return
	}
	defer func() { _ = client.Close() }()

	_, err = client.NewSession()
	if err == nil {
		t.Fatal("a session was opened despite the policy refusing")
	}
	if !strings.Contains(err.Error(), "no rule permits this target") {
		t.Errorf("the client should be told why, got %v", err)
	}
}

func TestUpstreamRefusedWhenHostKeyIsNotTrusted(t *testing.T) {
	h := newHarness(t, func(_ *Config, pdp *scriptedPDP) {
		pdp.hostKeyProceed = false
		pdp.hostKeyReason = "host key does not match any key pinned for this target"
	})

	client, err := h.connect("alice@web-1")
	if err != nil {
		return
	}
	defer func() { _ = client.Close() }()

	if _, err := client.NewSession(); err == nil {
		t.Fatal("the proxy connected to a target whose host key it could not verify")
	}
}

func TestChannelRefusedWhenPolicyDenies(t *testing.T) {
	h := newHarness(t, func(_ *Config, pdp *scriptedPDP) {
		pdp.channelDenied["CHANNEL_REQUEST_EXEC"] = "policy does not permit exec on this session"
	})
	client := h.mustConnect("alice@web-1")

	session, err := client.NewSession()
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}
	defer func() { _ = session.Close() }()

	if err := session.Run("uptime"); err == nil {
		t.Fatal("exec ran despite the policy refusing it")
	}
	if got := h.upstream.recordedExecs(); len(got) != 0 {
		t.Fatalf("a refused command still reached the upstream: %v", got)
	}
}

func TestLocalForwardIsGatedAndProxied(t *testing.T) {
	t.Run("denied", func(t *testing.T) {
		h := newHarness(t, func(_ *Config, pdp *scriptedPDP) {
			pdp.channelDenied["CHANNEL_TYPE_DIRECT_TCPIP"] = "port forwarding is not permitted"
		})
		client := h.mustConnect("alice@web-1")

		if _, err := client.Dial("tcp", "10.0.0.9:5432"); err == nil {
			t.Fatal("a forward was opened despite the policy refusing it")
		}
		if got := h.upstream.recordedForwards(); len(got) != 0 {
			t.Fatalf("a refused forward still reached the upstream: %v", got)
		}
	})

	t.Run("allowed", func(t *testing.T) {
		h := newHarness(t, nil)
		client := h.mustConnect("alice@web-1")

		conn, err := client.Dial("tcp", "10.0.0.9:5432")
		if err != nil {
			t.Fatalf("Dial through the proxy: %v", err)
		}
		defer func() { _ = conn.Close() }()

		if _, err := conn.Write([]byte("ping")); err != nil {
			t.Fatalf("write through the tunnel: %v", err)
		}
		buf := make([]byte, 4)
		if _, err := io.ReadFull(conn, buf); err != nil {
			t.Fatalf("read through the tunnel: %v", err)
		}
		if string(buf) != "ping" {
			t.Fatalf("tunnel echoed %q", buf)
		}
		if got := h.upstream.recordedForwards(); len(got) != 1 || got[0] != "10.0.0.9:5432" {
			t.Fatalf("the upstream saw forwards %v", got)
		}
	})
}

func TestCommandDenyBlocksBeforeReachingTheTarget(t *testing.T) {
	h := newHarness(t, func(_ *Config, pdp *scriptedPDP) {
		pdp.commandPolicyID = "cp-1"
		pdp.commandResponses["rm -rf /"] = &sshproxyv1.AuthorizeCommandResponse{
			Decision: sshproxyv1.CommandDecision_COMMAND_DECISION_DENY,
			Reason:   "refusing a recursive delete of the root filesystem",
		}
	})
	client := h.mustConnect("alice@web-1")

	session, err := client.NewSession()
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}
	defer func() { _ = session.Close() }()

	if err := session.Run("rm -rf /"); err == nil {
		t.Fatal("a denied command was reported as having succeeded")
	}
	// Blocking only counts if the command never runs.
	if got := h.upstream.recordedExecs(); len(got) != 0 {
		t.Fatalf("a denied command reached the target: %v", got)
	}
}

func TestCommandRewriteChangesWhatRuns(t *testing.T) {
	h := newHarness(t, func(_ *Config, pdp *scriptedPDP) {
		pdp.commandPolicyID = "cp-1"
		pdp.commandResponses["shutdown -h now"] = &sshproxyv1.AuthorizeCommandResponse{
			Decision:         sshproxyv1.CommandDecision_COMMAND_DECISION_REWRITE,
			RewrittenCommand: "echo refused",
		}
	})
	client := h.mustConnect("alice@web-1")

	session, err := client.NewSession()
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}
	defer func() { _ = session.Close() }()

	if _, err := session.Output("shutdown -h now"); err != nil {
		t.Fatalf("Output: %v", err)
	}
	got := h.upstream.recordedExecs()
	if len(got) != 1 || got[0] != "echo refused" {
		t.Fatalf("the upstream ran %v, want the rewritten command", got)
	}
}

func TestRevocationDisconnectsTheSession(t *testing.T) {
	h := newHarness(t, nil)
	client := h.mustConnect("alice@web-1")

	session, err := client.NewSession()
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}
	stdout, err := session.StdoutPipe()
	if err != nil {
		t.Fatalf("StdoutPipe: %v", err)
	}
	if err := session.Shell(); err != nil {
		t.Fatalf("Shell: %v", err)
	}
	// Wait until the session is established before revoking it.
	buf := make([]byte, len("upstream-shell-ready\n"))
	if _, err := io.ReadFull(stdout, buf); err != nil {
		t.Fatalf("read banner: %v", err)
	}

	h.pdp.mu.Lock()
	sessionID := h.pdp.openedSessions[0]
	h.pdp.mu.Unlock()
	h.pdp.revocations <- &sshproxyv1.Revocation{
		SessionId: sessionID, Reason: "terminated by an administrator",
	}

	// The connection must actually be closed, not merely marked.
	closed := make(chan struct{})
	go func() {
		_ = client.Wait()
		close(closed)
	}()
	select {
	case <-closed:
	case <-time.After(10 * time.Second):
		t.Fatal("the session was not disconnected after being revoked")
	}
}

func TestSessionCloseIsReported(t *testing.T) {
	h := newHarness(t, nil)
	client := h.mustConnect("alice@web-1")

	session, err := client.NewSession()
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}
	if _, err := session.Output("uptime"); err != nil {
		t.Fatalf("Output: %v", err)
	}
	_ = session.Close()
	_ = client.Close()

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if len(h.pdp.closedRequests()) > 0 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	closed := h.pdp.closedRequests()
	if len(closed) == 0 {
		t.Fatal("the end of the session was never reported; it would appear active forever")
	}
	if closed[0].GetBytesOut() == 0 {
		t.Error("the close report carries no byte counters")
	}
	if closed[0].GetRecordingRef() == "" {
		t.Error("the close report does not reference the recording, so it could not be found later")
	}
}

func TestDrainStopsNewConnectionsButKeepsExistingOnes(t *testing.T) {
	h := newHarness(t, nil)
	client := h.mustConnect("alice@web-1")

	// Establish a session that must survive the drain.
	session, err := client.NewSession()
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}
	stdout, err := session.StdoutPipe()
	if err != nil {
		t.Fatalf("StdoutPipe: %v", err)
	}
	if err := session.Shell(); err != nil {
		t.Fatalf("Shell: %v", err)
	}
	buf := make([]byte, len("upstream-shell-ready\n"))
	if _, err := io.ReadFull(stdout, buf); err != nil {
		t.Fatalf("read banner: %v", err)
	}

	h.proxy.Drain()
	if !h.proxy.Draining() {
		t.Fatal("Draining() should report true after Drain()")
	}

	if _, err := h.connect("bob@web-1"); err == nil {
		t.Fatal("a new connection was accepted while draining")
	}

	// The established session must still work; that is the point of draining
	// rather than stopping.
	other, err := client.NewSession()
	if err != nil {
		t.Fatalf("an established connection stopped working during a drain: %v", err)
	}
	out, err := other.Output("still-working")
	if err != nil {
		t.Fatalf("Output during drain: %v", err)
	}
	if !strings.Contains(string(out), "ran: still-working") {
		t.Fatalf("output = %q", out)
	}
	_ = other.Close()
}

func TestAuthenticationFailureIsRejected(t *testing.T) {
	h := newHarness(t, func(_ *Config, pdp *scriptedPDP) {
		pdp.authResult = sshproxyv1.AuthResult_AUTH_RESULT_FAILURE
	})

	if _, err := h.connect("alice@web-1"); err == nil {
		t.Fatal("a connection was accepted despite authentication failing")
	} else if !strings.Contains(err.Error(), "unable to authenticate") {
		t.Logf("rejection error: %v", err)
	}
}

func TestParseLoginSpec(t *testing.T) {
	cases := []struct {
		input string
		want  loginSpec
	}{
		{"alice", loginSpec{Principal: "alice"}},
		{"alice@web-1", loginSpec{Principal: "alice", Target: "web-1"}},
		{"alice%root@web-1", loginSpec{Principal: "alice", Login: "root", Target: "web-1"}},
		{"alice@10.0.1.10:2222", loginSpec{Principal: "alice", Target: "10.0.1.10:2222"}},
		{"", loginSpec{}},
	}
	for _, tc := range cases {
		got := parseLoginSpec(tc.input)
		if got != tc.want {
			t.Errorf("parseLoginSpec(%q) = %+v, want %+v", tc.input, got, tc.want)
		}
	}
}

func TestConfigValidation(t *testing.T) {
	cases := []struct {
		name string
		cfg  Config
		want string
	}{
		{"no node id", Config{HostKeyPaths: []string{"/x"}}, "node id"},
		{"no host key", Config{NodeID: "n1"}, "host key"},
		{"bad version string", Config{NodeID: "n1", HostKeyPaths: []string{"/x"}, ServerVersion: "MyProxy"},
			"SSH-2.0-"},
	}
	for _, tc := range cases {
		err := tc.cfg.withDefaults().Validate()
		if tc.name == "bad version string" {
			// withDefaults must not overwrite an explicitly wrong value.
			cfg := tc.cfg
			cfg.ServerVersion = "MyProxy"
			err = cfg.Validate()
		}
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: error = %v, want it to mention %q", tc.name, err, tc.want)
		}
	}
}

func TestNewRejectsMissingHostKey(t *testing.T) {
	cfg := DefaultConfig()
	cfg.NodeID = "n1"
	cfg.HostKeyPaths = []string{filepath.Join(t.TempDir(), "does-not-exist")}

	_, err := New(cfg, dialScriptedPDP(t, newScriptedPDP()))
	if err == nil {
		t.Fatal("a missing host key should be reported at startup, not at the first connection")
	}
	if !errors.Is(err, os.ErrNotExist) && !strings.Contains(err.Error(), "read host key") {
		t.Errorf("error = %v", err)
	}
}

func TestConnectionServesChannelsSequentially(t *testing.T) {
	h := newHarness(t, nil)
	client := h.mustConnect("alice@web-1")

	// Connection reuse is what OpenSSH's ControlMaster depends on: one channel
	// finishes and closes, and a later one has to open on the same connection.
	// A proxy that tears down the connection with its first channel appears to
	// work in simple tests and then breaks every multiplexed client.
	for i := 0; i < 4; i++ {
		session, err := client.NewSession()
		if err != nil {
			t.Fatalf("session %d could not be opened on the existing connection: %v", i, err)
		}
		command := fmt.Sprintf("sequential-%d", i)
		out, err := session.Output(command)
		if err != nil {
			t.Fatalf("session %d: %v", i, err)
		}
		if !strings.Contains(string(out), "ran: "+command) {
			t.Fatalf("session %d output = %q", i, out)
		}
		if err := session.Close(); err != nil && !errors.Is(err, io.EOF) {
			t.Fatalf("session %d close: %v", i, err)
		}
	}

	if got := len(h.upstream.recordedExecs()); got != 4 {
		t.Fatalf("the upstream ran %d commands, want 4", got)
	}
	// One client connection must map to one upstream connection, not one per
	// channel: otherwise every new shell re-authenticates to the target.
	h.pdp.mu.Lock()
	opened := len(h.pdp.openedSessions)
	h.pdp.mu.Unlock()
	if opened != 1 {
		t.Fatalf("%d sessions were registered for one connection, want 1", opened)
	}
}

func TestExitStatusReachesTheClient(t *testing.T) {
	h := newHarness(t, nil)
	client := h.mustConnect("alice@web-1")

	// A command that succeeded must not be reported as having failed. The exit
	// status travels as a channel request rather than as data, so it is easy to
	// lose to a teardown race and hard to notice without asserting on it.
	for i := 0; i < 5; i++ {
		session, err := client.NewSession()
		if err != nil {
			t.Fatalf("NewSession: %v", err)
		}
		if err := session.Run("uptime"); err != nil {
			t.Fatalf("attempt %d: a successful command reported %v", i, err)
		}
		_ = session.Close()
	}
}
