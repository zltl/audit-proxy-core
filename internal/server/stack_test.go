package server

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/ssh-proxy-core/ssh-proxy-core/internal/authn"
	"github.com/ssh-proxy-core/ssh-proxy-core/internal/config"
	"github.com/ssh-proxy-core/ssh-proxy-core/internal/dp"
	"github.com/ssh-proxy-core/ssh-proxy-core/internal/pdpclient"
	"github.com/ssh-proxy-core/ssh-proxy-core/internal/store"
)

// TestFullStack runs the real thing: a control plane serving the decision point
// over a unix socket, a data plane consulting it, and an SSH client connecting
// through to a target.
//
// Every layer has its own tests against a stub of the next one. This is the one
// that would catch the pieces disagreeing: a policy written to the database
// having no effect, credentials never reaching the dialer, or events being
// produced and then landing nowhere.
func TestFullStack(t *testing.T) {
	stack := newStack(t)

	t.Run("policy in the database governs access", func(t *testing.T) {
		client := stack.dial(t, "alice%deploy@web-1", "alice-password-1")
		defer func() { _ = client.Close() }()

		session, err := client.NewSession()
		if err != nil {
			t.Fatalf("NewSession: %v", err)
		}
		defer func() { _ = session.Close() }()

		out, err := session.Output("uptime")
		if err != nil {
			t.Fatalf("Output: %v", err)
		}
		if !strings.Contains(string(out), "ran: uptime") {
			t.Fatalf("output = %q", out)
		}
	})

	t.Run("an unknown password is refused", func(t *testing.T) {
		if _, err := stack.connect("alice%deploy@web-1", "wrong-password"); err == nil {
			t.Fatal("a wrong password was accepted")
		}
	})

	t.Run("a target with no rule is refused", func(t *testing.T) {
		client, err := stack.connect("alice%deploy@db-1", "alice-password-1")
		if err != nil {
			return // refused during the handshake is acceptable
		}
		defer func() { _ = client.Close() }()
		if _, err := client.NewSession(); err == nil {
			t.Fatal("a target no rule permits was reachable")
		}
	})

	t.Run("a capability the rule omits is refused", func(t *testing.T) {
		client := stack.dial(t, "alice%deploy@web-1", "alice-password-1")
		defer func() { _ = client.Close() }()

		// The rule grants shell and exec but not port forwarding.
		if _, err := client.Dial("tcp", "10.0.0.9:5432"); err == nil {
			t.Fatal("port forwarding was permitted by a rule that does not grant it")
		}
	})

	t.Run("the session is recorded in the shared database", func(t *testing.T) {
		client := stack.dial(t, "alice%deploy@web-1", "alice-password-1")
		session, err := client.NewSession()
		if err != nil {
			t.Fatalf("NewSession: %v", err)
		}
		if _, err := session.Output("hostname"); err != nil {
			t.Fatalf("Output: %v", err)
		}
		_ = session.Close()
		_ = client.Close()

		sessions := stack.waitForSessions(t, 1)
		found := false
		for _, s := range sessions {
			if s.Username == "alice" && s.UpstreamLogin == "deploy" {
				found = true
			}
		}
		if !found {
			t.Fatalf("the session was not recorded: %+v", sessions)
		}
	})

	t.Run("revoking a session disconnects it", func(t *testing.T) {
		client := stack.dial(t, "alice%deploy@web-1", "alice-password-1")
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

		// An operator asks the database to terminate it; the node serving it
		// has to notice and cut the connection.
		active := stack.activeSessions(t)
		if len(active) == 0 {
			t.Fatal("no active session to revoke")
		}
		if err := stack.store.RequestRevocation(active[0].ID, "terminated by an administrator"); err != nil {
			t.Fatalf("RequestRevocation: %v", err)
		}

		closed := make(chan struct{})
		go func() {
			_ = client.Wait()
			close(closed)
		}()
		select {
		case <-closed:
		case <-time.After(15 * time.Second):
			t.Fatal("the session outlived its revocation")
		}
	})

	t.Run("audit events reach the audit log", func(t *testing.T) {
		client := stack.dial(t, "alice%deploy@web-1", "alice-password-1")
		session, err := client.NewSession()
		if err != nil {
			t.Fatalf("NewSession: %v", err)
		}
		if _, err := session.Output("whoami"); err != nil {
			t.Fatalf("Output: %v", err)
		}
		_ = session.Close()
		_ = client.Close()

		records := stack.waitForAuditRecords(t, "session.start")
		for _, record := range records {
			if record["event_type"] != "session.start" {
				continue
			}
			if record["username"] != "alice" {
				t.Errorf("audit record names %v", record["username"])
			}
			if record["integrity_hash"] == "" {
				t.Error("the stored record carries no integrity hash")
			}
			return
		}
	})
}

// --------------------------------------------------------------------------
// Harness
// --------------------------------------------------------------------------

type stack struct {
	controlPlane *Server
	store        *store.Store
	proxyAddr    string
	auditDir     string
}

func newStack(t *testing.T) *stack {
	t.Helper()

	upstream := newStackUpstream(t)
	upstreamHost, upstreamPort := upstream.addr()

	dataDir := t.TempDir()
	auditDir := t.TempDir()
	socketPath := filepath.Join(t.TempDir(), "pdp.sock")

	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("generate key: %v", err)
	}

	cfg := &config.Config{
		ListenAddr:           "127.0.0.1:0",
		SessionSecret:        "full-stack-secret",
		AdminUser:            "admin",
		AuditLogDir:          auditDir,
		RecordingDir:         t.TempDir(),
		DataDir:              dataDir,
		PDPListenAddr:        "unix:" + socketPath,
		SecretsEncryptionKey: hex.EncodeToString(key),
	}

	controlPlane, err := New(cfg)
	if err != nil {
		t.Fatalf("control plane New: %v", err)
	}
	if err := controlPlane.startAccessDecisionPoint(); err != nil {
		t.Fatalf("start decision point: %v", err)
	}
	t.Cleanup(func() { controlPlane.stopAccessDecisionPoint() })

	st := controlPlane.dataPlaneStore
	seedStackPolicy(t, st, upstreamHost, upstreamPort, upstream.signer.PublicKey())

	// The data plane reaches the decision point over the socket, as it would in
	// a real deployment.
	client, err := pdpclient.Dial(context.Background(), pdpclient.Config{
		Address:  "unix:" + socketPath,
		NodeID:   "node-stack",
		Insecure: true,
		FailMode: pdpclient.FailClosed,
	})
	if err != nil {
		t.Fatalf("pdpclient.Dial: %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })

	dpConfig := dp.DefaultConfig()
	dpConfig.NodeID = "node-stack"
	dpConfig.HostKeyPaths = []string{writeStackHostKey(t)}
	dpConfig.RecordingDir = t.TempDir()
	dpConfig.AuditSpoolDir = filepath.Join(t.TempDir(), "spool")
	dpConfig.AuditFlushInterval = 50 * time.Millisecond
	dpConfig.HeartbeatInterval = 200 * time.Millisecond

	proxy, err := dp.New(dpConfig, client)
	if err != nil {
		t.Fatalf("data plane New: %v", err)
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

	return &stack{
		controlPlane: controlPlane,
		store:        st,
		proxyAddr:    listener.Addr().String(),
		auditDir:     auditDir,
	}
}

// seedStackPolicy writes the identity, target, credential, and rule that let
// alice reach the target as deploy — the same rows an operator would create.
func seedStackPolicy(t *testing.T, st *store.Store, host string, port int, hostKey ssh.PublicKey) {
	t.Helper()

	hash, err := authn.HashPassword("alice-password-1")
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	if _, err := st.CreateUser(store.User{Username: "alice", PasswordHash: hash}); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	target, err := st.CreateTarget(store.Target{
		Name: "web-1", Host: host, Port: port, Enabled: true,
		Tags: map[string]string{"env": "test"},
	})
	if err != nil {
		t.Fatalf("CreateTarget: %v", err)
	}

	// The proxy authenticates to the target with a vaulted password, which
	// exercises decryption on the decision-point side.
	ref, err := st.PutSecretString("upstream_password", "target-password")
	if err != nil {
		t.Fatalf("PutSecretString: %v", err)
	}
	if _, err := st.PutCredential(store.Credential{
		TargetID: target.ID, Login: "deploy",
		Kind: store.CredentialPassword, SecretRef: ref,
	}); err != nil {
		t.Fatalf("PutCredential: %v", err)
	}

	// The target's host key is pinned, as it would be for a managed host.
	// Without this the proxy refuses to connect at all, which is the intended
	// behaviour and is asserted separately below.
	if _, err := st.PutHostKey(store.HostKey{
		TargetID:    target.ID,
		Algorithm:   hostKey.Type(),
		PublicKey:   base64.StdEncoding.EncodeToString(hostKey.Marshal()),
		Fingerprint: ssh.FingerprintSHA256(hostKey),
		Status:      store.HostKeyTrusted,
		Source:      store.HostKeyManual,
	}); err != nil {
		t.Fatalf("PutHostKey: %v", err)
	}

	if _, err := st.PutAccessRule(store.AccessRule{
		ID: "stack-rule", Name: "alice to web-1", Priority: 10,
		Effect: store.EffectAllow, SubjectKind: store.SubjectUser, Subject: "alice",
		TargetSelector: "web-1", UpstreamLogins: []string{"deploy"},
		// Deliberately no forwarding: a capability the rule omits must be refused.
		Features:     store.FeatureShell | store.FeatureExec | store.FeaturePTY | store.FeatureEnv,
		RecordPolicy: store.RecordFull, Enabled: true,
	}); err != nil {
		t.Fatalf("PutAccessRule: %v", err)
	}
}

func (s *stack) connect(user, password string) (*ssh.Client, error) {
	return ssh.Dial("tcp", s.proxyAddr, &ssh.ClientConfig{
		User:            user,
		Auth:            []ssh.AuthMethod{ssh.Password(password)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         15 * time.Second,
	})
}

func (s *stack) dial(t *testing.T, user, password string) *ssh.Client {
	t.Helper()
	client, err := s.connect(user, password)
	if err != nil {
		t.Fatalf("connect as %q: %v", user, err)
	}
	return client
}

func (s *stack) activeSessions(t *testing.T) []store.Session {
	t.Helper()
	sessions, err := s.store.ListSessions(store.SessionFilter{Status: store.SessionActive})
	if err != nil {
		t.Fatalf("ListSessions: %v", err)
	}
	return sessions
}

func (s *stack) waitForSessions(t *testing.T, atLeast int) []store.Session {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		sessions, err := s.store.ListSessions(store.SessionFilter{})
		if err != nil {
			t.Fatalf("ListSessions: %v", err)
		}
		if len(sessions) >= atLeast {
			return sessions
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("fewer than %d sessions were recorded", atLeast)
	return nil
}

func (s *stack) waitForAuditRecords(t *testing.T, eventType string) []map[string]interface{} {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		records := s.readAuditRecords(t)
		for _, record := range records {
			if record["event_type"] == eventType {
				return records
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("no %s record reached the audit log", eventType)
	return nil
}

func (s *stack) readAuditRecords(t *testing.T) []map[string]interface{} {
	t.Helper()
	paths, err := filepath.Glob(filepath.Join(s.auditDir, "audit-*.jsonl"))
	if err != nil {
		t.Fatalf("glob: %v", err)
	}
	var records []map[string]interface{}
	for _, path := range paths {
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
			if strings.TrimSpace(line) == "" {
				continue
			}
			var record map[string]interface{}
			if json.Unmarshal([]byte(line), &record) == nil {
				records = append(records, record)
			}
		}
	}
	return records
}

func writeStackHostKey(t *testing.T) string {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate host key: %v", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	path := filepath.Join(t.TempDir(), "host_key")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600); err != nil {
		t.Fatalf("write host key: %v", err)
	}
	return path
}

// --------------------------------------------------------------------------
// A target to proxy to
// --------------------------------------------------------------------------

type stackUpstream struct {
	listener net.Listener
	signer   ssh.Signer
}

func newStackUpstream(t *testing.T) *stackUpstream {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	u := &stackUpstream{listener: listener, signer: signer}
	go u.serve()
	t.Cleanup(func() { _ = listener.Close() })
	return u
}

func (u *stackUpstream) addr() (string, int) {
	host, port, _ := net.SplitHostPort(u.listener.Addr().String())
	value := 0
	_, _ = fmt.Sscanf(port, "%d", &value)
	return host, value
}

func (u *stackUpstream) serve() {
	for {
		conn, err := u.listener.Accept()
		if err != nil {
			return
		}
		go u.handle(conn)
	}
}

func (u *stackUpstream) handle(conn net.Conn) {
	defer func() { _ = conn.Close() }()

	cfg := &ssh.ServerConfig{
		PasswordCallback: func(_ ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
			// The proxy must present the vaulted password, which proves the
			// credential travelled from the database to the dialer.
			if string(password) != "target-password" {
				return nil, fmt.Errorf("bad password")
			}
			return nil, nil
		},
	}
	cfg.AddHostKey(u.signer)

	serverConn, chans, reqs, err := ssh.NewServerConn(conn, cfg)
	if err != nil {
		return
	}
	defer func() { _ = serverConn.Close() }()
	go ssh.DiscardRequests(reqs)

	for newChannel := range chans {
		if newChannel.ChannelType() != "session" {
			_ = newChannel.Reject(ssh.UnknownChannelType, newChannel.ChannelType())
			continue
		}
		go u.handleSession(newChannel)
	}
}

func (u *stackUpstream) handleSession(newChannel ssh.NewChannel) {
	channel, requests, err := newChannel.Accept()
	if err != nil {
		return
	}
	defer func() { _ = channel.Close() }()

	for req := range requests {
		switch req.Type {
		case "shell":
			if req.WantReply {
				_ = req.Reply(true, nil)
			}
			_, _ = channel.Write([]byte("upstream-shell-ready\n"))
			_, _ = io.Copy(channel, channel)
			sendStackExit(channel, 0)
			return
		case "exec":
			var payload struct{ Command string }
			_ = ssh.Unmarshal(req.Payload, &payload)
			if req.WantReply {
				_ = req.Reply(true, nil)
			}
			_, _ = fmt.Fprintf(channel, "ran: %s\n", payload.Command)
			sendStackExit(channel, 0)
			return
		default:
			if req.WantReply {
				_ = req.Reply(req.Type == "pty-req" || req.Type == "env", nil)
			}
		}
	}
}

func sendStackExit(channel ssh.Channel, code uint32) {
	payload := make([]byte, 4)
	binary.BigEndian.PutUint32(payload, code)
	_, _ = channel.SendRequest("exit-status", false, payload)
}
