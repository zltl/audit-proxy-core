package terminal

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"

	sshproxyv1 "github.com/ssh-proxy-core/ssh-proxy-core/api/proto/sshproxy/v1"
	"github.com/ssh-proxy-core/ssh-proxy-core/internal/dp"
	"github.com/ssh-proxy-core/ssh-proxy-core/internal/pdp"
	"github.com/ssh-proxy-core/ssh-proxy-core/internal/telemetry"
)

// PolicyClient is the subset of the decision point a web terminal needs.
type PolicyClient interface {
	AuthorizeSession(context.Context, *sshproxyv1.AuthorizeSessionRequest) (*sshproxyv1.AuthorizeSessionResponse, error)
	OpenSession(context.Context, *sshproxyv1.OpenSessionRequest) (*sshproxyv1.OpenSessionResponse, error)
	CloseSession(context.Context, *sshproxyv1.CloseSessionRequest) (*sshproxyv1.CloseSessionResponse, error)
	HeartbeatSession(context.Context, *sshproxyv1.HeartbeatSessionRequest) (*sshproxyv1.HeartbeatSessionResponse, error)
	IssueUpstreamCredential(context.Context, *sshproxyv1.IssueUpstreamCredentialRequest) (*sshproxyv1.IssueUpstreamCredentialResponse, error)
	ResolveHostKey(context.Context, *sshproxyv1.ResolveHostKeyRequest) (*sshproxyv1.ResolveHostKeyResponse, error)
}

// Bridge opens in-process SSH sessions that follow the same policy path as the
// data plane without requiring the browser to speak SSH.
type Bridge struct {
	PDP                  PolicyClient
	NodeID               string
	RecordingDir         string
	RecordingKey         []byte
	CompressRecordings   bool
	CaptureKeystrokes    bool
	UpstreamDialTimeout  time.Duration
}

// ConnectRequest describes a browser terminal session.
type ConnectRequest struct {
	Username      string
	Roles         []string
	Target        string
	UpstreamLogin string
	SourceIP      string
	Cols          int
	Rows          int
}

// Session is an established upstream shell.
type Session struct {
	ID            string
	TargetHost    string
	UpstreamLogin string
	RecordingPath string
	client        *ssh.Client
	shell         *ssh.Session
	stdin         io.WriteCloser
	stdout        io.Reader
	recorder      *dp.Recorder
	pdp           PolicyClient
	nodeID        string
	bytesIn       int64
	bytesOut      int64
	startedAt     time.Time
	lastActivity  time.Time
	maxTTL        time.Duration
	idleTimeout   time.Duration
	cancelHB      context.CancelFunc
	closeOnce     sync.Once
}

func (b *Bridge) withDefaults() Bridge {
	if b.UpstreamDialTimeout <= 0 {
		b.UpstreamDialTimeout = 15 * time.Second
	}
	if b.NodeID == "" {
		b.NodeID = "control-plane"
	}
	return *b
}

// Connect authorizes and dials upstream.
func (b *Bridge) Connect(ctx context.Context, req ConnectRequest) (*Session, error) {
	cfg := b.withDefaults()
	if cfg.PDP == nil {
		return nil, fmt.Errorf("terminal: policy client is not configured")
	}
	target := strings.TrimSpace(req.Target)
	if target == "" {
		return nil, fmt.Errorf("terminal: target is required")
	}
	host, port := splitHostPort(target, 22)

	decision, err := cfg.PDP.AuthorizeSession(ctx, &sshproxyv1.AuthorizeSessionRequest{
		Client: &sshproxyv1.ClientInfo{
			NodeId:         cfg.NodeID,
			SourceIp:       req.SourceIP,
			ClientVersion:  "ssh-proxy-web-terminal/1.0",
		},
		Username:      req.Username,
		Roles:         req.Roles,
		Target:        target,
		TargetHost:    host,
		TargetPort:    int32(port),
		UpstreamLogin: req.UpstreamLogin,
	})
	if err != nil {
		return nil, fmt.Errorf("terminal: authorize session: %w", err)
	}
	if !decision.GetAllowed() {
		return nil, fmt.Errorf("access denied: %s", decision.GetReason())
	}
	if decision.GetApprovalRequired() {
		return nil, fmt.Errorf("access requires approval; request just-in-time access first")
	}
	if !featureAllowed(decision.GetFeatures(), "shell") || !featureAllowed(decision.GetFeatures(), "pty") {
		return nil, fmt.Errorf("policy does not permit an interactive shell on this target")
	}

	opened, err := cfg.PDP.OpenSession(ctx, &sshproxyv1.OpenSessionRequest{
		Client: &sshproxyv1.ClientInfo{
			NodeId:        cfg.NodeID,
			SourceIp:      req.SourceIP,
			ClientVersion: "ssh-proxy-web-terminal/1.0",
		},
		Username:      req.Username,
		TargetId:      decision.GetTargetId(),
		TargetHost:    decision.GetTargetHost(),
		TargetPort:    decision.GetTargetPort(),
		UpstreamLogin: decision.GetUpstreamLogin(),
		RuleId:        decision.GetRuleId(),
	})
	if err != nil {
		return nil, fmt.Errorf("terminal: open session: %w", err)
	}
	ctx = telemetry.SetSessionID(ctx, opened.GetSessionId())

	upTarget := upstreamTarget{
		SessionID: opened.GetSessionId(),
		TargetID:  decision.GetTargetId(),
		Host:      decision.GetTargetHost(),
		Port:      int(decision.GetTargetPort()),
		Login:     decision.GetUpstreamLogin(),
		Username:  req.Username,
	}

	client, err := dialUpstream(ctx, cfg.PDP, upTarget, cfg.UpstreamDialTimeout)
	if err != nil {
		_, _ = cfg.PDP.CloseSession(context.Background(), &sshproxyv1.CloseSessionRequest{
			SessionId: opened.GetSessionId(), TerminationInfo: "upstream dial failed",
		})
		return nil, err
	}

	shell, err := client.NewSession()
	if err != nil {
		_ = client.Close()
		_, _ = cfg.PDP.CloseSession(context.Background(), &sshproxyv1.CloseSessionRequest{
			SessionId: opened.GetSessionId(), TerminationInfo: "shell open failed",
		})
		return nil, fmt.Errorf("terminal: open shell: %w", err)
	}

	cols, rows := req.Cols, req.Rows
	if cols <= 0 {
		cols = 80
	}
	if rows <= 0 {
		rows = 24
	}
	modes := ssh.TerminalModes{
		ssh.ECHO:          1,
		ssh.TTY_OP_ISPEED: 14400,
		ssh.TTY_OP_OSPEED: 14400,
	}
	if err := shell.RequestPty("xterm-256color", rows, cols, modes); err != nil {
		_ = shell.Close()
		_ = client.Close()
		_, _ = cfg.PDP.CloseSession(context.Background(), &sshproxyv1.CloseSessionRequest{
			SessionId: opened.GetSessionId(), TerminationInfo: "pty request failed",
		})
		return nil, fmt.Errorf("terminal: request pty: %w", err)
	}
	stdin, err := shell.StdinPipe()
	if err != nil {
		_ = shell.Close()
		_ = client.Close()
		_, _ = cfg.PDP.CloseSession(context.Background(), &sshproxyv1.CloseSessionRequest{
			SessionId: opened.GetSessionId(), TerminationInfo: "stdin pipe failed",
		})
		return nil, err
	}
	stdout, err := shell.StdoutPipe()
	if err != nil {
		_ = shell.Close()
		_ = client.Close()
		_, _ = cfg.PDP.CloseSession(context.Background(), &sshproxyv1.CloseSessionRequest{
			SessionId: opened.GetSessionId(), TerminationInfo: "stdout pipe failed",
		})
		return nil, err
	}
	shell.Stderr = shell.Stdout
	if err := shell.Start("/bin/sh"); err != nil {
		if err := shell.Start("sh"); err != nil {
			_ = shell.Close()
			_ = client.Close()
			_, _ = cfg.PDP.CloseSession(context.Background(), &sshproxyv1.CloseSessionRequest{
				SessionId: opened.GetSessionId(), TerminationInfo: "shell start failed",
			})
			return nil, fmt.Errorf("terminal: start shell: %w", err)
		}
	}

	s := &Session{
		ID:            opened.GetSessionId(),
		TargetHost:    net.JoinHostPort(decision.GetTargetHost(), fmt.Sprintf("%d", decision.GetTargetPort())),
		UpstreamLogin: decision.GetUpstreamLogin(),
		client:        client,
		shell:         shell,
		stdin:         stdin,
		stdout:        stdout,
		pdp:           cfg.PDP,
		nodeID:        cfg.NodeID,
		startedAt:     time.Now(),
		lastActivity:  time.Now(),
		maxTTL:        time.Duration(decision.GetMaxSessionSeconds()) * time.Second,
		idleTimeout:   time.Duration(decision.GetIdleTimeoutSeconds()) * time.Second,
	}
	s.recorder = s.startRecording(cfg, decision, cols, rows)
	if s.recorder != nil {
		s.RecordingPath = s.recorder.Path()
	}

	hbCtx, cancel := context.WithCancel(context.Background())
	s.cancelHB = cancel
	go s.heartbeatLoop(hbCtx, req.SourceIP)

	return s, nil
}

func (s *Session) startRecording(cfg Bridge, decision *sshproxyv1.AuthorizeSessionResponse, cols, rows int) *dp.Recorder {
	if strings.TrimSpace(cfg.RecordingDir) == "" || decision.GetRecordPolicy() == sshproxyv1.RecordPolicy_RECORD_POLICY_NONE {
		return nil
	}
	started := time.Now()
	ext := recordingExtension(cfg.CompressRecordings, len(cfg.RecordingKey) > 0)
	path := fmt.Sprintf("%s/%s-%s%s", strings.TrimRight(cfg.RecordingDir, "/"),
		s.ID, started.UTC().Format("20060102T150405"), ext)
	rec, err := dp.NewRecorder(dp.RecorderOptions{
		Path:          path,
		Width:         cols,
		Height:        rows,
		Title:         fmt.Sprintf("Web terminal — %s@%s", s.UpstreamLogin, s.TargetHost),
		CaptureInput:  cfg.CaptureKeystrokes,
		StartedAt:     started,
		Compress:      cfg.CompressRecordings,
		EncryptionKey: cfg.RecordingKey,
		Env: map[string]string{
			"SSH_PROXY_SESSION": s.ID,
			"SSH_PROXY_CHANNEL": "web-terminal",
		},
	})
	if err != nil {
		log.Printf("terminal: session %s: recording failed: %v", s.ID, err)
		return nil
	}
	return rec
}

func recordingExtension(compress bool, encrypt bool) string {
	ext := ".cast"
	if compress {
		ext += ".gz"
	}
	if encrypt {
		ext += ".enc"
	}
	return ext
}

func (s *Session) touchActivity() {
	s.lastActivity = time.Now()
}

func (s *Session) heartbeatLoop(ctx context.Context, sourceIP string) {
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			resp, err := s.pdp.HeartbeatSession(ctx, &sshproxyv1.HeartbeatSessionRequest{
				SessionId: s.ID,
				BytesIn:   s.bytesIn,
				BytesOut:  s.bytesOut,
			})
			if err != nil {
				log.Printf("terminal: heartbeat %s: %v", s.ID, err)
			} else if resp.GetRevoked() {
				_ = s.Close(firstNonEmpty(resp.GetReason(), "revoked by an administrator"))
				return
			}
			now := time.Now()
			if s.maxTTL > 0 && now.Sub(s.startedAt) > s.maxTTL {
				_ = s.Close("maximum session duration reached")
				return
			}
			if s.idleTimeout > 0 && now.Sub(s.lastActivity) > s.idleTimeout {
				_ = s.Close("idle timeout")
				return
			}
		}
	}
}

// WriteInput sends keystrokes to the remote shell.
func (s *Session) WriteInput(p []byte) error {
	if len(p) == 0 {
		return nil
	}
	s.touchActivity()
	s.bytesIn += int64(len(p))
		if s.recorder != nil {
			s.recorder.Input(p)
		}
	_, err := s.stdin.Write(p)
	return err
}

// ReadOutput waits for upstream output.
func (s *Session) ReadOutput(buf []byte) (int, error) {
	n, err := s.stdout.Read(buf)
	if n > 0 {
		s.touchActivity()
		s.bytesOut += int64(n)
		if s.recorder != nil {
			s.recorder.Output(buf[:n])
		}
	}
	return n, err
}

// Resize updates the remote PTY geometry.
func (s *Session) Resize(cols, rows int) error {
	if cols <= 0 || rows <= 0 {
		return nil
	}
	return s.shell.WindowChange(rows, cols)
}

// Close ends the session and reports it to the decision point.
func (s *Session) Close(reason string) error {
	var err error
	s.closeOnce.Do(func() {
		if s.cancelHB != nil {
			s.cancelHB()
		}
		if s.recorder != nil {
			_ = s.recorder.Close()
		}
		if s.shell != nil {
			_ = s.shell.Close()
		}
		if s.client != nil {
			_ = s.client.Close()
		}
		_, err = s.pdp.CloseSession(context.Background(), &sshproxyv1.CloseSessionRequest{
			SessionId:       s.ID,
			TerminationInfo: reason,
			BytesIn:         s.bytesIn,
			BytesOut:        s.bytesOut,
			Status:          "closed",
			RecordingRef:    s.RecordingPath,
		})
	})
	return err
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

func featureAllowed(features []string, name string) bool {
	for _, f := range features {
		if strings.EqualFold(f, name) {
			return true
		}
	}
	return false
}

func splitHostPort(target string, defaultPort int) (string, int) {
	if host, portText, err := net.SplitHostPort(target); err == nil {
		port := defaultPort
		fmt.Sscanf(portText, "%d", &port)
		return host, port
	}
	return target, defaultPort
}

// Ensure Bridge accepts the concrete PDP server.
var _ PolicyClient = (*pdp.Server)(nil)

type upstreamTarget struct {
	SessionID string
	TargetID  string
	Host      string
	Port      int
	Login     string
	Username  string
}

func (t upstreamTarget) address() string {
	port := t.Port
	if port == 0 {
		port = 22
	}
	return net.JoinHostPort(t.Host, fmt.Sprintf("%d", port))
}

func dialUpstream(ctx context.Context, pdp PolicyClient, target upstreamTarget, timeout time.Duration) (*ssh.Client, error) {
	publicKey, ephemeral, err := generateEphemeralKey()
	if err != nil {
		return nil, err
	}
	cred, err := pdp.IssueUpstreamCredential(ctx, &sshproxyv1.IssueUpstreamCredentialRequest{
		SessionId:     target.SessionID,
		TargetId:      target.TargetID,
		UpstreamLogin: target.Login,
		Username:      target.Username,
		PublicKey:     publicKey,
	})
	if err != nil {
		return nil, fmt.Errorf("terminal: upstream credential: %w", err)
	}
	authMethods, err := buildAuthMethods(cred, ephemeral)
	if err != nil {
		return nil, err
	}
	clientConfig := &ssh.ClientConfig{
		User:            target.Login,
		Auth:            authMethods,
		Timeout:         timeout,
		HostKeyCallback: hostKeyCallback(ctx, pdp, target),
	}
	dialer := net.Dialer{Timeout: timeout}
	conn, err := dialer.DialContext(ctx, "tcp", target.address())
	if err != nil {
		return nil, fmt.Errorf("terminal: connect upstream: %w", err)
	}
	_ = conn.SetDeadline(time.Now().Add(timeout))
	sshConn, chans, reqs, err := ssh.NewClientConn(conn, target.address(), clientConfig)
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("terminal: upstream ssh handshake: %w", err)
	}
	_ = conn.SetDeadline(time.Time{})
	return ssh.NewClient(sshConn, chans, reqs), nil
}

func hostKeyCallback(ctx context.Context, pdp PolicyClient, target upstreamTarget) ssh.HostKeyCallback {
	return func(_ string, _ net.Addr, key ssh.PublicKey) error {
		req := &sshproxyv1.ResolveHostKeyRequest{
			TargetId:    target.TargetID,
			TargetHost:  target.Host,
			TargetPort:  int32(target.Port),
			Algorithm:   key.Type(),
			PublicKey:   base64.StdEncoding.EncodeToString(key.Marshal()),
			Fingerprint: ssh.FingerprintSHA256(key),
		}
		resp, err := pdp.ResolveHostKey(ctx, req)
		if err != nil {
			return err
		}
		if !resp.GetProceed() {
			return fmt.Errorf("refusing upstream host key: %s", resp.GetReason())
		}
		return nil
	}
}

func buildAuthMethods(cred *sshproxyv1.IssueUpstreamCredentialResponse, ephemeral ssh.Signer) ([]ssh.AuthMethod, error) {
	switch cred.GetKind() {
	case sshproxyv1.CredentialKind_CREDENTIAL_KIND_PASSWORD:
		return []ssh.AuthMethod{ssh.Password(cred.GetPassword())}, nil
	case sshproxyv1.CredentialKind_CREDENTIAL_KIND_PRIVATE_KEY:
		signer, err := ssh.ParsePrivateKey([]byte(cred.GetPrivateKey()))
		if err != nil {
			return nil, err
		}
		return []ssh.AuthMethod{ssh.PublicKeys(signer)}, nil
	case sshproxyv1.CredentialKind_CREDENTIAL_KIND_CERTIFICATE:
		parsed, _, _, _, err := ssh.ParseAuthorizedKey([]byte(cred.GetCertificate()))
		if err != nil {
			return nil, err
		}
		cert, ok := parsed.(*ssh.Certificate)
		if !ok {
			return nil, fmt.Errorf("expected certificate")
		}
		certSigner, err := ssh.NewCertSigner(cert, ephemeral)
		if err != nil {
			return nil, err
		}
		return []ssh.AuthMethod{ssh.PublicKeys(certSigner)}, nil
	default:
		reason := cred.GetReason()
		if reason == "" {
			reason = "no upstream credential issued"
		}
		return nil, fmt.Errorf("%s", reason)
	}
}

func generateEphemeralKey() (string, ssh.Signer, error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", nil, err
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		return "", nil, err
	}
	return string(ssh.MarshalAuthorizedKey(signer.PublicKey())), signer, nil
}

// ParseRecordingKey decodes a hex recording encryption key.
func ParseRecordingKey(spec string) ([]byte, error) {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return nil, nil
	}
	if strings.HasPrefix(spec, "file:") {
		data, err := os.ReadFile(strings.TrimPrefix(spec, "file:"))
		if err != nil {
			return nil, err
		}
		spec = strings.TrimSpace(string(data))
	}
	key, err := hex.DecodeString(spec)
	if err != nil {
		return nil, err
	}
	if len(key) != 32 {
		return nil, fmt.Errorf("recording key must be 32 bytes")
	}
	return key, nil
}
