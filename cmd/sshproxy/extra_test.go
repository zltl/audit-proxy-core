package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestClientUnwrapsEnvelope(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"success": true,
			"data":    map[string]string{"status": "healthy"},
		})
	}))
	defer ts.Close()

	client := NewClientFromConfig(ClientConfig{Server: ts.URL, Token: "tk"})
	data, err := client.Get("/api/v2/system/health")
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	if !strings.Contains(string(data), `"status":"healthy"`) {
		t.Fatalf("expected unwrapped data, got %s", string(data))
	}
}

func TestClientConfigSSHAddrFromEnv(t *testing.T) {
	t.Setenv("SSHPROXY_SSH_ADDR", "proxy.example.com:2222")
	cfg := loadConfig()
	if cfg.SSHAddr != "proxy.example.com:2222" {
		t.Fatalf("expected ssh addr from env, got %q", cfg.SSHAddr)
	}
}

func TestPlayAsciicastNoTiming(t *testing.T) {
	recording := strings.Join([]string{
		`{"version":2,"width":80,"height":24,"timestamp":1710000000}`,
		`[0.1,"o","hello "]`,
		`[0.2,"i","ignored"]`,
		`[0.3,"o","world"]`,
		"",
	}, "\n")

	var out bytes.Buffer
	if err := playAsciicast(strings.NewReader(recording), &out, 1.0, false, false); err != nil {
		t.Fatalf("playAsciicast() error = %v", err)
	}
	if out.String() != "hello world" {
		t.Fatalf("unexpected playback output: %q", out.String())
	}
}

func TestProxyStream(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen() error = %v", err)
	}
	defer ln.Close()

	serverErr := make(chan error, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			serverErr <- err
			return
		}
		defer conn.Close()

		buf := make([]byte, 4)
		if _, err := io.ReadFull(conn, buf); err != nil {
			serverErr <- err
			return
		}
		if _, err := conn.Write([]byte("pong")); err != nil {
			serverErr <- err
			return
		}
		serverErr <- nil
	}()

	var stdout bytes.Buffer
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := proxyStream(ctx, ln.Addr().String(), bytes.NewBufferString("ping"), &stdout); err != nil {
		t.Fatalf("proxyStream() error = %v", err)
	}
	if err := <-serverErr; err != nil {
		t.Fatalf("server error = %v", err)
	}
	if stdout.String() != "pong" {
		t.Fatalf("unexpected proxy output: %q", stdout.String())
	}
}

func TestCompletionScript(t *testing.T) {
	script, err := completionScript("bash")
	if err != nil {
		t.Fatalf("completionScript() error = %v", err)
	}
	if !strings.Contains(script, "proxycommand") || !strings.Contains(script, "completion") || !strings.Contains(script, "login ssh scp") {
		t.Fatalf("unexpected completion script: %s", script)
	}
}

func TestClientBootstrapsCSRFFromSessionCookie(t *testing.T) {
	var (
		bootstrapCount int
		gotCookie      string
		gotCSRF        string
	)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/auth/me":
			bootstrapCount++
			gotCookie = r.Header.Get("Cookie")
			w.Header().Set("X-CSRF-Token", "csrf-token-123")
			_ = json.NewEncoder(w).Encode(map[string]string{"username": "alice"})
		case "/api/v2/ca/sign-user":
			gotCSRF = r.Header.Get("X-CSRF-Token")
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"success": true,
				"data": map[string]string{
					"certificate": "ssh-ed25519-cert-v01@openssh.com AAAA...",
				},
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer ts.Close()

	client := NewClientFromConfig(ClientConfig{
		Server:        ts.URL,
		SessionCookie: "session-cookie-value",
	})
	if _, err := client.Post("/api/v2/ca/sign-user", map[string]string{"public_key": "ssh-ed25519 AAAA...", "ttl": "1h"}); err != nil {
		t.Fatalf("Post() error = %v", err)
	}
	if bootstrapCount != 1 {
		t.Fatalf("expected one CSRF bootstrap request, got %d", bootstrapCount)
	}
	if !strings.Contains(gotCookie, "session=session-cookie-value") {
		t.Fatalf("expected session cookie on bootstrap request, got %q", gotCookie)
	}
	if gotCSRF != "csrf-token-123" {
		t.Fatalf("expected CSRF token header on POST, got %q", gotCSRF)
	}
}

func TestSaveConfigPersistsSessionAndIdentity(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	cfg := ClientConfig{
		Server:        "https://proxy.example.com",
		SessionCookie: "signed-session-cookie",
		IdentityFile:  "/tmp/id_ed25519",
		SSHAddr:       "proxy.example.com:2222",
	}
	if err := saveConfig(cfg); err != nil {
		t.Fatalf("saveConfig() error = %v", err)
	}

	loaded := loadConfig()
	if loaded.Server != cfg.Server || loaded.SessionCookie != cfg.SessionCookie || loaded.IdentityFile != cfg.IdentityFile {
		t.Fatalf("loaded config mismatch: %#v", loaded)
	}

	data, err := os.ReadFile(filepath.Join(home, ".sshproxy", "config.json"))
	if err != nil {
		t.Fatalf("os.ReadFile() error = %v", err)
	}
	if !strings.Contains(string(data), `"session_cookie": "signed-session-cookie"`) {
		t.Fatalf("expected session cookie in config file, got %s", string(data))
	}
}

func TestClientPinnedServerPublicKeyAllowsMatchingSelfSignedServer(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"success": true,
			"data":    map[string]string{"status": "ok"},
		})
	}))
	defer ts.Close()

	pin, err := publicKeyPin(ts.Certificate())
	if err != nil {
		t.Fatalf("publicKeyPin() error = %v", err)
	}

	client := NewClientFromConfig(ClientConfig{
		Server:                   ts.URL,
		Insecure:                 true,
		PinnedServerPubKeySHA256: pin,
	})

	body, err := client.Get("/api/v2/system/health")
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	if !strings.Contains(string(body), `"status":"ok"`) {
		t.Fatalf("unexpected body: %s", string(body))
	}
}

func TestClientPinnedServerPublicKeyRejectsMismatch(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"success":true}`))
	}))
	defer ts.Close()

	client := NewClientFromConfig(ClientConfig{
		Server:                   ts.URL,
		Insecure:                 true,
		PinnedServerPubKeySHA256: "sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
	})

	if _, err := client.GetRaw("/"); err == nil || !strings.Contains(err.Error(), "tls pin verification failed") {
		t.Fatalf("GetRaw() error = %v, want tls pin verification failure", err)
	}
}

func TestEnsureIdentityKeyPairGeneratesPublicKey(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "id_ed25519")

	publicKey, err := ensureIdentityKeyPair(keyPath)
	if err != nil {
		t.Fatalf("ensureIdentityKeyPair() error = %v", err)
	}
	if !strings.Contains(publicKey, "ssh-ed25519") {
		t.Fatalf("unexpected public key: %q", publicKey)
	}

	pubData, err := os.ReadFile(keyPath + ".pub")
	if err != nil {
		t.Fatalf("os.ReadFile() error = %v", err)
	}
	if strings.TrimSpace(string(pubData)) != publicKey {
		t.Fatalf("public key file mismatch: %q", string(pubData))
	}
}

func TestParseConfigValue(t *testing.T) {
	value := parseConfigValue(`{"nested":true}`)
	parsed, ok := value.(map[string]interface{})
	if !ok || parsed["nested"] != true {
		t.Fatalf("unexpected parsed value: %#v", value)
	}

	value = parseConfigValue("plain-text")
	if value != "plain-text" {
		t.Fatalf("expected string fallback, got %#v", value)
	}
}

func TestSetConfigValue(t *testing.T) {
	cfg := map[string]interface{}{"logging": map[string]interface{}{"level": "info"}}
	setConfigValue(cfg, "logging.level", "debug")
	setConfigValue(cfg, "security.mfa.enabled", true)

	logging := cfg["logging"].(map[string]interface{})
	if logging["level"] != "debug" {
		t.Fatalf("unexpected logging level: %#v", logging["level"])
	}

	security := cfg["security"].(map[string]interface{})
	mfa := security["mfa"].(map[string]interface{})
	if mfa["enabled"] != true {
		t.Fatalf("unexpected nested config: %#v", cfg)
	}
}

func TestWrappedSSHArgs(t *testing.T) {
	args := wrappedSSHArgs("/tmp/ssh proxy", "proxy.example.com:2222", []string{"alice@host", "-p", "2200"})
	if len(args) < 4 {
		t.Fatalf("unexpected args: %#v", args)
	}
	if args[0] != "-o" {
		t.Fatalf("expected -o prefix, got %#v", args)
	}
	if !strings.Contains(args[1], "ProxyCommand='/tmp/ssh proxy' proxycommand --addr 'proxy.example.com:2222'") {
		t.Fatalf("unexpected proxy command option: %q", args[1])
	}
	if args[2] != "alice@host" || args[3] != "-p" {
		t.Fatalf("expected passthrough ssh args, got %#v", args)
	}
}

func TestWrappedSSHArgsWithIdentity(t *testing.T) {
	args := wrappedSSHArgsWithIdentity("/tmp/sshproxy", "proxy.example.com:2222", "/tmp/id_ed25519", []string{"alice@host"})
	if len(args) < 4 {
		t.Fatalf("unexpected args: %#v", args)
	}
	if args[0] != "-i" || args[1] != "/tmp/id_ed25519" {
		t.Fatalf("expected injected identity file, got %#v", args)
	}
}

func TestWrappedSSHArgsDoesNotDuplicateIdentity(t *testing.T) {
	args := wrappedSSHArgsWithIdentity("/tmp/sshproxy", "proxy.example.com:2222", "/tmp/id_ed25519", []string{"-i", "/tmp/custom", "alice@host"})
	if args[0] == "-i" && args[1] == "/tmp/id_ed25519" {
		t.Fatalf("expected explicit identity to win, got %#v", args)
	}
}
