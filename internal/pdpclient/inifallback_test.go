package pdpclient

import (
	"os"
	"path/filepath"
	"testing"

	sshproxyv1 "github.com/ssh-proxy-core/ssh-proxy-core/api/proto/sshproxy/v1"
)

func TestINIFallbackAllowsKnownRoute(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.ini")
	content := `[user:alice]
enabled = true

[route:web]
host = 10.0.0.1
port = 22
user = alice
`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	fb := newINIFallback(path)
	resp, ok := fb.evaluate(&sshproxyv1.AuthorizeSessionRequest{
		Username: "alice",
		Target:   "10.0.0.1:22",
	})
	if !ok || !resp.GetAllowed() {
		t.Fatalf("expected allow, got ok=%v resp=%+v", ok, resp)
	}
}

func TestINIFallbackDeniesUnknownUser(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.ini")
	if err := os.WriteFile(path, []byte("[user:bob]\nenabled = true\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	fb := newINIFallback(path)
	resp, ok := fb.evaluate(&sshproxyv1.AuthorizeSessionRequest{Username: "alice", Target: "10.0.0.1:22"})
	if !ok || resp.GetAllowed() {
		t.Fatalf("expected deny for unknown user")
	}
}
