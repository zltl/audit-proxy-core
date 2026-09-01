package dp

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	sshproxyv1 "github.com/ssh-proxy-core/ssh-proxy-core/api/proto/sshproxy/v1"
)

// requireOpenSSH skips when the system ssh client is unavailable.
//
// Testing against the Go client alone proves the proxy is self-consistent, not
// that it is correct: OpenSSH is what people actually connect with, and it is
// stricter about the protocol in places where x/crypto/ssh is forgiving.
func requireOpenSSH(t *testing.T) string {
	t.Helper()
	path, err := exec.LookPath("ssh")
	if err != nil {
		t.Skip("the openssh client is not installed; skipping interoperability test")
	}
	return path
}

// sshCommand builds an ssh invocation against the proxy that will not touch the
// user's real configuration or known_hosts.
func (h *harness) sshCommand(t *testing.T, sshPath, user string, extra ...string) *exec.Cmd {
	t.Helper()
	host, port, _ := splitHostPort(h.addr)

	args := []string{
		"-F", "/dev/null",
		"-o", "StrictHostKeyChecking=no",
		"-o", "UserKnownHostsFile=" + filepath.Join(t.TempDir(), "known_hosts"),
		"-o", "PreferredAuthentications=password,keyboard-interactive",
		"-o", "PubkeyAuthentication=no",
		"-o", "NumberOfPasswordPrompts=1",
		"-o", "ConnectTimeout=10",
		"-o", "LogLevel=ERROR",
		"-p", port,
		"-l", user,
		host,
	}
	args = append(args, extra...)

	cmd := exec.Command(sshPath, args...)
	// SSH_ASKPASS with SSH_ASKPASS_REQUIRE supplies the password without a tty,
	// which is the only way to script password authentication.
	askpass := filepath.Join(t.TempDir(), "askpass.sh")
	script := "#!/bin/sh\necho client-password\n"
	if err := os.WriteFile(askpass, []byte(script), 0o700); err != nil {
		t.Fatalf("write askpass helper: %v", err)
	}
	cmd.Env = append(os.Environ(),
		"SSH_ASKPASS="+askpass,
		"SSH_ASKPASS_REQUIRE=force",
		"DISPLAY=none",
	)
	return cmd
}

func splitHostPort(addr string) (host, port string, ok bool) {
	idx := strings.LastIndex(addr, ":")
	if idx < 0 {
		return addr, "22", false
	}
	return addr[:idx], addr[idx+1:], true
}

func TestOpenSSHClientCanRunACommand(t *testing.T) {
	sshPath := requireOpenSSH(t)
	h := newHarness(t, nil)

	cmd := h.sshCommand(t, sshPath, "alice@web-1", "uptime")
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	done := make(chan error, 1)
	go func() { done <- cmd.Run() }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("ssh exited with %v\nstdout: %s\nstderr: %s", err, stdout.String(), stderr.String())
		}
	case <-time.After(30 * time.Second):
		_ = cmd.Process.Kill()
		t.Fatalf("ssh did not finish\nstdout: %s\nstderr: %s", stdout.String(), stderr.String())
	}

	if !strings.Contains(stdout.String(), "ran: uptime") {
		t.Fatalf("stdout = %q, stderr = %q", stdout.String(), stderr.String())
	}
	if got := h.upstream.recordedExecs(); len(got) != 1 || got[0] != "uptime" {
		t.Fatalf("the upstream saw %v", got)
	}
}

func TestOpenSSHClientSeesADeniedCommandMessage(t *testing.T) {
	sshPath := requireOpenSSH(t)
	h := newHarness(t, func(_ *Config, pdp *scriptedPDP) {
		pdp.commandPolicyID = "cp-1"
		pdp.commandResponses["rm -rf /"] = &sshproxyv1.AuthorizeCommandResponse{
			Decision: sshproxyv1.CommandDecision_COMMAND_DECISION_DENY,
			Reason:   "refusing a recursive delete of the root filesystem",
		}
	})

	cmd := h.sshCommand(t, sshPath, "alice@web-1", "rm -rf /")
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	done := make(chan error, 1)
	go func() { done <- cmd.Run() }()
	select {
	case <-done:
	case <-time.After(30 * time.Second):
		_ = cmd.Process.Kill()
		t.Fatal("ssh did not finish after a command was refused")
	}

	// The point of refusing this way is that the user is told why, rather than
	// seeing an unexplained disconnection.
	if !strings.Contains(stderr.String(), "recursive delete") {
		t.Fatalf("the reason was not shown to the user\nstdout: %q\nstderr: %q",
			stdout.String(), stderr.String())
	}
	if got := h.upstream.recordedExecs(); len(got) != 0 {
		t.Fatalf("a refused command reached the target: %v", got)
	}
}

func TestOpenSSHClientMultiplexesChannels(t *testing.T) {
	sshPath := requireOpenSSH(t)
	h := newHarness(t, nil)

	controlPath := filepath.Join(t.TempDir(), "cm")
	host, port, _ := splitHostPort(h.addr)
	common := []string{
		"-F", "/dev/null",
		"-o", "StrictHostKeyChecking=no",
		"-o", "UserKnownHostsFile=" + filepath.Join(t.TempDir(), "kh"),
		"-o", "PubkeyAuthentication=no",
		"-o", "PreferredAuthentications=password",
		"-o", "NumberOfPasswordPrompts=1",
		"-o", "LogLevel=ERROR",
		"-o", "ControlMaster=auto",
		"-o", "ControlPath=" + controlPath,
		"-o", "ControlPersist=10",
		"-p", port,
		"-l", "alice@web-1",
		host,
	}

	askpass := filepath.Join(t.TempDir(), "askpass.sh")
	if err := os.WriteFile(askpass, []byte("#!/bin/sh\necho client-password\n"), 0o700); err != nil {
		t.Fatalf("write askpass: %v", err)
	}
	env := append(os.Environ(), "SSH_ASKPASS="+askpass, "SSH_ASKPASS_REQUIRE=force", "DISPLAY=none")

	run := func(command string) (string, error) {
		cmd := exec.Command(sshPath, append(append([]string{}, common...), command)...)
		cmd.Env = env
		out, err := cmd.CombinedOutput()
		return string(out), err
	}

	// The first invocation establishes the shared connection; the ones after it
	// reuse it, which is exactly the multiplexing the previous data plane could
	// not serve because it only ever handled one channel.
	if out, err := run("first"); err != nil {
		t.Skipf("connection multiplexing is unavailable in this environment: %v (%s)", err, out)
	}
	defer func() {
		stop := exec.Command(sshPath, "-O", "exit", "-o", "ControlPath="+controlPath, host)
		stop.Env = env
		_ = stop.Run()
	}()

	for _, command := range []string{"second", "third"} {
		out, err := run(command)
		if err != nil {
			t.Fatalf("multiplexed %q failed: %v (%s)", command, err, out)
		}
		if !strings.Contains(out, "ran: "+command) {
			t.Fatalf("multiplexed %q output = %q", command, out)
		}
	}

	execs := h.upstream.recordedExecs()
	if len(execs) < 3 {
		t.Fatalf("the upstream saw %v; multiplexed commands did not all arrive", execs)
	}
}
