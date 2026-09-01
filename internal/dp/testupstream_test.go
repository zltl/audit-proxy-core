package dp

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
	"testing"

	"golang.org/x/crypto/ssh"
)

// fakeUpstream is a minimal SSH server standing in for a target host.
//
// It speaks enough of the protocol to prove the proxy relays faithfully: shell
// and exec on session channels, direct-tcpip forwarding, and the exit status
// that tells a client a command finished.
type fakeUpstream struct {
	t        *testing.T
	listener net.Listener
	signer   ssh.Signer

	mu sync.Mutex
	// execs records every command the upstream was asked to run, which is how a
	// test asserts that a rewritten command really changed what executed.
	execs []string
	// envs records env requests, to prove they arrive before the command.
	envs []string
	// ptys counts pty allocations.
	ptys int
	// forwards records direct-tcpip destinations.
	forwards []string
	// shellBanner is written when a shell starts.
	shellBanner string
	// echo makes the shell echo back what it receives.
	echo bool
}

func newFakeUpstream(t *testing.T) *fakeUpstream {
	t.Helper()

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate upstream host key: %v", err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("build upstream signer: %v", err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	up := &fakeUpstream{
		t:           t,
		listener:    listener,
		signer:      signer,
		shellBanner: "upstream-shell-ready\n",
		echo:        true,
	}
	go up.serve()
	t.Cleanup(func() { _ = listener.Close() })
	return up
}

func (u *fakeUpstream) addr() (string, int) {
	host, port, _ := net.SplitHostPort(u.listener.Addr().String())
	return host, atoi(port)
}

func (u *fakeUpstream) hostKey() ssh.PublicKey { return u.signer.PublicKey() }

func (u *fakeUpstream) recordedExecs() []string {
	u.mu.Lock()
	defer u.mu.Unlock()
	return append([]string(nil), u.execs...)
}

func (u *fakeUpstream) recordedForwards() []string {
	u.mu.Lock()
	defer u.mu.Unlock()
	return append([]string(nil), u.forwards...)
}

func (u *fakeUpstream) ptyCount() int {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.ptys
}

func (u *fakeUpstream) serve() {
	for {
		conn, err := u.listener.Accept()
		if err != nil {
			return
		}
		go u.handleConn(conn)
	}
}

func (u *fakeUpstream) handleConn(conn net.Conn) {
	defer func() { _ = conn.Close() }()

	config := &ssh.ServerConfig{
		// The upstream accepts whatever the proxy presents; what these tests
		// exercise is the proxy's behaviour, not the target's authentication.
		NoClientAuth:      true,
		PasswordCallback:  func(ssh.ConnMetadata, []byte) (*ssh.Permissions, error) { return nil, nil },
		PublicKeyCallback: func(ssh.ConnMetadata, ssh.PublicKey) (*ssh.Permissions, error) { return nil, nil },
	}
	config.AddHostKey(u.signer)

	serverConn, chans, reqs, err := ssh.NewServerConn(conn, config)
	if err != nil {
		return
	}
	defer func() { _ = serverConn.Close() }()
	go ssh.DiscardRequests(reqs)

	for newChannel := range chans {
		switch newChannel.ChannelType() {
		case "session":
			go u.handleSession(newChannel)
		case "direct-tcpip":
			go u.handleDirect(newChannel)
		default:
			_ = newChannel.Reject(ssh.UnknownChannelType, newChannel.ChannelType())
		}
	}
}

func (u *fakeUpstream) handleSession(newChannel ssh.NewChannel) {
	channel, requests, err := newChannel.Accept()
	if err != nil {
		return
	}
	defer func() { _ = channel.Close() }()

	for req := range requests {
		switch req.Type {
		case "pty-req":
			u.mu.Lock()
			u.ptys++
			u.mu.Unlock()
			if req.WantReply {
				_ = req.Reply(true, nil)
			}
		case "env":
			var payload struct{ Name, Value string }
			_ = ssh.Unmarshal(req.Payload, &payload)
			u.mu.Lock()
			u.envs = append(u.envs, payload.Name+"="+payload.Value)
			u.mu.Unlock()
			if req.WantReply {
				_ = req.Reply(true, nil)
			}
		case "shell":
			if req.WantReply {
				_ = req.Reply(true, nil)
			}
			_, _ = channel.Write([]byte(u.shellBanner))
			if u.echo {
				_, _ = io.Copy(channel, channel)
			}
			u.sendExit(channel, 0)
			return
		case "exec":
			var payload struct{ Command string }
			_ = ssh.Unmarshal(req.Payload, &payload)
			u.mu.Lock()
			u.execs = append(u.execs, payload.Command)
			u.mu.Unlock()
			if req.WantReply {
				_ = req.Reply(true, nil)
			}
			_, _ = fmt.Fprintf(channel, "ran: %s\n", payload.Command)
			_, _ = fmt.Fprintf(channel.Stderr(), "stderr: %s\n", payload.Command)
			u.sendExit(channel, 0)
			return
		case "subsystem":
			var payload struct{ Command string }
			_ = ssh.Unmarshal(req.Payload, &payload)
			if req.WantReply {
				_ = req.Reply(true, nil)
			}
			_, _ = fmt.Fprintf(channel, "subsystem: %s\n", payload.Command)
			u.sendExit(channel, 0)
			return
		default:
			if req.WantReply {
				_ = req.Reply(false, nil)
			}
		}
	}
}

func (u *fakeUpstream) sendExit(channel ssh.Channel, code uint32) {
	payload := make([]byte, 4)
	binary.BigEndian.PutUint32(payload, code)
	_, _ = channel.SendRequest("exit-status", false, payload)
}

func (u *fakeUpstream) handleDirect(newChannel ssh.NewChannel) {
	var payload struct {
		DestHost   string
		DestPort   uint32
		OriginHost string
		OriginPort uint32
	}
	if err := ssh.Unmarshal(newChannel.ExtraData(), &payload); err != nil {
		_ = newChannel.Reject(ssh.ConnectionFailed, "bad payload")
		return
	}
	u.mu.Lock()
	u.forwards = append(u.forwards, fmt.Sprintf("%s:%d", payload.DestHost, payload.DestPort))
	u.mu.Unlock()

	channel, requests, err := newChannel.Accept()
	if err != nil {
		return
	}
	go ssh.DiscardRequests(requests)
	defer func() { _ = channel.Close() }()

	// Echo, so a test can prove bytes cross the tunnel in both directions.
	_, _ = io.Copy(channel, channel)
}
