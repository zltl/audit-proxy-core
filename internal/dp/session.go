package dp

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"

	sshproxyv1 "github.com/ssh-proxy-core/ssh-proxy-core/api/proto/sshproxy/v1"
)

// ptyRequest is the payload of a pty-req channel request.
type ptyRequest struct {
	Term          string
	Columns, Rows uint32
	Width, Height uint32
	Modes         string
}

// windowChangeRequest is the payload of a window-change request.
type windowChangeRequest struct {
	Columns, Rows uint32
	Width, Height uint32
}

// execRequest is the payload of exec and subsystem requests.
type execRequest struct {
	Command string
}

// envRequest is the payload of an env request.
type envRequest struct {
	Name  string
	Value string
}

// handleSessionChannel proxies one session channel.
func (c *connection) handleSessionChannel(ctx context.Context, newChannel ssh.NewChannel) {
	clientChannel, clientRequests, err := newChannel.Accept()
	if err != nil {
		log.Printf("dp: session %s: accept session channel: %v", c.sessionID, err)
		return
	}
	defer func() { _ = clientChannel.Close() }()

	c.trackChannel(clientChannel)
	defer c.untrackChannel(clientChannel)

	// The upstream channel is opened up front so that requests can be relayed
	// as they arrive, in order. Buffering them until a shell request would
	// reorder pty-req and env relative to the command they configure.
	upstreamChannel, upstreamRequests, err := c.upstream.OpenChannel("session", nil)
	if err != nil {
		writeChannelError(clientChannel, "cannot open a session on the target: "+err.Error())
		return
	}
	defer func() { _ = upstreamChannel.Close() }()

	sess := &sessionChannel{
		conn:     c,
		client:   clientChannel,
		upstream: upstreamChannel,
		width:    80,
		height:   24,
	}
	defer sess.finish()

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		sess.relayClientRequests(ctx, clientRequests)
		// The request stream ending means the client closed the channel, not
		// merely its stdin. Nothing more can arrive for the upstream channel,
		// so it is closed to unblock the copy reading from it — otherwise a
		// client that gives up after a refused request would leave the pair
		// half-open forever.
		_ = upstreamChannel.Close()
	}()

	upstreamRequestsDone := make(chan struct{})
	go func() {
		defer wg.Done()
		defer close(upstreamRequestsDone)
		sess.relayUpstreamRequests(upstreamRequests)
	}()

	sess.pump()

	// The data has stopped flowing, but exit-status arrives as a request rather
	// than as data and is relayed by a different goroutine. Closing the client
	// channel now would race that relay, and a client that never receives an
	// exit status reports the command as having failed even though it
	// succeeded. So the request relay is given a moment to drain first.
	select {
	case <-upstreamRequestsDone:
	case <-time.After(exitStatusGrace):
		// An upstream that half-closes without ending the channel must not hold
		// the session open; losing a trailing request is the lesser problem.
	}

	// Closing both channels ends the request relays, which range over channels
	// that x/crypto/ssh only closes with the channel itself.
	_ = clientChannel.Close()
	_ = upstreamChannel.Close()
	wg.Wait()
}

// exitStatusGrace bounds how long teardown waits for trailing channel requests.
const exitStatusGrace = 5 * time.Second

// sessionChannel carries the state of one proxied session channel.
type sessionChannel struct {
	conn     *connection
	client   ssh.Channel
	upstream ssh.Channel

	mu       sync.Mutex
	recorder *Recorder
	width    int
	height   int
	// interactive marks that a pty was allocated, which is what distinguishes a
	// terminal session worth recording as a stream from a one-shot command.
	interactive bool
	// commandLine accumulates typed characters so an interactive command can be
	// screened before the user presses enter sends it onward.
	commandLine []byte
	started     time.Time
	finished    bool

	// sftp and scp are set when the channel carries a file transfer, which is
	// the only way to record what was moved rather than how much. The filters
	// wrap the data path and are consulted on every write, because the request
	// that reveals a transfer arrives after copying has already started.
	sftp           *sftpInspector
	scp            *scpInspector
	requestFilter  io.Writer
	responseFilter io.Writer
}

// relayClientRequests forwards channel requests, gating each against policy.
func (s *sessionChannel) relayClientRequests(ctx context.Context, requests <-chan *ssh.Request) {
	for req := range requests {
		allowed, handled := s.screenRequest(ctx, req)
		if handled {
			continue
		}
		if !allowed {
			if req.WantReply {
				_ = req.Reply(false, nil)
			}
			continue
		}
		ok, err := s.upstream.SendRequest(req.Type, req.WantReply, req.Payload)
		if err != nil {
			if req.WantReply {
				_ = req.Reply(false, nil)
			}
			return
		}
		if req.WantReply {
			_ = req.Reply(ok, nil)
		}
	}
	// The client is finished with this channel; let the upstream see the same.
	_ = s.upstream.CloseWrite()
}

// screenRequest applies policy to a channel request.
//
// It returns whether the request may be relayed, and whether it has already
// been fully handled here.
func (s *sessionChannel) screenRequest(ctx context.Context, req *ssh.Request) (allowed, handled bool) {
	switch req.Type {
	case "pty-req":
		var payload ptyRequest
		if err := ssh.Unmarshal(req.Payload, &payload); err == nil {
			s.mu.Lock()
			s.width, s.height = int(payload.Columns), int(payload.Rows)
			s.interactive = true
			s.mu.Unlock()
		}
		return s.authorize(ctx, sshproxyv1.ChannelRequestType_CHANNEL_REQUEST_PTY, "", req), false

	case "window-change":
		var payload windowChangeRequest
		if err := ssh.Unmarshal(req.Payload, &payload); err == nil {
			s.mu.Lock()
			s.width, s.height = int(payload.Columns), int(payload.Rows)
			recorder := s.recorder
			s.mu.Unlock()
			recorder.Resize(int(payload.Columns), int(payload.Rows))
		}
		return true, false

	case "env":
		return s.authorize(ctx, sshproxyv1.ChannelRequestType_CHANNEL_REQUEST_ENV, "", req), false

	case "shell":
		if !s.authorize(ctx, sshproxyv1.ChannelRequestType_CHANNEL_REQUEST_SHELL, "", req) {
			return false, false
		}
		s.startRecording("shell")
		return true, false

	case "exec":
		var payload execRequest
		_ = ssh.Unmarshal(req.Payload, &payload)
		if !s.authorize(ctx, sshproxyv1.ChannelRequestType_CHANNEL_REQUEST_EXEC, payload.Command, req) {
			return false, false
		}
		// A one-shot command is screened before it reaches the target, which is
		// the only point at which blocking it still prevents it from running.
		decision := s.screenCommand(ctx, payload.Command)
		if decision.blocked {
			s.rejectCommand(req, decision.message)
			return false, true
		}
		if decision.rewritten != "" && decision.rewritten != payload.Command {
			req.Payload = ssh.Marshal(execRequest{Command: decision.rewritten})
		}
		// scp runs as an ordinary exec, so a transfer is only distinguishable
		// from a command by recognising the invocation.
		s.enableSCPInspection(payload.Command)
		s.startRecording("exec: " + payload.Command)
		return true, false

	case "subsystem":
		var payload execRequest
		_ = ssh.Unmarshal(req.Payload, &payload)
		if !s.authorize(ctx, sshproxyv1.ChannelRequestType_CHANNEL_REQUEST_SUBSYSTEM, payload.Command, req) {
			return false, false
		}
		s.enableSFTPInspection(payload.Command)
		s.startRecording("subsystem: " + payload.Command)
		return true, false

	case "x11-req":
		return s.authorize(ctx, sshproxyv1.ChannelRequestType_CHANNEL_REQUEST_X11, "", req), false

	case "auth-agent-req@openssh.com":
		return s.authorize(ctx, sshproxyv1.ChannelRequestType_CHANNEL_REQUEST_AGENT, "", req), false

	default:
		// Signals, exit-status, and vendor extensions carry no new privilege.
		return true, false
	}
}

// rejectCommand turns a blocked command into something a user can understand.
//
// The request is accepted and then reported as having exited non-zero, rather
// than being failed outright: an SSH client shown "exec request failed" cannot
// display a reason, whereas a non-zero exit with a message on stderr reads
// exactly like the command ran and refused, which is what happened.
func (s *sessionChannel) rejectCommand(req *ssh.Request, message string) {
	if req.WantReply {
		_ = req.Reply(true, nil)
	}
	writeChannelError(s.client, message)
	_, _ = s.client.SendRequest("exit-status", false, exitStatusPayload(1))
	_ = s.client.CloseWrite()
	// Closing the channel is what lets the client's Wait return; without it the
	// session would sit open after a refusal.
	_ = s.client.Close()
}

func (s *sessionChannel) authorize(ctx context.Context, requestType sshproxyv1.ChannelRequestType, payload string, req *ssh.Request) bool {
	err := s.conn.authorizeChannel(ctx, &sshproxyv1.AuthorizeChannelRequest{
		ChannelType: sshproxyv1.ChannelType_CHANNEL_TYPE_SESSION,
		RequestType: requestType,
		Payload:     payload,
	})
	if err == nil {
		return true
	}
	log.Printf("dp: session %s: %s refused: %v", s.conn.sessionID, req.Type, err)
	writeChannelError(s.client, err.Error())
	return false
}

// commandDecision is the outcome of screening a command.
type commandDecision struct {
	blocked   bool
	message   string
	rewritten string
}

// screenCommand asks the decision point about a command, blocking while an
// approval is pending and telling the user what is happening meanwhile.
func (s *sessionChannel) screenCommand(ctx context.Context, command string) commandDecision {
	if strings.TrimSpace(command) == "" {
		return commandDecision{}
	}

	resp, err := s.conn.proxy.pdp.AuthorizeCommand(ctx, &sshproxyv1.AuthorizeCommandRequest{
		SessionId:       s.conn.sessionID,
		Username:        s.conn.username,
		Roles:           s.conn.roles,
		Target:          s.conn.targetHost,
		Command:         command,
		CommandPolicyId: s.conn.commandPolicy,
	}, func(update *sshproxyv1.AuthorizeCommandResponse) {
		if update.GetDecision() == sshproxyv1.CommandDecision_COMMAND_DECISION_PENDING_APPROVAL {
			// Without this the shell just stops, and the user has no way to
			// know whether it is waiting on a person or has hung.
			writeChannelNotice(s.client, "waiting for approval: "+update.GetReason())
		}
	})
	if err != nil {
		log.Printf("dp: session %s: command screening failed: %v", s.conn.sessionID, err)
		return commandDecision{blocked: true, message: "command policy could not be consulted"}
	}

	s.mu.Lock()
	recorder := s.recorder
	s.mu.Unlock()

	switch resp.GetDecision() {
	case sshproxyv1.CommandDecision_COMMAND_DECISION_DENY:
		recorder.Marker("blocked: " + command)
		return commandDecision{blocked: true, message: resp.GetReason()}
	case sshproxyv1.CommandDecision_COMMAND_DECISION_REWRITE:
		recorder.Marker("rewritten: " + command)
		return commandDecision{rewritten: resp.GetRewrittenCommand()}
	case sshproxyv1.CommandDecision_COMMAND_DECISION_AUDIT:
		recorder.Marker("flagged: " + command)
		return commandDecision{}
	default:
		return commandDecision{}
	}
}

// relayUpstreamRequests forwards requests the target sends back, such as the
// exit status that tells the client the command finished.
func (s *sessionChannel) relayUpstreamRequests(requests <-chan *ssh.Request) {
	for req := range requests {
		ok, err := s.client.SendRequest(req.Type, req.WantReply, req.Payload)
		if err != nil {
			return
		}
		if req.WantReply {
			_ = req.Reply(ok, nil)
		}
	}
}

// enableSFTPInspection turns on packet-level parsing for an sftp subsystem.
//
// Without it, a file transfer is just bytes on a channel: the audit trail would
// record that somebody moved four megabytes and be unable to say which file, in
// which direction, or whether it should have been allowed.
func (s *sessionChannel) enableSFTPInspection(subsystem string) {
	if !strings.EqualFold(strings.TrimSpace(subsystem), "sftp") {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	inspector := newSFTPInspector(s.conn.transferPolicy(), s.conn)
	s.sftp = inspector
	s.requestFilter = newSFTPRequestFilter(inspector, writerFunc(s.rawToUpstream), s.client, nil)
	// Replies are parsed too: sftp returns an opaque handle for an open, and
	// only correlating the two attributes transferred bytes to a filename.
	s.responseFilter = newSFTPResponseFilter(inspector, writerFunc(s.rawToClient), nil)
}

// enableSCPInspection turns on control-stream parsing for an scp invocation.
func (s *sessionChannel) enableSCPInspection(command string) {
	mode, remotePath, ok := parseSCPCommand(command)
	if !ok {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	inspector := newSCPInspector(mode, remotePath, s.conn.transferPolicy(), s.conn)
	s.scp = inspector
	// Only the side carrying control lines is parsed: for an upload that is the
	// client's stream, for a download the target's. The other side is file
	// content and acknowledgements.
	if mode == scpModeSink {
		s.requestFilter = newSCPFilter(inspector, writerFunc(s.rawToUpstream), nil)
	} else {
		s.responseFilter = newSCPFilter(inspector, writerFunc(s.rawToClient), nil)
	}
}

// pump copies data in both directions until either side finishes.
//
// The transfer inspectors are resolved on each write rather than captured here,
// because a session channel starts before the client says what it is for: the
// subsystem or exec request that reveals a file transfer arrives after the
// copies are already running.
func (s *sessionChannel) pump() {
	defer s.flushInspectors()

	var wg sync.WaitGroup
	wg.Add(2)

	// Client to upstream: what the user typed, or the requests and file content
	// of a transfer.
	go func() {
		defer wg.Done()
		_, _ = io.Copy(writerFunc(s.writeToUpstream), s.client)
		_ = s.upstream.CloseWrite()
	}()

	// Upstream to client: what the user saw, on both streams.
	//
	// Standard error is a separate SSH stream, so a proxy that only copies
	// stdout silently swallows every diagnostic a command produces. The two are
	// drained together and the EOF is sent only once both are done, because EOF
	// is a property of the channel rather than of one stream: signalling it
	// after stdout finishes would discard whatever stderr had left to send.
	go func() {
		defer wg.Done()

		var streams sync.WaitGroup
		streams.Add(2)
		go func() {
			defer streams.Done()
			_, _ = io.Copy(writerFunc(s.writeToClient), s.upstream)
		}()
		go func() {
			defer streams.Done()
			_, _ = io.Copy(s.client.Stderr(), s.upstream.Stderr())
		}()
		streams.Wait()

		_ = s.client.CloseWrite()
	}()

	wg.Wait()
}

// writerFunc adapts a method to io.Writer.
type writerFunc func([]byte) (int, error)

func (f writerFunc) Write(p []byte) (int, error) { return f(p) }

// writeToUpstream sends client data onward, through the transfer inspector when
// one is active.
func (s *sessionChannel) writeToUpstream(p []byte) (int, error) {
	s.mu.Lock()
	filter := s.requestFilter
	s.mu.Unlock()
	if filter != nil {
		// The filter forwards to the accounting writer itself, and may withhold
		// a packet that policy refuses.
		return filter.Write(p)
	}
	return s.rawToUpstream(p)
}

// rawToUpstream records and accounts for data on its way to the target.
func (s *sessionChannel) rawToUpstream(p []byte) (int, error) {
	n, err := s.upstream.Write(p)
	if n > 0 {
		s.conn.bytesIn.Add(int64(n))
		s.mu.Lock()
		recorder := s.recorder
		s.mu.Unlock()
		recorder.Input(p[:n])
	}
	return n, err
}

// writeToClient sends target data back, through the transfer inspector when one
// is active.
func (s *sessionChannel) writeToClient(p []byte) (int, error) {
	s.mu.Lock()
	filter := s.responseFilter
	s.mu.Unlock()
	if filter != nil {
		return filter.Write(p)
	}
	return s.rawToClient(p)
}

// rawToClient records and accounts for data on its way back.
func (s *sessionChannel) rawToClient(p []byte) (int, error) {
	n, err := s.client.Write(p)
	if n > 0 {
		s.conn.bytesOut.Add(int64(n))
		s.mu.Lock()
		recorder := s.recorder
		s.mu.Unlock()
		recorder.Output(p[:n])
	}
	return n, err
}

// flushInspectors records anything still in flight when the session ends, so an
// interrupted transfer leaves a trace rather than none.
func (s *sessionChannel) flushInspectors() {
	s.mu.Lock()
	sftpInspect, scpInspect := s.sftp, s.scp
	s.mu.Unlock()

	if sftpInspect != nil {
		sftpInspect.Flush()
	}
	if scpInspect != nil {
		scpInspect.Flush()
	}
}

// startRecording begins capturing this channel, unless policy says not to.
func (s *sessionChannel) startRecording(title string) {
	if s.conn.recordPolicy == sshproxyv1.RecordPolicy_RECORD_POLICY_NONE {
		return
	}
	if s.conn.recordPolicy == sshproxyv1.RecordPolicy_RECORD_POLICY_COMMANDS {
		// Command-level recording captures decisions and transfers but not the
		// terminal stream, for environments where screen content is sensitive.
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.recorder != nil {
		return
	}
	s.started = time.Now()

	path := filepath.Join(s.conn.proxy.config.RecordingDir,
		s.conn.sessionID+"-"+s.started.UTC().Format("20060102T150405")+".cast")
	recorder, err := NewRecorder(RecorderOptions{
		Path:         path,
		Width:        s.width,
		Height:       s.height,
		Title:        title,
		CaptureInput: s.conn.proxy.config.CaptureKeystrokes,
		StartedAt:    s.started,
		Env: map[string]string{
			"SSH_PROXY_SESSION": s.conn.sessionID,
			"SSH_PROXY_USER":    s.conn.username,
			"SSH_PROXY_TARGET":  fmt.Sprintf("%s@%s", s.conn.upstreamLogin, s.conn.targetHost),
		},
	})
	if err != nil {
		// A session that cannot be recorded is a policy problem, not a
		// technical one, so it is reported loudly rather than silently
		// continuing unrecorded.
		log.Printf("dp: session %s: recording could not be started: %v", s.conn.sessionID, err)
		return
	}
	s.recorder = recorder
	s.conn.noteRecording(path)
}

func (s *sessionChannel) finish() {
	s.mu.Lock()
	recorder := s.recorder
	s.recorder = nil
	s.finished = true
	s.mu.Unlock()

	if recorder != nil {
		if err := recorder.Close(); err != nil {
			log.Printf("dp: session %s: closing recording: %v", s.conn.sessionID, err)
		}
	}
}

// writeChannelError sends a message the SSH client will show the user.
func writeChannelError(channel ssh.Channel, message string) {
	_, _ = channel.Stderr().Write([]byte("\r\n[ssh-proxy] " + message + "\r\n"))
}

func writeChannelNotice(channel ssh.Channel, message string) {
	_, _ = channel.Stderr().Write([]byte("\r\n[ssh-proxy] " + message + "\r\n"))
}

// exitStatusPayload builds the payload of an exit-status request.
func exitStatusPayload(code uint32) []byte {
	payload := make([]byte, 4)
	binary.BigEndian.PutUint32(payload, code)
	return payload
}
