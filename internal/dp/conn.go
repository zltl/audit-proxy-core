package dp

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/ssh"

	sshproxyv1 "github.com/ssh-proxy-core/ssh-proxy-core/api/proto/sshproxy/v1"
)

// connection is one authenticated client connection and its upstream.
type connection struct {
	proxy *Server

	client   *ssh.ServerConn
	upstream *ssh.Client

	sessionID     string
	username      string
	roles         []string
	targetID      string
	targetHost    string
	targetPort    int
	upstreamLogin string
	features      map[string]bool
	commandPolicy string
	recordPolicy  sshproxyv1.RecordPolicy

	bytesIn  atomic.Int64
	bytesOut atomic.Int64
	// lastActivity is when data last moved in either direction. An idle
	// timeout has to measure silence, not age: a session that has been open
	// for hours while somebody works is not idle, and one that connected a
	// minute ago and went quiet is.
	lastActivity atomic.Int64

	// maxSessionTTL and idleTimeout are the limits this session was granted.
	maxSessionTTL time.Duration
	idleTimeout   time.Duration

	// transfers and operations accumulate what the transfer inspectors saw, so
	// the close report can describe which files moved rather than only how many
	// bytes crossed the channel.
	transfersMu sync.Mutex
	transfers   []FileTransfer
	operations  []FileOperation

	// channels tracks open channels so a revocation closes all of them, not
	// just whichever one happens to notice first.
	channelsMu sync.Mutex
	channels   map[*ssh.Channel]struct{}

	startedAt time.Time
	closeOnce sync.Once
	closed    chan struct{}
	// terminated records why the session ended, for the audit trail.
	terminatedMu sync.Mutex
	terminated   string
}

// handle runs a connection from handshake to teardown.
func (s *Server) handle(ctx context.Context, rawConn net.Conn) {
	defer func() { _ = rawConn.Close() }()

	// The handshake gets its own deadline so an unauthenticated client cannot
	// hold a slot open by stalling.
	_ = rawConn.SetDeadline(time.Now().Add(s.config.AuthTimeout))

	serverConn, chans, globalReqs, err := ssh.NewServerConn(rawConn, s.serverConfig())
	if err != nil {
		// A failed handshake is routine: port scanners, health checks, and
		// clients that give up after seeing the available methods.
		log.Printf("dp: handshake from %s failed: %v", rawConn.RemoteAddr(), err)
		return
	}
	defer s.authState.release(serverConn.SessionID())
	_ = rawConn.SetDeadline(time.Time{})

	conn := &connection{
		proxy:     s,
		client:    serverConn,
		startedAt: time.Now(),
		channels:  make(map[*ssh.Channel]struct{}),
		closed:    make(chan struct{}),
		username:  serverConn.Permissions.Extensions["username"],
		roles:     splitRoles(serverConn.Permissions.Extensions["roles"]),
	}
	if conn.username == "" {
		conn.username = serverConn.User()
	}

	if err := conn.authorizeAndConnect(ctx); err != nil {
		s.metrics.SessionsRejected.Add(1)
		conn.emitSessionDenied(err.Error())
		conn.rejectAllChannels(chans, err)
		_ = serverConn.Close()
		return
	}

	s.trackConnection(conn)
	defer s.untrackConnection(conn)
	defer conn.close(ctx)

	go conn.heartbeat(ctx)
	go conn.forwardGlobalRequests(ctx, globalReqs)
	conn.serveUpstreamChannels(ctx)

	conn.serveChannels(ctx, chans)
}

// authorizeAndConnect resolves the target, gets a decision, registers the
// session, and dials the upstream.
func (c *connection) authorizeAndConnect(ctx context.Context) error {
	spec := parseLoginSpec(c.client.User())

	decision, err := c.proxy.pdp.AuthorizeSession(ctx, &sshproxyv1.AuthorizeSessionRequest{
		Client:        clientInfo(c.client, c.proxy.config.NodeID),
		Username:      c.username,
		Roles:         c.roles,
		Target:        spec.Target,
		TargetHost:    hostOf(spec.Target),
		TargetPort:    int32(portOf(spec.Target)),
		UpstreamLogin: spec.Login,
	})
	if err != nil {
		c.proxy.metrics.PolicyUnavailable.Add(1)
		return fmt.Errorf("authorization failed: %w", err)
	}
	if !decision.GetAllowed() {
		return fmt.Errorf("access denied: %s", decision.GetReason())
	}
	if decision.GetApprovalRequired() {
		// Holding the connection open while a human decides is a session-level
		// approval; until that workflow is wired the safe answer is to refuse
		// rather than to silently connect without the required approval.
		return fmt.Errorf("access to this target requires approval, which is not yet available for session start")
	}

	c.targetID = decision.GetTargetId()
	c.targetHost = decision.GetTargetHost()
	c.targetPort = int(decision.GetTargetPort())
	c.upstreamLogin = decision.GetUpstreamLogin()
	c.commandPolicy = decision.GetCommandPolicyId()
	c.recordPolicy = decision.GetRecordPolicy()
	c.maxSessionTTL = time.Duration(decision.GetMaxSessionSeconds()) * time.Second
	c.idleTimeout = time.Duration(decision.GetIdleTimeoutSeconds()) * time.Second
	c.features = make(map[string]bool, len(decision.GetFeatures()))
	for _, feature := range decision.GetFeatures() {
		c.features[feature] = true
	}

	opened, err := c.proxy.pdp.OpenSession(ctx, &sshproxyv1.OpenSessionRequest{
		Client:        clientInfo(c.client, c.proxy.config.NodeID),
		Username:      c.username,
		TargetId:      c.targetID,
		TargetHost:    c.targetHost,
		TargetPort:    int32(c.targetPort),
		UpstreamLogin: c.upstreamLogin,
		RuleId:        decision.GetRuleId(),
	})
	if err != nil {
		return fmt.Errorf("register session: %w", err)
	}
	if !opened.GetAllowed() {
		return fmt.Errorf("access denied: %s", opened.GetReason())
	}
	c.sessionID = opened.GetSessionId()

	dialer := &upstreamDialer{proxy: c.proxy}
	upstream, err := dialer.dial(ctx, upstreamTarget{
		SessionID: c.sessionID,
		TargetID:  c.targetID,
		Host:      c.targetHost,
		Port:      c.targetPort,
		Login:     c.upstreamLogin,
		Username:  c.username,
	})
	if err != nil {
		c.setTerminated("upstream connection failed")
		return err
	}
	c.upstream = upstream

	log.Printf("dp: session %s: %s connected to %s@%s:%d",
		c.sessionID, c.username, c.upstreamLogin, c.targetHost, c.targetPort)
	c.emitSessionStart(decision.GetRuleId())
	c.proxy.metrics.SessionsStarted.Add(1)
	return nil
}

// rejectAllChannels turns away every channel with an explanation.
//
// Simply closing the connection after authentication succeeded gives the user
// "Connection closed by remote host", which tells them nothing. Rejecting the
// channel makes OpenSSH print the reason, so somebody denied by policy learns
// that rather than assuming the proxy is broken.
func (c *connection) rejectAllChannels(chans <-chan ssh.NewChannel, cause error) {
	message := cause.Error()
	log.Printf("dp: refusing %s: %s", c.username, message)

	// A client that never opens a channel must not hold the goroutine open.
	deadline := time.After(5 * time.Second)
	for {
		select {
		case newChannel, ok := <-chans:
			if !ok {
				return
			}
			_ = newChannel.Reject(ssh.Prohibited, message)
		case <-deadline:
			return
		}
	}
}

// serveChannels dispatches every channel the client opens.
//
// Handling all of them, concurrently, is the difference between proxying an SSH
// connection and proxying one thing on it: a single connection routinely
// carries a shell, an sftp subsystem, and several forwarded ports at once, and
// clients using connection multiplexing open new ones throughout its life.
func (c *connection) serveChannels(ctx context.Context, chans <-chan ssh.NewChannel) {
	var wg sync.WaitGroup
	for newChannel := range chans {
		wg.Add(1)
		go func(nc ssh.NewChannel) {
			defer wg.Done()
			c.dispatchChannel(ctx, nc)
		}(newChannel)
	}
	wg.Wait()
}

func (c *connection) dispatchChannel(ctx context.Context, newChannel ssh.NewChannel) {
	switch newChannel.ChannelType() {
	case "session":
		c.handleSessionChannel(ctx, newChannel)
	case "direct-tcpip":
		c.handleDirectTCPIP(ctx, newChannel)
	default:
		// Refusing by name rather than silently is what lets an operator see
		// that a client wanted something the policy does not cover.
		log.Printf("dp: session %s: refusing channel type %q", c.sessionID, newChannel.ChannelType())
		_ = newChannel.Reject(ssh.UnknownChannelType,
			fmt.Sprintf("channel type %q is not permitted", newChannel.ChannelType()))
	}
}

// forwardGlobalRequests relays connection-level requests, gating the ones that
// grant something.
func (c *connection) forwardGlobalRequests(ctx context.Context, reqs <-chan *ssh.Request) {
	for req := range reqs {
		switch req.Type {
		case "tcpip-forward", "cancel-tcpip-forward":
			c.handleRemoteForwardRequest(ctx, req)
		case "keepalive@openssh.com":
			if req.WantReply {
				_ = req.Reply(true, nil)
			}
		case "no-more-sessions@openssh.com":
			// A hint from OpenSSH that no further session channels will be
			// opened. Passing it through lets the upstream apply the same
			// hardening it would for a direct connection.
			c.forwardGlobalRequest(req)
		default:
			c.forwardGlobalRequest(req)
		}
	}
}

func (c *connection) forwardGlobalRequest(req *ssh.Request) {
	if c.upstream == nil {
		if req.WantReply {
			_ = req.Reply(false, nil)
		}
		return
	}
	ok, payload, err := c.upstream.SendRequest(req.Type, req.WantReply, req.Payload)
	if err != nil {
		if req.WantReply {
			_ = req.Reply(false, nil)
		}
		return
	}
	if req.WantReply {
		_ = req.Reply(ok, payload)
	}
}

// authorizeChannel asks the decision point about a channel or channel request.
func (c *connection) authorizeChannel(ctx context.Context, req *sshproxyv1.AuthorizeChannelRequest) error {
	req.SessionId = c.sessionID
	resp, err := c.proxy.pdp.AuthorizeChannel(ctx, req)
	if err != nil {
		return fmt.Errorf("policy could not be consulted: %w", err)
	}
	if !resp.GetAllowed() {
		c.proxy.metrics.ChannelsRefused.Add(1)
		c.emitChannelDenied(req.GetChannelType().String(), resp.GetReason())
		return errors.New(resp.GetReason())
	}
	c.proxy.metrics.ChannelsOpened.Add(1)
	return nil
}

// heartbeat reports liveness and acts on a revocation.
func (c *connection) heartbeat(ctx context.Context) {
	ticker := time.NewTicker(c.proxy.config.HeartbeatInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-c.closed:
			return
		case <-ticker.C:
			// Idle is enforced here rather than centrally because only this
			// node can see whether bytes are moving; the control plane sees
			// heartbeats either way.
			if reason, expired := c.expired(); expired {
				c.terminate(reason)
				return
			}
			revoked, reason, err := c.proxy.pdp.HeartbeatSession(ctx, c.sessionID,
				c.bytesIn.Load(), c.bytesOut.Load())
			if err != nil {
				log.Printf("dp: session %s heartbeat: %v", c.sessionID, err)
				continue
			}
			if revoked {
				c.terminate(reason)
				return
			}
		}
	}
}

// noteActivity records that data moved, which is what keeps a session from
// being considered idle.
func (c *connection) noteActivity() {
	c.lastActivity.Store(time.Now().UnixNano())
}

// expired reports whether the session has outlived one of its granted limits.
func (c *connection) expired() (string, bool) {
	now := time.Now()
	if c.maxSessionTTL > 0 && !c.startedAt.IsZero() && now.After(c.startedAt.Add(c.maxSessionTTL)) {
		return "the maximum session duration of " + c.maxSessionTTL.String() + " was reached", true
	}
	if c.idleTimeout > 0 {
		last := c.lastActivity.Load()
		if last == 0 {
			last = c.startedAt.UnixNano()
		}
		if now.Sub(time.Unix(0, last)) > c.idleTimeout {
			return "the session was idle for longer than " + c.idleTimeout.String(), true
		}
	}
	return "", false
}

// terminate closes the session, telling the user why before the connection goes
// away so a disconnection does not look like a network fault.
func (c *connection) terminate(reason string) {
	if reason == "" {
		reason = "session terminated by policy"
	}
	c.setTerminated(reason)
	c.proxy.metrics.SessionsTerminated.Add(1)
	log.Printf("dp: session %s terminated: %s", c.sessionID, reason)

	c.channelsMu.Lock()
	channels := make([]*ssh.Channel, 0, len(c.channels))
	for ch := range c.channels {
		channels = append(channels, ch)
	}
	c.channelsMu.Unlock()

	notice := "\r\n[ssh-proxy] " + reason + "\r\n"
	for _, ch := range channels {
		_, _ = (*ch).Write([]byte(notice))
		_ = (*ch).Close()
	}
	_ = c.client.Close()
}

func (c *connection) setTerminated(reason string) {
	c.terminatedMu.Lock()
	if c.terminated == "" {
		c.terminated = reason
	}
	c.terminatedMu.Unlock()
}

func (c *connection) terminationReason() string {
	c.terminatedMu.Lock()
	defer c.terminatedMu.Unlock()
	return c.terminated
}

func (c *connection) trackChannel(ch ssh.Channel) {
	c.channelsMu.Lock()
	c.channels[&ch] = struct{}{}
	c.channelsMu.Unlock()
}

func (c *connection) untrackChannel(ch ssh.Channel) {
	c.channelsMu.Lock()
	for key := range c.channels {
		if *key == ch {
			delete(c.channels, key)
			break
		}
	}
	c.channelsMu.Unlock()
}

// close tears the session down and records the outcome.
func (c *connection) close(ctx context.Context) {
	c.closeOnce.Do(func() {
		close(c.closed)
		if c.upstream != nil {
			_ = c.upstream.Close()
		}
		if c.sessionID == "" {
			return
		}

		status := "closed"
		if c.terminationReason() != "" {
			status = "terminated"
		}
		c.emitSessionEnd(status, c.terminationReason())
		// A fresh context: the session's own may already be cancelled, and the
		// record of how it ended is the part that must not be lost.
		closeCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := c.proxy.pdp.CloseSession(closeCtx, &sshproxyv1.CloseSessionRequest{
			SessionId:       c.sessionID,
			BytesIn:         c.bytesIn.Load(),
			BytesOut:        c.bytesOut.Load(),
			Status:          status,
			TerminationInfo: c.terminationReason(),
			RecordingRef:    c.proxy.recordingFor(c.sessionID),
		}); err != nil {
			log.Printf("dp: record close of session %s: %v", c.sessionID, err)
		}
	})
}

// loginSpec is the SSH username decomposed into who is connecting, which
// account they want on the far side, and where.
type loginSpec struct {
	Principal string
	Login     string
	Target    string
}

// parseLoginSpec splits the SSH username.
//
// A client can only send one username, so the destination has to travel inside
// it. The accepted forms, from simplest to most explicit:
//
//	alice                  the principal; the target comes from policy
//	alice@web-1            the principal and the target
//	alice%root@web-1       the principal, the upstream account, and the target
//
// The principal always comes first, because it is what authentication runs
// against: putting the destination first would mean the account being
// authenticated depended on which host was requested.
func parseLoginSpec(sshUser string) loginSpec {
	spec := loginSpec{Principal: strings.TrimSpace(sshUser)}

	if idx := strings.Index(spec.Principal, "@"); idx > 0 {
		spec.Target = strings.TrimSpace(spec.Principal[idx+1:])
		spec.Principal = spec.Principal[:idx]
	}
	if idx := strings.Index(spec.Principal, "%"); idx > 0 {
		spec.Login = strings.TrimSpace(spec.Principal[idx+1:])
		spec.Principal = spec.Principal[:idx]
	}
	spec.Principal = strings.TrimSpace(spec.Principal)
	return spec
}

func hostOf(spec string) string {
	if spec == "" {
		return ""
	}
	if host, _, err := net.SplitHostPort(spec); err == nil {
		return host
	}
	return spec
}

func portOf(spec string) int {
	if spec == "" {
		return 0
	}
	if _, port, err := net.SplitHostPort(spec); err == nil {
		return atoi(port)
	}
	return 0
}
