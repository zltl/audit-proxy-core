// Package dp is the SSH data plane: it terminates client connections, decides
// nothing on its own, and proxies to the target under the constraints the
// policy decision point returns.
//
// Everything that could grant access is a question asked of the control plane
// at the moment it matters. What lives here is the part that has to be here:
// speaking SSH correctly, moving bytes, and capturing what happened.
package dp

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/ssh"

	auditproxyv1 "github.com/zltl/audit-proxy-core/api/proto/auditproxy/v1"
	"github.com/zltl/audit-proxy-core/internal/pdpclient"
)

// Server is a data-plane node.
type Server struct {
	config      Config
	pdp         *pdpclient.Client
	hostSigners []ssh.Signer

	authState *authStateTable
	audit     *auditEmitter
	metrics   *Metrics
	// recordingKey seals recordings at rest when configured.
	recordingKey []byte

	listenerMu sync.Mutex
	listener   net.Listener

	connectionsMu sync.Mutex
	connections   map[*connection]struct{}

	// draining stops new connections from being accepted while letting
	// established ones finish, which is what makes a rolling restart invisible
	// to anyone already working.
	draining atomic.Bool

	// recordings maps session ids to their recording paths so the close report
	// can reference them.
	recordingsMu sync.Mutex
	recordings   map[string]string

	shutdownOnce sync.Once
	shutdown     chan struct{}
}

// New builds a data-plane node.
func New(cfg Config, pdp *pdpclient.Client) (*Server, error) {
	cfg = cfg.withDefaults()
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	if pdp == nil {
		return nil, errors.New("dp: a policy decision point client is required")
	}

	signers, err := loadHostKeys(cfg.HostKeyPaths)
	if err != nil {
		return nil, err
	}

	recordingKey, err := recordingKeyBytes(cfg.RecordingEncryptionKey)
	if err != nil {
		return nil, err
	}

	emitter, err := newAuditEmitter(auditEmitterOptions{
		NodeID:         cfg.NodeID,
		Dir:            cfg.AuditSpoolDir,
		SyncEveryWrite: cfg.AuditSpoolSync,
		MaxTotalBytes:  cfg.AuditSpoolMaxBytes,
		ChainKey:       auditChainKeyBytes(cfg.AuditChainKey),
	}, pdp)
	if err != nil {
		return nil, err
	}

	server := &Server{
		config:       cfg,
		pdp:          pdp,
		hostSigners:  signers,
		authState:    newAuthStateTable(),
		audit:        emitter,
		metrics:      NewMetrics(),
		recordingKey: recordingKey,
		connections:  make(map[*connection]struct{}),
		recordings:   make(map[string]string),
		shutdown:     make(chan struct{}),
	}
	// The emitter reports through the same registry, so audit backlog and
	// delivery show up alongside everything else rather than needing a
	// separate place to look.
	emitter.metrics = server.metrics
	server.registerGauges()
	return server, nil
}

// loadHostKeys reads the private keys the proxy presents to clients.
// auditChainKeyBytes decodes the configured chain key, accepting hex or a
// passphrase so an operator gets what they intended rather than a silent
// fallback to no shared key.
func auditChainKeyBytes(raw string) []byte {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	if decoded, err := hex.DecodeString(raw); err == nil && len(decoded) >= 16 {
		return decoded
	}
	return []byte(raw)
}

func loadHostKeys(paths []string) ([]ssh.Signer, error) {
	signers := make([]ssh.Signer, 0, len(paths))
	for _, path := range paths {
		raw, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("dp: read host key %s: %w", path, err)
		}
		signer, err := ssh.ParsePrivateKey(raw)
		if err != nil {
			return nil, fmt.Errorf("dp: parse host key %s: %w", path, err)
		}
		signers = append(signers, signer)
	}
	if len(signers) == 0 {
		return nil, errors.New("dp: no usable host keys were loaded")
	}
	return signers, nil
}

// Serve accepts connections until the context ends or Shutdown is called.
func (s *Server) Serve(ctx context.Context) error {
	listener, err := net.Listen("tcp", s.config.ListenAddr)
	if err != nil {
		return fmt.Errorf("dp: listen on %s: %w", s.config.ListenAddr, err)
	}
	return s.serveListener(ctx, listener)
}

// ServeListener runs on an already-bound listener, which is how a socket is
// inherited across a restart and how tests avoid binding a real port.
func (s *Server) ServeListener(ctx context.Context, listener net.Listener) error {
	return s.serveListener(ctx, listener)
}

func (s *Server) serveListener(ctx context.Context, listener net.Listener) error {
	s.listenerMu.Lock()
	s.listener = listener
	s.listenerMu.Unlock()

	log.Printf("dp: node %s listening on %s", s.config.NodeID, listener.Addr())

	// Revocations arrive out of band as well as on the heartbeat, so a kill
	// takes effect promptly rather than at the next heartbeat interval.
	go s.pdp.WatchRevocations(ctx, s.applyRevocation)
	go s.audit.Run(ctx, s.config.AuditFlushInterval)

	var wg sync.WaitGroup
	defer wg.Wait()

	for {
		conn, err := listener.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return nil
			case <-s.shutdown:
				return nil
			default:
			}
			var netErr net.Error
			if errors.As(err, &netErr) && netErr.Timeout() {
				continue
			}
			return fmt.Errorf("dp: accept: %w", err)
		}

		if s.draining.Load() {
			// During a drain the listener is usually already closed; this covers
			// a connection accepted in the race and makes the refusal explicit
			// rather than dropping it silently.
			_ = conn.Close()
			continue
		}
		if s.connectionCount() >= s.config.MaxSessions {
			log.Printf("dp: refusing %s: node is at its %d session capacity",
				conn.RemoteAddr(), s.config.MaxSessions)
			_ = conn.Close()
			continue
		}

		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() {
				if r := recover(); r != nil {
					// One malformed connection must not take the node down with
					// every other session on it.
					log.Printf("dp: recovered from a panic handling %s: %v", conn.RemoteAddr(), r)
				}
			}()
			s.handle(ctx, conn)
		}()
	}
}

// Addr reports the bound address.
func (s *Server) Addr() net.Addr {
	s.listenerMu.Lock()
	defer s.listenerMu.Unlock()
	if s.listener == nil {
		return nil
	}
	return s.listener.Addr()
}

// Drain stops accepting new connections while leaving established ones alone.
func (s *Server) Drain() {
	if s.draining.Swap(true) {
		return
	}
	log.Printf("dp: node %s draining; %d sessions still active", s.config.NodeID, s.connectionCount())
	s.listenerMu.Lock()
	if s.listener != nil {
		_ = s.listener.Close()
	}
	s.listenerMu.Unlock()
}

// Draining reports whether the node is refusing new connections.
func (s *Server) Draining() bool { return s.draining.Load() }

// ActiveSessions reports how many connections are being served.
func (s *Server) ActiveSessions() int { return s.connectionCount() }

// Shutdown drains, waits for sessions to finish, then closes what remains.
func (s *Server) Shutdown(ctx context.Context) error {
	s.Drain()
	s.shutdownOnce.Do(func() { close(s.shutdown) })

	deadline := time.Now().Add(s.config.DrainTimeout)
	for time.Now().Before(deadline) {
		if s.connectionCount() == 0 {
			return nil
		}
		select {
		case <-ctx.Done():
			// The caller gave up waiting; fall through and close.
		case <-time.After(200 * time.Millisecond):
			continue
		}
		break
	}

	remaining := s.connectionCount()
	if remaining > 0 {
		log.Printf("dp: closing %d session(s) that outlasted the drain timeout", remaining)
		s.closeAllConnections("the proxy is shutting down")
	}

	// The spool is flushed last so that the events of the sessions just closed
	// are included rather than left behind.
	if pending := s.audit.Pending(); pending > 0 {
		log.Printf("dp: %d bytes of audit events are still spooled at shutdown", pending)
	}
	return s.audit.Close()
}

// AuditBacklog reports how many bytes of audit events are awaiting delivery,
// which is what distinguishes a brief hiccup from an outage that is piling up.
func (s *Server) AuditBacklog() int64 { return s.audit.Pending() }

func (s *Server) trackConnection(c *connection) {
	s.connectionsMu.Lock()
	s.connections[c] = struct{}{}
	s.connectionsMu.Unlock()
}

func (s *Server) untrackConnection(c *connection) {
	s.connectionsMu.Lock()
	delete(s.connections, c)
	s.connectionsMu.Unlock()
}

func (s *Server) connectionCount() int {
	s.connectionsMu.Lock()
	defer s.connectionsMu.Unlock()
	return len(s.connections)
}

func (s *Server) closeAllConnections(reason string) {
	s.connectionsMu.Lock()
	conns := make([]*connection, 0, len(s.connections))
	for c := range s.connections {
		conns = append(conns, c)
	}
	s.connectionsMu.Unlock()

	for _, c := range conns {
		c.terminate(reason)
	}
}

// applyRevocation disconnects a session an operator asked to terminate.
func (s *Server) applyRevocation(rev *auditproxyv1.Revocation) {
	s.connectionsMu.Lock()
	var match *connection
	for c := range s.connections {
		if c.sessionID == rev.GetSessionId() {
			match = c
			break
		}
	}
	s.connectionsMu.Unlock()

	if match == nil {
		// The session already ended, or belongs to another node. Either way
		// there is nothing to close here.
		return
	}
	match.terminate(rev.GetReason())
}

// noteRecording remembers where a session's recording is being written.
func (c *connection) noteRecording(path string) {
	c.proxy.recordingsMu.Lock()
	c.proxy.recordings[c.sessionID] = path
	c.proxy.recordingsMu.Unlock()
}

func (s *Server) recordingFor(sessionID string) string {
	s.recordingsMu.Lock()
	defer s.recordingsMu.Unlock()
	path := s.recordings[sessionID]
	delete(s.recordings, sessionID)
	return path
}

// transfersForTest exposes the file transfers recorded across live sessions.
func (s *Server) transfersForTest() []FileTransfer {
	s.connectionsMu.Lock()
	conns := make([]*connection, 0, len(s.connections))
	for c := range s.connections {
		conns = append(conns, c)
	}
	s.connectionsMu.Unlock()

	var all []FileTransfer
	for _, c := range conns {
		all = append(all, c.Transfers()...)
	}
	return all
}
