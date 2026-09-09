package dp

import (
	"errors"
	"fmt"
	"strings"
	"time"
)

// Config describes a data-plane node.
type Config struct {
	// ListenAddr is where the SSH listener binds.
	ListenAddr string

	// NodeID identifies this node in session records and revocation routing.
	NodeID string

	// HostKeyPaths are the private keys this proxy presents to clients. At
	// least one is required: generating one silently on first start would mean
	// clients accept a different host key after every redeployment, training
	// people to click through the warning that exists to stop interception.
	HostKeyPaths []string

	// ServerVersion is the SSH identification string.
	ServerVersion string

	// Banner is shown before authentication.
	Banner string

	// RecordingDir is where session recordings are written.
	RecordingDir string

	// CaptureKeystrokes records what users type as well as what they see.
	// Off by default: keystrokes include passwords typed at upstream prompts.
	CaptureKeystrokes bool

	// CompressRecordings shrinks recordings by roughly an order of magnitude.
	// Terminal output is overwhelmingly repetitive, and the difference decides
	// whether keeping a year of sessions is affordable.
	CompressRecordings bool

	// RecordingEncryptionKey is a 32-byte hex key sealing recordings at rest.
	// A transcript contains whatever the user typed, including passwords
	// entered at an upstream prompt, so reading the disk should not be the
	// same as reading the sessions.
	RecordingEncryptionKey string

	// MaxSessions bounds concurrent connections on this node. Policy limits are
	// per user and enforced centrally; this is the node's own capacity guard.
	MaxSessions int

	// AuthTimeout bounds how long a connection may stay unauthenticated.
	AuthTimeout time.Duration

	// HeartbeatInterval is how often a live session reports to the control
	// plane. It also bounds how long a revocation takes to be noticed.
	HeartbeatInterval time.Duration

	// UpstreamDialTimeout bounds connecting to a target.
	UpstreamDialTimeout time.Duration

	// KeepAliveInterval sends keepalives to idle upstream connections so that
	// a firewall dropping the flow is detected rather than leaving a hung session.
	KeepAliveInterval time.Duration

	// DrainTimeout is how long Shutdown waits for sessions to end before
	// closing them.
	DrainTimeout time.Duration

	// AuditSpoolDir is where audit events are buffered before delivery. They go
	// to disk first so a session never waits on the control plane and a record
	// is not lost to a restart during an outage.
	AuditSpoolDir string

	// AuditSpoolSync forces each audit event to durable storage before the
	// session continues. It is the difference between surviving a process crash
	// and surviving a machine crash, at a substantial cost in throughput.
	AuditSpoolSync bool

	// AuditSpoolMaxBytes bounds the spool. Past it the oldest records are
	// dropped, because a proxy that fills its disk stops serving sessions.
	AuditSpoolMaxBytes int64

	// AuditFlushInterval is how often spooled events are shipped.
	AuditFlushInterval time.Duration

	// AuditChainKey is the key the tamper-evidence chain is computed under. It
	// must match the control plane's, or the records this node produces cannot
	// be verified there. Left empty, a per-process key is generated: the chain
	// still links records, but only this process can attest to it.
	AuditChainKey string
}

// DefaultConfig returns the shipped defaults.
func DefaultConfig() Config {
	return Config{
		ListenAddr:          "0.0.0.0:2222",
		ServerVersion:       "SSH-2.0-AuditProxy",
		RecordingDir:        "/var/lib/audit-proxy/recordings",
		MaxSessions:         1000,
		AuthTimeout:         60 * time.Second,
		HeartbeatInterval:   15 * time.Second,
		UpstreamDialTimeout: 15 * time.Second,
		KeepAliveInterval:   30 * time.Second,
		DrainTimeout:        30 * time.Second,
		AuditSpoolDir:       "/var/lib/audit-proxy/audit-spool",
		AuditSpoolMaxBytes:  1 << 30,
		AuditFlushInterval:  time.Second,
	}
}

func (c Config) withDefaults() Config {
	defaults := DefaultConfig()
	if c.ListenAddr == "" {
		c.ListenAddr = defaults.ListenAddr
	}
	if c.ServerVersion == "" {
		c.ServerVersion = defaults.ServerVersion
	}
	if c.RecordingDir == "" {
		c.RecordingDir = defaults.RecordingDir
	}
	if c.MaxSessions == 0 {
		c.MaxSessions = defaults.MaxSessions
	}
	if c.AuthTimeout == 0 {
		c.AuthTimeout = defaults.AuthTimeout
	}
	if c.HeartbeatInterval == 0 {
		c.HeartbeatInterval = defaults.HeartbeatInterval
	}
	if c.UpstreamDialTimeout == 0 {
		c.UpstreamDialTimeout = defaults.UpstreamDialTimeout
	}
	if c.KeepAliveInterval == 0 {
		c.KeepAliveInterval = defaults.KeepAliveInterval
	}
	if c.DrainTimeout == 0 {
		c.DrainTimeout = defaults.DrainTimeout
	}
	if c.AuditSpoolDir == "" {
		c.AuditSpoolDir = defaults.AuditSpoolDir
	}
	if c.AuditSpoolMaxBytes == 0 {
		c.AuditSpoolMaxBytes = defaults.AuditSpoolMaxBytes
	}
	if c.AuditFlushInterval == 0 {
		c.AuditFlushInterval = defaults.AuditFlushInterval
	}
	return c
}

// Validate reports configuration the node cannot run with.
func (c Config) Validate() error {
	if strings.TrimSpace(c.NodeID) == "" {
		return errors.New("dp: a node id is required so sessions can be attributed and revoked")
	}
	if len(c.HostKeyPaths) == 0 {
		return errors.New("dp: at least one host key is required")
	}
	if !strings.HasPrefix(c.ServerVersion, "SSH-2.0-") {
		return fmt.Errorf("dp: server version must begin with SSH-2.0-, got %q", c.ServerVersion)
	}
	if _, err := recordingKeyBytes(c.RecordingEncryptionKey); err != nil {
		return err
	}
	return nil
}
