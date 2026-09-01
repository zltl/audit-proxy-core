// Package pdpclient is the data plane's connection to the policy decision
// point.
//
// Every decision the proxy makes is a round trip to the control plane, which is
// what allows a revocation to take effect immediately. That also makes the
// control plane a dependency of every new connection, so this package decides
// deliberately what happens when it is unreachable: by default nothing new is
// admitted, because an access proxy that keeps letting people in when it cannot
// check the policy is not enforcing one.
package pdpclient

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"

	sshproxyv1 "github.com/ssh-proxy-core/ssh-proxy-core/api/proto/sshproxy/v1"
)

// FailMode decides what happens when the decision point cannot be reached.
type FailMode string

const (
	// FailClosed refuses anything that cannot be checked. This is the default:
	// an access proxy that admits connections it could not authorize is not
	// enforcing a policy, it is only logging one.
	FailClosed FailMode = "closed"
	// FailOpen keeps serving from the last known policy. It trades enforcement
	// accuracy for availability and should only be chosen deliberately.
	FailOpen FailMode = "open"
)

// Config describes how to reach the decision point.
type Config struct {
	// Address is a TCP address, or a "unix:" path for a local socket. A local
	// socket is preferred when the two run on the same host: it avoids exposing
	// the decision API on the network at all.
	Address string

	// NodeID identifies this data-plane node, so revocations can be routed to
	// whichever node holds the affected session.
	NodeID string

	// TLS settings for a remote decision point. Client certificates are
	// required rather than optional, because anything that can call this API
	// can ask for credentials.
	TLSCACert     string
	TLSClientCert string
	TLSClientKey  string
	TLSServerName string

	// Insecure disables transport security. It exists for a local socket and
	// for tests, and refuses to apply to a network address.
	Insecure bool

	FailMode FailMode

	// DialTimeout and RequestTimeout bound how long a connection attempt waits
	// on the control plane before the fail mode applies.
	DialTimeout    time.Duration
	RequestTimeout time.Duration

	// CacheTTL is how long an authorization decision may be reused. Short by
	// design: it absorbs bursts without letting a revoked grant linger.
	CacheTTL time.Duration
}

func (c Config) withDefaults() Config {
	if c.FailMode == "" {
		c.FailMode = FailClosed
	}
	if c.DialTimeout == 0 {
		c.DialTimeout = 5 * time.Second
	}
	if c.RequestTimeout == 0 {
		c.RequestTimeout = 10 * time.Second
	}
	if c.CacheTTL == 0 {
		c.CacheTTL = 5 * time.Second
	}
	return c
}

// Validate reports configuration that cannot be honoured safely.
func (c Config) Validate() error {
	if strings.TrimSpace(c.Address) == "" {
		return errors.New("pdpclient: an address is required")
	}
	if strings.TrimSpace(c.NodeID) == "" {
		return errors.New("pdpclient: a node id is required so revocations can be routed")
	}
	if c.FailMode != "" && c.FailMode != FailClosed && c.FailMode != FailOpen {
		return fmt.Errorf("pdpclient: unknown fail mode %q", c.FailMode)
	}
	if c.Insecure && !isLocalSocket(c.Address) {
		return errors.New("pdpclient: transport security may only be disabled for a local unix socket")
	}
	if !c.Insecure && !isLocalSocket(c.Address) {
		if strings.TrimSpace(c.TLSClientCert) == "" || strings.TrimSpace(c.TLSClientKey) == "" {
			return errors.New("pdpclient: a client certificate is required to reach a remote decision point")
		}
	}
	return nil
}

func isLocalSocket(address string) bool {
	return strings.HasPrefix(address, "unix:") || strings.HasPrefix(address, "/")
}

// Client talks to the decision point.
type Client struct {
	config Config
	conn   *grpc.ClientConn
	api    sshproxyv1.AccessDecisionServiceClient

	cache *decisionCache

	// healthy tracks whether the last call succeeded, so the fail mode is only
	// consulted when it is actually relevant.
	healthyMu sync.RWMutex
	healthy   bool
	lastError error
}

// Dial connects to the decision point.
func Dial(ctx context.Context, cfg Config) (*Client, error) {
	cfg = cfg.withDefaults()
	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	transport, err := transportCredentials(cfg)
	if err != nil {
		return nil, err
	}

	target := cfg.Address
	var dialOpts []grpc.DialOption
	dialOpts = append(dialOpts, grpc.WithTransportCredentials(transport))
	if path, ok := strings.CutPrefix(cfg.Address, "unix:"); ok {
		target = "unix:" + path
		dialOpts = append(dialOpts, grpc.WithContextDialer(func(ctx context.Context, addr string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", strings.TrimPrefix(addr, "unix:"))
		}))
	}

	dialCtx, cancel := context.WithTimeout(ctx, cfg.DialTimeout)
	defer cancel()
	conn, err := grpc.DialContext(dialCtx, target, dialOpts...)
	if err != nil {
		return nil, fmt.Errorf("pdpclient: dial %s: %w", cfg.Address, err)
	}

	return &Client{
		config:  cfg,
		conn:    conn,
		api:     sshproxyv1.NewAccessDecisionServiceClient(conn),
		cache:   newDecisionCache(cfg.CacheTTL),
		healthy: true,
	}, nil
}

// NewWithConn wraps an existing connection, which is how tests and in-process
// deployments avoid a real network hop.
func NewWithConn(conn *grpc.ClientConn, cfg Config) *Client {
	cfg = cfg.withDefaults()
	return &Client{
		config:  cfg,
		conn:    conn,
		api:     sshproxyv1.NewAccessDecisionServiceClient(conn),
		cache:   newDecisionCache(cfg.CacheTTL),
		healthy: true,
	}
}

func transportCredentials(cfg Config) (credentials.TransportCredentials, error) {
	if cfg.Insecure {
		return insecure.NewCredentials(), nil
	}

	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS13}
	if name := strings.TrimSpace(cfg.TLSServerName); name != "" {
		tlsConfig.ServerName = name
	}
	if path := strings.TrimSpace(cfg.TLSCACert); path != "" {
		pem, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("pdpclient: read CA certificate: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("pdpclient: %s contains no usable certificates", path)
		}
		tlsConfig.RootCAs = pool
	}
	if cert := strings.TrimSpace(cfg.TLSClientCert); cert != "" {
		pair, err := tls.LoadX509KeyPair(cert, strings.TrimSpace(cfg.TLSClientKey))
		if err != nil {
			return nil, fmt.Errorf("pdpclient: load client certificate: %w", err)
		}
		tlsConfig.Certificates = []tls.Certificate{pair}
	}
	return credentials.NewTLS(tlsConfig), nil
}

// Close releases the connection.
func (c *Client) Close() error {
	if c == nil || c.conn == nil {
		return nil
	}
	return c.conn.Close()
}

// NodeID reports this node's identifier.
func (c *Client) NodeID() string { return c.config.NodeID }

// Healthy reports whether the last call to the decision point succeeded, along
// with the error that made it unhealthy.
func (c *Client) Healthy() (bool, error) {
	c.healthyMu.RLock()
	defer c.healthyMu.RUnlock()
	return c.healthy, c.lastError
}

func (c *Client) markHealthy() {
	c.healthyMu.Lock()
	c.healthy = true
	c.lastError = nil
	c.healthyMu.Unlock()
}

func (c *Client) markUnhealthy(err error) {
	c.healthyMu.Lock()
	c.healthy = false
	c.lastError = err
	c.healthyMu.Unlock()
}

// callContext bounds a single request.
func (c *Client) callContext(parent context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(parent, c.config.RequestTimeout)
}

// unreachable reports whether an error means the decision point could not be
// consulted, as opposed to having answered with a refusal. Only the former
// engages the fail mode: a deliberate denial must never be softened by it.
func unreachable(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		return true
	}
	var netErr net.Error
	if errors.As(err, &netErr) {
		return true
	}
	// gRPC surfaces transport problems as Unavailable; anything else came from
	// the service itself and is a real answer.
	return strings.Contains(err.Error(), "Unavailable") ||
		strings.Contains(err.Error(), "connection refused") ||
		strings.Contains(err.Error(), "transport is closing")
}
