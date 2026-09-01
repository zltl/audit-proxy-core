// Command dataplane runs an SSH proxy node.
//
// The node terminates client connections and moves bytes; it decides nothing on
// its own. Authentication, authorization, credentials, and command screening
// are all asked of the policy decision point at the moment they matter, which
// is what lets a revocation take effect immediately and keeps credential
// material out of the process exposed to untrusted clients.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/ssh-proxy-core/ssh-proxy-core/internal/dp"
	"github.com/ssh-proxy-core/ssh-proxy-core/internal/pdpclient"
)

func main() {
	log.SetFlags(log.LstdFlags | log.LUTC)

	var (
		listenAddr   = flag.String("listen", "0.0.0.0:2222", "address to accept SSH connections on")
		nodeID       = flag.String("node-id", defaultNodeID(), "identifier for this node in session records")
		hostKeys     = flag.String("host-keys", "", "comma-separated host key paths (required)")
		banner       = flag.String("banner", "", "text shown before authentication")
		recordingDir = flag.String("recording-dir", "/var/lib/ssh-proxy/recordings", "where session recordings are written")
		captureKeys  = flag.Bool("capture-keystrokes", false,
			"record what users type as well as what they see; keystrokes include passwords typed at upstream prompts")
		maxSessions = flag.Int("max-sessions", 1000, "concurrent connections this node will serve")

		pdpAddr     = flag.String("pdp", "unix:/run/ssh-proxy/pdp.sock", "policy decision point address, or unix:<path>")
		pdpInsecure = flag.Bool("pdp-insecure", false, "disable transport security; only valid for a local socket")
		pdpCA       = flag.String("pdp-ca", "", "CA certificate for verifying the decision point")
		pdpCert     = flag.String("pdp-cert", "", "client certificate presented to the decision point")
		pdpKey      = flag.String("pdp-key", "", "private key for the client certificate")
		pdpName     = flag.String("pdp-server-name", "", "expected server name in the decision point's certificate")
		failMode    = flag.String("fail-mode", "closed",
			"what to do when the decision point is unreachable: closed refuses new sessions, open admits them")
		cacheTTL = flag.Duration("decision-cache-ttl", 5*time.Second,
			"how long an authorization decision may be reused; also how long a revocation can lag")

		drainTimeout = flag.Duration("drain-timeout", 30*time.Second,
			"how long a shutdown waits for sessions to finish before closing them")
	)
	flag.Parse()

	if strings.TrimSpace(*hostKeys) == "" {
		fatal("--host-keys is required: a proxy that generates a host key on each start teaches users to ignore the warning that detects interception")
	}

	pdpConfig := pdpclient.Config{
		Address:        *pdpAddr,
		NodeID:         *nodeID,
		TLSCACert:      *pdpCA,
		TLSClientCert:  *pdpCert,
		TLSClientKey:   *pdpKey,
		TLSServerName:  *pdpName,
		Insecure:       *pdpInsecure,
		FailMode:       pdpclient.FailMode(*failMode),
		CacheTTL:       *cacheTTL,
		RequestTimeout: 10 * time.Second,
	}
	if err := pdpConfig.Validate(); err != nil {
		fatal(err.Error())
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	client, err := pdpclient.Dial(ctx, pdpConfig)
	if err != nil {
		fatal(fmt.Sprintf("connect to the policy decision point: %v", err))
	}
	defer func() { _ = client.Close() }()

	cfg := dp.DefaultConfig()
	cfg.ListenAddr = *listenAddr
	cfg.NodeID = *nodeID
	cfg.HostKeyPaths = splitList(*hostKeys)
	cfg.Banner = *banner
	cfg.RecordingDir = *recordingDir
	cfg.CaptureKeystrokes = *captureKeys
	cfg.MaxSessions = *maxSessions
	cfg.DrainTimeout = *drainTimeout

	server, err := dp.New(cfg, client)
	if err != nil {
		fatal(err.Error())
	}

	// SIGUSR1 starts a drain without stopping the process, which is how a node
	// is taken out of rotation for a rolling upgrade while the sessions already
	// on it are allowed to finish.
	drainSignals := make(chan os.Signal, 1)
	signal.Notify(drainSignals, syscall.SIGUSR1)
	go func() {
		for range drainSignals {
			log.Printf("dataplane: draining on request; %d session(s) active", server.ActiveSessions())
			server.Drain()
		}
	}()

	serveErr := make(chan error, 1)
	go func() { serveErr <- server.Serve(ctx) }()

	select {
	case err := <-serveErr:
		if err != nil {
			fatal(err.Error())
		}
	case <-ctx.Done():
		log.Printf("dataplane: shutting down; %d session(s) active", server.ActiveSessions())
		shutdownCtx, cancel := context.WithTimeout(context.Background(), *drainTimeout+5*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdownCtx); err != nil {
			log.Printf("dataplane: shutdown: %v", err)
		}
	}
}

func splitList(raw string) []string {
	var out []string
	for _, field := range strings.Split(raw, ",") {
		if trimmed := strings.TrimSpace(field); trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out
}

// defaultNodeID prefers the hostname so that sessions in a shared database can
// be attributed to a machine without extra configuration.
func defaultNodeID() string {
	if host, err := os.Hostname(); err == nil && host != "" {
		return host
	}
	return "dataplane"
}

func fatal(message string) {
	fmt.Fprintln(os.Stderr, "dataplane: "+message)
	os.Exit(1)
}
