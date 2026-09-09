package dp

import (
	"fmt"
	"log"
	"net/http"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
)

// Metrics reports what an operator needs to tell a healthy node from one that
// is quietly failing.
//
// The interesting numbers here are not throughput. They are the ones that say
// whether the proxy is still enforcing anything: how often the policy could not
// be consulted, how many host keys were refused, and how far behind audit
// delivery has fallen. A node that serves sessions happily while none of that
// works looks fine on a traffic graph.
type Metrics struct {
	SessionsStarted    atomic.Int64
	SessionsRejected   atomic.Int64
	SessionsActive     atomic.Int64
	SessionsTerminated atomic.Int64

	AuthAttempts atomic.Int64
	AuthFailures atomic.Int64

	ChannelsOpened  atomic.Int64
	ChannelsRefused atomic.Int64

	CommandsScreened atomic.Int64
	CommandsBlocked  atomic.Int64

	TransfersRecorded atomic.Int64
	TransfersRefused  atomic.Int64

	ForwardsOpened  atomic.Int64
	ForwardsRefused atomic.Int64

	// HostKeysRefused counts upstreams the proxy declined to connect to. A
	// sudden rise is either a fleet rotating host keys or an interception, and
	// both are worth waking up for.
	HostKeysRefused atomic.Int64

	// PolicyUnavailable counts decisions that could not be obtained. Under
	// fail-closed this is refused work; under fail-open it is work that
	// happened without being checked, which is the more alarming case.
	PolicyUnavailable atomic.Int64

	AuditEventsEmitted   atomic.Int64
	AuditEventsDelivered atomic.Int64
	AuditEventsDropped   atomic.Int64

	RecordingsStarted atomic.Int64
	RecordingsFailed  atomic.Int64

	// gauges are read at scrape time rather than tracked incrementally, so
	// they cannot drift away from reality.
	gaugesMu sync.RWMutex
	gauges   map[string]func() float64
}

// NewMetrics creates a metrics registry.
func NewMetrics() *Metrics {
	return &Metrics{gauges: make(map[string]func() float64)}
}

// SetGauge registers a value sampled when metrics are scraped.
func (m *Metrics) SetGauge(name string, read func() float64) {
	if m == nil {
		return
	}
	m.gaugesMu.Lock()
	defer m.gaugesMu.Unlock()
	m.gauges[name] = read
}

// metric describes one exported series.
type metric struct {
	name  string
	help  string
	kind  string
	value float64
}

func (m *Metrics) snapshot() []metric {
	if m == nil {
		return nil
	}
	counters := []struct {
		name  string
		help  string
		value int64
	}{
		{"audit_proxy_sessions_started_total", "Sessions that were authorized and connected.", m.SessionsStarted.Load()},
		{"audit_proxy_sessions_rejected_total", "Connections refused before a session was established.", m.SessionsRejected.Load()},
		{"audit_proxy_sessions_terminated_total", "Sessions ended by policy rather than by the user.", m.SessionsTerminated.Load()},
		{"audit_proxy_auth_attempts_total", "Authentication attempts of any method.", m.AuthAttempts.Load()},
		{"audit_proxy_auth_failures_total", "Authentication attempts that were refused.", m.AuthFailures.Load()},
		{"audit_proxy_channels_opened_total", "Channels opened across all sessions.", m.ChannelsOpened.Load()},
		{"audit_proxy_channels_refused_total", "Channels refused by policy.", m.ChannelsRefused.Load()},
		{"audit_proxy_commands_screened_total", "Commands submitted to the command policy.", m.CommandsScreened.Load()},
		{"audit_proxy_commands_blocked_total", "Commands the policy refused.", m.CommandsBlocked.Load()},
		{"audit_proxy_transfers_total", "File transfers observed.", m.TransfersRecorded.Load()},
		{"audit_proxy_transfers_refused_total", "File transfers refused by policy.", m.TransfersRefused.Load()},
		{"audit_proxy_forwards_total", "Port forwards opened.", m.ForwardsOpened.Load()},
		{"audit_proxy_forwards_refused_total", "Port forwards refused by policy.", m.ForwardsRefused.Load()},
		{"audit_proxy_host_keys_refused_total", "Upstream connections refused over an untrusted host key.", m.HostKeysRefused.Load()},
		{"audit_proxy_policy_unavailable_total", "Decisions that could not be obtained from the control plane.", m.PolicyUnavailable.Load()},
		{"audit_proxy_audit_events_emitted_total", "Audit events produced.", m.AuditEventsEmitted.Load()},
		{"audit_proxy_audit_events_delivered_total", "Audit events accepted by the control plane.", m.AuditEventsDelivered.Load()},
		{"audit_proxy_audit_events_dropped_total", "Audit events discarded to stay within the spool budget.", m.AuditEventsDropped.Load()},
		{"audit_proxy_recordings_started_total", "Session recordings started.", m.RecordingsStarted.Load()},
		{"audit_proxy_recordings_failed_total", "Session recordings that could not be started.", m.RecordingsFailed.Load()},
	}

	out := make([]metric, 0, len(counters)+4)
	for _, c := range counters {
		out = append(out, metric{name: c.name, help: c.help, kind: "counter", value: float64(c.value)})
	}

	m.gaugesMu.RLock()
	names := make([]string, 0, len(m.gauges))
	for name := range m.gauges {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		out = append(out, metric{name: name, kind: "gauge", value: m.gauges[name]()})
	}
	m.gaugesMu.RUnlock()

	return out
}

// Render writes the metrics in the Prometheus text exposition format.
func (m *Metrics) Render() string {
	var b strings.Builder
	for _, item := range m.snapshot() {
		if item.help != "" {
			fmt.Fprintf(&b, "# HELP %s %s\n", item.name, item.help)
		}
		fmt.Fprintf(&b, "# TYPE %s %s\n", item.name, item.kind)
		fmt.Fprintf(&b, "%s %g\n", item.name, item.value)
	}
	return b.String()
}

// Handler serves the metrics endpoint.
func (m *Metrics) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		_, _ = w.Write([]byte(m.Render()))
	})
}

// --------------------------------------------------------------------------
// Node instrumentation
// --------------------------------------------------------------------------

// Metrics returns the node's metrics registry.
func (s *Server) Metrics() *Metrics { return s.metrics }

// registerGauges wires the values that are read rather than counted.
func (s *Server) registerGauges() {
	s.metrics.SetGauge("audit_proxy_sessions_active", func() float64 {
		return float64(s.connectionCount())
	})
	s.metrics.SetGauge("audit_proxy_audit_spool_bytes", func() float64 {
		return float64(s.audit.Pending())
	})
	s.metrics.SetGauge("audit_proxy_draining", func() float64 {
		if s.draining.Load() {
			return 1
		}
		return 0
	})
	s.metrics.SetGauge("audit_proxy_control_plane_healthy", func() float64 {
		if healthy, _ := s.pdp.Healthy(); healthy {
			return 1
		}
		return 0
	})
}

// ServeMetrics runs an HTTP listener exposing metrics and readiness.
//
// It is a separate listener from the SSH port so that scraping does not require
// reaching the proxy's data path, and so it can be bound to an interface the
// monitoring system can see and clients cannot.
func (s *Server) ServeMetrics(address string) (func() error, error) {
	if strings.TrimSpace(address) == "" {
		return func() error { return nil }, nil
	}
	mux := http.NewServeMux()
	mux.Handle("GET /metrics", s.metrics.Handler())
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok\n"))
	})
	mux.Handle("GET /readyz", s.readinessHandler())

	server := &http.Server{Addr: address, Handler: mux}
	go func() {
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Printf("dp: metrics listener stopped: %v", err)
		}
	}()
	return server.Close, nil
}

// readinessHandler reports whether the node should receive new connections.
func (s *Server) readinessHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		// Draining reports not-ready so a load balancer stops sending new
		// connections while the sessions already here finish.
		if s.draining.Load() {
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte("draining\n"))
			return
		}
		if healthy, err := s.pdp.Healthy(); !healthy {
			// A node that cannot reach the policy cannot admit anybody under
			// fail-closed, so it should not be in rotation.
			w.WriteHeader(http.StatusServiceUnavailable)
			fmt.Fprintf(w, "control plane unreachable: %v\n", err)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ready\n"))
	})
}
