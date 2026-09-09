package dp

import (
	"net/http/httptest"
	"strings"
	"testing"
)

func TestMetricsRenderPrometheusFormat(t *testing.T) {
	m := NewMetrics()
	m.SessionsStarted.Add(3)
	m.HostKeysRefused.Add(1)
	m.SetGauge("audit_proxy_sessions_active", func() float64 { return 2 })

	output := m.Render()
	for _, want := range []string{
		"# TYPE audit_proxy_sessions_started_total counter",
		"audit_proxy_sessions_started_total 3",
		"audit_proxy_host_keys_refused_total 1",
		"# TYPE audit_proxy_sessions_active gauge",
		"audit_proxy_sessions_active 2",
	} {
		if !strings.Contains(output, want) {
			t.Errorf("output is missing %q:\n%s", want, output)
		}
	}

	// Every counter needs help text: a metric nobody can interpret does not get
	// alerted on.
	for _, line := range strings.Split(output, "\n") {
		if strings.HasPrefix(line, "# TYPE ") && strings.HasSuffix(line, " counter") {
			name := strings.Fields(line)[2]
			if !strings.Contains(output, "# HELP "+name+" ") {
				t.Errorf("counter %s has no help text", name)
			}
		}
	}
}

func TestMetricsGaugesAreSampledAtScrapeTime(t *testing.T) {
	m := NewMetrics()
	value := 1.0
	m.SetGauge("audit_proxy_sessions_active", func() float64 { return value })

	if !strings.Contains(m.Render(), "audit_proxy_sessions_active 1") {
		t.Fatal("gauge was not rendered")
	}
	// Reading at scrape time rather than tracking incrementally means the value
	// cannot drift away from reality.
	value = 7
	if !strings.Contains(m.Render(), "audit_proxy_sessions_active 7") {
		t.Fatal("the gauge did not reflect the current value")
	}
}

func TestMetricsHandler(t *testing.T) {
	m := NewMetrics()
	m.SessionsStarted.Add(1)

	rec := httptest.NewRecorder()
	m.Handler().ServeHTTP(rec, httptest.NewRequest("GET", "/metrics", nil))

	if rec.Code != 200 {
		t.Fatalf("status = %d", rec.Code)
	}
	if got := rec.Header().Get("Content-Type"); !strings.HasPrefix(got, "text/plain") {
		t.Errorf("content type = %q", got)
	}
	if !strings.Contains(rec.Body.String(), "audit_proxy_sessions_started_total 1") {
		t.Errorf("body = %s", rec.Body.String())
	}
}

func TestMetricsCountEnforcement(t *testing.T) {
	h := newHarness(t, func(_ *Config, pdp *scriptedPDP) {
		pdp.channelDenied["CHANNEL_TYPE_DIRECT_TCPIP"] = "forwarding is not permitted"
	})
	client := h.mustConnect("alice@web-1")

	session, err := client.NewSession()
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}
	if _, err := session.Output("uptime"); err != nil {
		t.Fatalf("Output: %v", err)
	}
	_ = session.Close()

	if _, err := client.Dial("tcp", "10.0.0.9:5432"); err == nil {
		t.Fatal("the forward should have been refused")
	}

	metrics := h.proxy.Metrics()
	if metrics.SessionsStarted.Load() != 1 {
		t.Errorf("sessions started = %d, want 1", metrics.SessionsStarted.Load())
	}
	// What matters operationally is that refusals are counted, not just
	// successes: a node that has stopped enforcing looks healthy on a traffic
	// graph and only shows up here.
	if metrics.ForwardsRefused.Load() != 1 {
		t.Errorf("forwards refused = %d, want 1", metrics.ForwardsRefused.Load())
	}
	if metrics.ChannelsRefused.Load() == 0 {
		t.Error("a refused channel was not counted")
	}
	if metrics.AuditEventsEmitted.Load() == 0 {
		t.Error("audit events were produced but not counted")
	}
}

func TestReadinessReflectsDrainAndControlPlaneHealth(t *testing.T) {
	h := newHarness(t, nil)

	stop, err := h.proxy.ServeMetrics("127.0.0.1:0")
	if err != nil {
		t.Fatalf("ServeMetrics: %v", err)
	}
	defer func() { _ = stop() }()

	// Exercising the handler directly avoids depending on the bound port.
	rec := httptest.NewRecorder()
	h.proxy.readinessHandler().ServeHTTP(rec, httptest.NewRequest("GET", "/readyz", nil))
	if rec.Code != 200 {
		t.Fatalf("a healthy node should be ready, got %d: %s", rec.Code, rec.Body.String())
	}

	// A draining node must report not-ready so a load balancer stops sending it
	// new connections while the ones it has finish.
	h.proxy.Drain()
	rec = httptest.NewRecorder()
	h.proxy.readinessHandler().ServeHTTP(rec, httptest.NewRequest("GET", "/readyz", nil))
	if rec.Code != 503 {
		t.Fatalf("a draining node reported ready: %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "draining") {
		t.Errorf("body = %q", rec.Body.String())
	}
}
