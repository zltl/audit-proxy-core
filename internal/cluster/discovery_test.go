package cluster

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"sync"
	"testing"
	"time"
)

type stubHostResolver struct {
	hosts map[string][]string
}

func (s stubHostResolver) LookupHost(_ context.Context, host string) ([]string, error) {
	addresses, ok := s.hosts[host]
	if !ok {
		return nil, fmt.Errorf("host %s not found", host)
	}
	return addresses, nil
}

func TestValidateSeedReferenceSupportsDiscoverySchemes(t *testing.T) {
	valid := []string{
		"10.0.0.10:9444",
		"dns://proxy.internal:9444",
		"k8s://ssh-proxy.default:9444",
		"consul://127.0.0.1:8500/ssh-proxy?tag=prod",
	}
	for _, seed := range valid {
		if err := ValidateSeedReference(seed); err != nil {
			t.Fatalf("ValidateSeedReference(%q) error = %v", seed, err)
		}
	}

	if err := ValidateSeedReference("ftp://proxy.internal:9444"); err == nil {
		t.Fatal("expected unsupported scheme to fail validation")
	}
}

func TestResolveSeedReferencesWithDNSAndKubernetes(t *testing.T) {
	addresses, err := resolveSeedReferencesWith(
		context.Background(),
		[]string{
			"dns://proxy.internal:9444",
			"k8s://ssh-proxy.default:9444",
		},
		stubHostResolver{
			hosts: map[string][]string{
				"proxy.internal":                      {"10.0.0.10", "10.0.0.11"},
				"ssh-proxy.default.svc.cluster.local": {"10.3.0.21"},
			},
		},
		nil,
	)
	if err != nil {
		t.Fatalf("resolveSeedReferencesWith() error = %v", err)
	}

	expected := []string{"10.0.0.10:9444", "10.0.0.11:9444", "10.3.0.21:9444"}
	for _, want := range expected {
		if !slices.Contains(addresses, want) {
			t.Fatalf("resolved addresses = %v, want %q", addresses, want)
		}
	}
}

func TestResolveSeedReferencesWithConsul(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/health/service/ssh-proxy" {
			t.Fatalf("unexpected path %q", r.URL.Path)
		}
		if got := r.URL.Query().Get("passing"); got != "1" {
			t.Fatalf("passing query = %q, want 1", got)
		}
		if got := r.URL.Query().Get("tag"); got != "prod" {
			t.Fatalf("tag query = %q, want prod", got)
		}
		_ = json.NewEncoder(w).Encode([]map[string]any{
			{
				"Node": map[string]any{"Address": "10.1.0.5"},
				"Service": map[string]any{
					"Address": "10.2.0.9",
					"Port":    9444,
				},
			},
		})
	}))
	defer server.Close()

	parsed, err := url.Parse(server.URL)
	if err != nil {
		t.Fatalf("Parse(server.URL) error = %v", err)
	}

	addresses, err := resolveSeedReferencesWith(
		context.Background(),
		[]string{fmt.Sprintf("consul://%s/ssh-proxy?tag=prod", parsed.Host)},
		stubHostResolver{},
		server.Client(),
	)
	if err != nil {
		t.Fatalf("resolveSeedReferencesWith(consul) error = %v", err)
	}
	if len(addresses) != 1 || addresses[0] != "10.2.0.9:9444" {
		t.Fatalf("resolved addresses = %v, want [10.2.0.9:9444]", addresses)
	}
}

func TestJoinWithDNSDiscoverySeed(t *testing.T) {
	m1 := startManager(t, testConfig("node-1", "Node 1", "127.0.0.1:0"))
	_, port, err := net.SplitHostPort(m1.Self().Address)
	if err != nil {
		t.Fatalf("SplitHostPort(m1 addr) error = %v", err)
	}

	cfg2 := testConfig("node-2", "Node 2", "127.0.0.1:0")
	cfg2.Seeds = []string{fmt.Sprintf("dns://localhost:%s", port)}
	m2 := startManager(t, cfg2)

	time.Sleep(500 * time.Millisecond)
	if m1.NodeCount() < 2 || m2.NodeCount() < 2 {
		t.Fatalf("node counts = (%d, %d), want both >= 2", m1.NodeCount(), m2.NodeCount())
	}
}

func TestDiscoveryLoopRetriesConsulSeeds(t *testing.T) {
	m1 := startManager(t, testConfig("node-1", "Node 1", "127.0.0.1:0"))
	host, port, err := net.SplitHostPort(m1.Self().Address)
	if err != nil {
		t.Fatalf("SplitHostPort(m1 addr) error = %v", err)
	}

	var (
		mu         sync.RWMutex
		advertised bool
	)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.RLock()
		ready := advertised
		mu.RUnlock()
		if !ready {
			_ = json.NewEncoder(w).Encode([]map[string]any{})
			return
		}
		_ = json.NewEncoder(w).Encode([]map[string]any{
			{
				"Node": map[string]any{"Address": host},
				"Service": map[string]any{
					"Address": host,
					"Port":    mustAtoi(t, port),
				},
			},
		})
	}))
	defer server.Close()

	parsed, err := url.Parse(server.URL)
	if err != nil {
		t.Fatalf("Parse(server.URL) error = %v", err)
	}

	cfg2 := testConfig("node-2", "Node 2", "127.0.0.1:0")
	cfg2.SyncInterval = 100 * time.Millisecond
	cfg2.Seeds = []string{fmt.Sprintf("consul://%s/ssh-proxy", parsed.Host)}
	m2 := startManager(t, cfg2)

	time.Sleep(350 * time.Millisecond)
	mu.Lock()
	advertised = true
	mu.Unlock()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if m1.NodeCount() >= 2 && m2.NodeCount() >= 2 {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("node counts after discovery retry = (%d, %d), want both >= 2", m1.NodeCount(), m2.NodeCount())
}

func mustAtoi(t *testing.T, value string) int {
	t.Helper()
	parsed, err := net.LookupPort("tcp", value)
	if err != nil {
		t.Fatalf("LookupPort(%q) error = %v", value, err)
	}
	return parsed
}
