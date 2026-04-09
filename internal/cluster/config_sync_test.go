package cluster

import (
	"strings"
	"sync"
	"testing"
	"time"
)

func waitForClusterCondition(t *testing.T, timeout time.Duration, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatal("timed out waiting for cluster condition")
}

func TestConfigSyncPublishPropagatesToFollowerAndTracksStatus(t *testing.T) {
	m1 := startManager(t, testConfig("node-1", "Node 1", "127.0.0.1:0"))
	addr1 := m1.Self().Address

	cfg2 := testConfig("node-2", "Node 2", "127.0.0.1:0")
	cfg2.Seeds = []string{addr1}
	m2 := startManager(t, cfg2)

	time.Sleep(500 * time.Millisecond)

	applied := make(chan string, 1)
	m2.SetConfigSyncApplier(func(snapshot []byte) error {
		applied <- string(snapshot)
		return nil
	})

	if err := m1.PublishConfigSnapshot([]byte(`{"listen_port":3333}`), "sync-v1", "chg-1", "admin"); err != nil {
		t.Fatalf("PublishConfigSnapshot: %v", err)
	}

	select {
	case raw := <-applied:
		if !strings.Contains(raw, `"listen_port":3333`) {
			t.Fatalf("unexpected synced snapshot: %s", raw)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for follower apply")
	}

	waitForClusterCondition(t, 2*time.Second, func() bool {
		status := m1.GetConfigSyncStatus()
		for _, node := range status.Nodes {
			if node.NodeID == "node-2" && node.Status == configSyncStatusApplied && node.Version == "sync-v1" {
				return true
			}
		}
		return false
	})
}

func TestConfigSyncFollowerRetriesAfterFailure(t *testing.T) {
	m1 := startManager(t, testConfig("node-1", "Node 1", "127.0.0.1:0"))
	addr1 := m1.Self().Address

	cfg2 := testConfig("node-2", "Node 2", "127.0.0.1:0")
	cfg2.Seeds = []string{addr1}
	m2 := startManager(t, cfg2)

	time.Sleep(500 * time.Millisecond)

	var mu sync.Mutex
	attempts := 0
	m2.SetConfigSyncApplier(func(snapshot []byte) error {
		mu.Lock()
		defer mu.Unlock()
		attempts++
		if attempts == 1 {
			return errConfigSyncTestFailure
		}
		return nil
	})

	if err := m1.PublishConfigSnapshot([]byte(`{"listen_port":4444}`), "sync-v2", "chg-2", "admin"); err != nil {
		t.Fatalf("PublishConfigSnapshot: %v", err)
	}

	waitForClusterCondition(t, 2*time.Second, func() bool {
		mu.Lock()
		defer mu.Unlock()
		return attempts >= 1
	})

	waitForClusterCondition(t, 2*time.Second, func() bool {
		status := m1.GetConfigSyncStatus()
		for _, node := range status.Nodes {
			if node.NodeID == "node-2" && node.Status == configSyncStatusFailed {
				return true
			}
		}
		return false
	})

	waitForClusterCondition(t, 3*time.Second, func() bool {
		mu.Lock()
		defer mu.Unlock()
		if attempts < 2 {
			return false
		}
		status := m1.GetConfigSyncStatus()
		for _, node := range status.Nodes {
			if node.NodeID == "node-2" && node.Status == configSyncStatusApplied && node.Version == "sync-v2" {
				return true
			}
		}
		return false
	})
}

var errConfigSyncTestFailure = &configSyncTestError{message: "reload failed once"}

type configSyncTestError struct {
	message string
}

func (e *configSyncTestError) Error() string {
	return e.message
}
