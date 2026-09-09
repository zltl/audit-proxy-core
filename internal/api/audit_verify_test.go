package api

import (
	"encoding/hex"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/zltl/audit-proxy-core/internal/auditchain"
)

// chainWriter produces a valid chain of audit records the way the data plane
// would, so the verifier is tested against real input rather than a fixture.
type chainWriter struct {
	key      []byte
	node     string
	prevHash string
	records  []map[string]interface{}
}

func (w *chainWriter) add(id, eventType, username, command string, at time.Time) {
	timestamp := at.UTC().Format(time.RFC3339Nano)
	entry := auditchain.Entry{
		ID: id, EventType: eventType, Username: username,
		Command: command, Timestamp: timestamp, PrevHash: w.prevHash,
	}
	hash := auditchain.Compute(w.key, w.prevHash, entry)
	w.records = append(w.records, map[string]interface{}{
		"id":             id,
		"event_type":     eventType,
		"username":       username,
		"command":        command,
		"timestamp":      timestamp,
		"node_id":        w.node,
		"prev_hash":      w.prevHash,
		"integrity_hash": hash,
	})
	w.prevHash = hash
}

func (w *chainWriter) write(t *testing.T, dir, name string) {
	t.Helper()
	var lines []string
	for _, record := range w.records {
		encoded, err := json.Marshal(record)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		lines = append(lines, string(encoded))
	}
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func setupVerifyAPI(t *testing.T, chainKey string) (*API, *http.ServeMux) {
	t.Helper()
	api, mux, _ := setupTestAPI(t)
	api.config.AuditChainKey = chainKey
	// The shared harness seeds sample events without a chain; remove them so
	// the test controls exactly what is verified.
	entries, _ := filepath.Glob(filepath.Join(api.config.AuditLogDir, "*.jsonl"))
	for _, path := range entries {
		_ = os.Remove(path)
	}
	return api, mux
}

func verifyResponse(t *testing.T, mux *http.ServeMux, query string) (int, map[string]interface{}) {
	t.Helper()
	rr := doRequest(mux, http.MethodGet, "/api/v2/audit/verify"+query, nil)
	var envelope APIResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &envelope); err != nil {
		t.Fatalf("decode response: %v (%s)", err, rr.Body.String())
	}
	data, _ := envelope.Data.(map[string]interface{})
	return rr.Code, data
}

func TestVerifyIntactChain(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef")
	api, mux := setupVerifyAPI(t, hex.EncodeToString(key))

	writer := &chainWriter{key: key, node: "node-a"}
	base := time.Now().UTC().Add(-time.Hour)
	writer.add("e1", "session.start", "alice", "", base)
	writer.add("e2", "command", "alice", "uptime", base.Add(time.Second))
	writer.add("e3", "session.end", "alice", "", base.Add(2*time.Second))
	writer.write(t, api.config.AuditLogDir, "audit-20260101.jsonl")

	status, data := verifyResponse(t, mux, "")
	if status != http.StatusOK {
		t.Fatalf("status = %d, want 200 for an intact chain", status)
	}
	if data["intact"] != true {
		t.Fatalf("intact = %v: %+v", data["intact"], data)
	}
	if data["verified"].(float64) != 3 {
		t.Errorf("verified = %v, want 3", data["verified"])
	}
	if data["digest_checked"] != true {
		t.Error("with a key configured the digests should have been recomputed")
	}
}

func TestVerifyDetectsADeletedRecord(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef")
	api, mux := setupVerifyAPI(t, hex.EncodeToString(key))

	writer := &chainWriter{key: key, node: "node-a"}
	base := time.Now().UTC().Add(-time.Hour)
	writer.add("e1", "session.start", "alice", "", base)
	writer.add("e2", "command", "alice", "rm -rf /", base.Add(time.Second))
	writer.add("e3", "session.end", "alice", "", base.Add(2*time.Second))

	// Somebody removes the inconvenient record. This is the case the chain
	// exists for: the remaining records no longer link up.
	writer.records = append(writer.records[:1], writer.records[2:]...)
	writer.write(t, api.config.AuditLogDir, "audit-20260101.jsonl")

	status, data := verifyResponse(t, mux, "")
	if status != http.StatusConflict {
		t.Fatalf("status = %d, want 409 so that a broken chain can be alerted on", status)
	}
	if data["intact"] != false {
		t.Fatal("a deleted record was not detected")
	}
	problems := data["problems"].([]interface{})
	if len(problems) == 0 {
		t.Fatal("no problem was reported")
	}
	first := problems[0].(map[string]interface{})
	if first["kind"] != auditchain.ProblemBrokenLink {
		t.Errorf("kind = %v, want broken_link", first["kind"])
	}
	if first["id"] != "e3" {
		t.Errorf("the report should point at the record that no longer follows, got %v", first["id"])
	}
}

func TestVerifyDetectsAnAlteredRecord(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef")
	api, mux := setupVerifyAPI(t, hex.EncodeToString(key))

	writer := &chainWriter{key: key, node: "node-a"}
	base := time.Now().UTC().Add(-time.Hour)
	writer.add("e1", "session.start", "alice", "", base)
	writer.add("e2", "command", "alice", "rm -rf /", base.Add(time.Second))

	// Editing the command in place leaves the linkage intact but breaks the
	// record's own digest, which is why the digest is checked as well.
	writer.records[1]["command"] = "ls -la"
	writer.write(t, api.config.AuditLogDir, "audit-20260101.jsonl")

	status, data := verifyResponse(t, mux, "")
	if status != http.StatusConflict {
		t.Fatalf("status = %d, want 409", status)
	}
	problems := data["problems"].([]interface{})
	found := false
	for _, raw := range problems {
		if raw.(map[string]interface{})["kind"] == auditchain.ProblemBadDigest {
			found = true
		}
	}
	if !found {
		t.Fatalf("an edited record was not detected: %+v", problems)
	}
}

func TestVerifyWithoutAKeyChecksLinkageOnly(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef")
	api, mux := setupVerifyAPI(t, "")

	writer := &chainWriter{key: key, node: "node-a"}
	base := time.Now().UTC().Add(-time.Hour)
	writer.add("e1", "session.start", "alice", "", base)
	writer.add("e2", "command", "alice", "rm -rf /", base.Add(time.Second))
	// An edit that linkage alone cannot catch.
	writer.records[1]["command"] = "ls -la"
	writer.write(t, api.config.AuditLogDir, "audit-20260101.jsonl")

	status, data := verifyResponse(t, mux, "")
	if status != http.StatusOK {
		t.Fatalf("status = %d; linkage is intact so this run should pass", status)
	}
	if data["digest_checked"] != false {
		t.Error("without a key the digests cannot have been recomputed")
	}
	// The limitation has to be stated, or a passing result reads as more than
	// it is.
	note, _ := data["note"].(string)
	if !strings.Contains(note, "audit_chain_key") {
		t.Errorf("the response should explain what was not checked, got %q", note)
	}
	if data["unverifiable"].(float64) != 2 {
		t.Errorf("unverifiable = %v, want 2", data["unverifiable"])
	}
}

func TestVerifyTreatsNodesAsSeparateChains(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef")
	api, mux := setupVerifyAPI(t, hex.EncodeToString(key))

	// Two nodes run independently, so their records interleave in the log.
	// Verifying them as one sequence would report every record as following one
	// from a different machine.
	nodeA := &chainWriter{key: key, node: "node-a"}
	nodeB := &chainWriter{key: key, node: "node-b"}
	base := time.Now().UTC().Add(-time.Hour)
	nodeA.add("a1", "session.start", "alice", "", base)
	nodeB.add("b1", "session.start", "bob", "", base.Add(time.Millisecond))
	nodeA.add("a2", "session.end", "alice", "", base.Add(2*time.Millisecond))
	nodeB.add("b2", "session.end", "bob", "", base.Add(3*time.Millisecond))

	interleaved := &chainWriter{}
	interleaved.records = []map[string]interface{}{
		nodeA.records[0], nodeB.records[0], nodeA.records[1], nodeB.records[1],
	}
	interleaved.write(t, api.config.AuditLogDir, "audit-20260101.jsonl")

	status, data := verifyResponse(t, mux, "")
	if status != http.StatusOK {
		t.Fatalf("status = %d: interleaved records from two nodes are not tampering (%+v)", status, data)
	}
	if data["checked"].(float64) != 4 {
		t.Errorf("checked = %v, want 4", data["checked"])
	}
}

func TestVerifyIgnoresRecordsWithoutAChain(t *testing.T) {
	api, mux := setupVerifyAPI(t, "")

	// Records from other producers carry no chain. Treating their absence as
	// tampering would make the check useless in a mixed deployment.
	path := filepath.Join(api.config.AuditLogDir, "audit-other.jsonl")
	if err := os.WriteFile(path, []byte(
		`{"id":"x1","event_type":"login","username":"admin","timestamp":"2026-01-01T00:00:00Z"}`+"\n"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	status, data := verifyResponse(t, mux, "")
	if status != http.StatusOK {
		t.Fatalf("status = %d", status)
	}
	if data["checked"].(float64) != 0 {
		t.Errorf("checked = %v, want 0", data["checked"])
	}
}

func TestVerifyRejectsABadTimeRange(t *testing.T) {
	_, mux := setupVerifyAPI(t, "")
	status, _ := verifyResponse(t, mux, "?from=yesterday")
	if status != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", status)
	}
}

func TestAuditChainKeyAcceptsHexAndPassphrase(t *testing.T) {
	api := &API{config: &Config{AuditChainKey: hex.EncodeToString([]byte("0123456789abcdef"))}}
	key, ok := api.auditChainKey()
	if !ok || string(key) != "0123456789abcdef" {
		t.Fatalf("hex key = %q (%v)", key, ok)
	}

	// A passphrase is used as-is rather than falling back to no key, which
	// would silently downgrade the check an operator asked for.
	api = &API{config: &Config{AuditChainKey: "a rather long passphrase"}}
	key, ok = api.auditChainKey()
	if !ok || string(key) != "a rather long passphrase" {
		t.Fatalf("passphrase key = %q (%v)", key, ok)
	}

	api = &API{config: &Config{}}
	if _, ok := api.auditChainKey(); ok {
		t.Fatal("an empty setting should report no key")
	}
}
