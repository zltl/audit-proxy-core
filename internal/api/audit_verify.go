package api

import (
	"bufio"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/ssh-proxy-core/ssh-proxy-core/internal/auditchain"
)

// handleVerifyAuditChain checks the tamper-evidence chain over stored records.
//
// Writing a chain and never checking it is theatre: the value is entirely in
// somebody running this and getting an answer. It is exposed as an endpoint
// rather than a background job so a verification can be produced on demand,
// during an investigation, over a stated time range.
func (a *API) handleVerifyAuditChain(w http.ResponseWriter, r *http.Request) {
	from, to, err := parseVerifyRange(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	entries, nodes, err := a.loadChainEntries(from, to)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "read audit records: "+err.Error())
		return
	}

	key, keyConfigured := a.auditChainKey()
	result := auditchain.Verify(key, entries, func(i int) string { return nodes[i] })

	// A run without a key still detects deletions and reordering, but not an
	// edit by somebody who can recompute digests. Saying which check ran is the
	// difference between a meaningful result and a reassuring one.
	response := map[string]interface{}{
		"checked":        result.Checked,
		"verified":       result.Verified,
		"unverifiable":   result.Unverifiable,
		"intact":         result.Intact,
		"problems":       result.Problems,
		"digest_checked": keyConfigured,
	}
	if !keyConfigured {
		response["note"] = "no audit_chain_key is configured, so only the linkage between " +
			"records was checked; an alteration by someone able to recompute digests " +
			"would not be detected"
	}
	if from != nil {
		response["from"] = from.UTC().Format(time.RFC3339)
	}
	if to != nil {
		response["to"] = to.UTC().Format(time.RFC3339)
	}

	status := http.StatusOK
	if !result.Intact {
		// A broken chain is not a client error, but it must not read as a
		// success either: something consuming this should be able to alert on
		// the status alone.
		status = http.StatusConflict
	}
	writeJSON(w, status, APIResponse{Success: result.Intact, Data: response})
}

func parseVerifyRange(r *http.Request) (from, to *time.Time, err error) {
	parse := func(key string) (*time.Time, error) {
		raw := strings.TrimSpace(r.URL.Query().Get(key))
		if raw == "" {
			return nil, nil
		}
		parsed, parseErr := time.Parse(time.RFC3339, raw)
		if parseErr != nil {
			return nil, &verifyRangeError{key: key}
		}
		return &parsed, nil
	}
	if from, err = parse("from"); err != nil {
		return nil, nil, err
	}
	if to, err = parse("to"); err != nil {
		return nil, nil, err
	}
	return from, to, nil
}

type verifyRangeError struct{ key string }

func (e *verifyRangeError) Error() string {
	return e.key + " must be an RFC3339 timestamp"
}

// auditChainKey returns the key digests are computed under, and whether one is
// configured at all.
func (a *API) auditChainKey() ([]byte, bool) {
	if a == nil || a.config == nil {
		return nil, false
	}
	raw := strings.TrimSpace(a.config.AuditChainKey)
	if raw == "" {
		return nil, false
	}
	if decoded, err := hex.DecodeString(raw); err == nil && len(decoded) >= 16 {
		return decoded, true
	}
	// A non-hex value is used as-is, so an operator who sets a passphrase gets
	// what they intended rather than a silent fallback to no key at all.
	return []byte(raw), true
}

// loadChainEntries reads the stored records in the order they were written.
//
// Order matters: the chain is a sequence, so verification has to see records as
// they were appended. Files are read in name order and lines in file order,
// which is how they were produced.
func (a *API) loadChainEntries(from, to *time.Time) ([]auditchain.Entry, []string, error) {
	dir := a.config.AuditLogDir
	if strings.TrimSpace(dir) == "" {
		return nil, nil, nil
	}
	files, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil, nil
		}
		return nil, nil, err
	}

	names := make([]string, 0, len(files))
	for _, file := range files {
		name := file.Name()
		if file.IsDir() || (!strings.HasSuffix(name, ".jsonl") && !strings.HasSuffix(name, ".log")) {
			continue
		}
		names = append(names, name)
	}
	sort.Strings(names)

	var (
		entries []auditchain.Entry
		nodes   []string
	)
	for _, name := range names {
		file, err := os.Open(filepath.Join(dir, name))
		if err != nil {
			continue
		}
		scanner := bufio.NewScanner(file)
		scanner.Buffer(make([]byte, 0, 64*1024), 8<<20)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" {
				continue
			}
			var record map[string]interface{}
			if json.Unmarshal([]byte(line), &record) != nil {
				continue
			}
			// Only records that carry a chain participate. Events written by
			// other producers are not evidence of tampering by their absence.
			hash, _ := record["integrity_hash"].(string)
			if hash == "" {
				continue
			}
			timestamp, _ := record["timestamp"].(string)
			if !withinRange(timestamp, from, to) {
				continue
			}
			prevHash, _ := record["prev_hash"].(string)
			node, _ := record["node_id"].(string)

			entries = append(entries, auditchain.Entry{
				ID:        stringField(record, "id"),
				EventType: stringField(record, "event_type"),
				SessionID: stringField(record, "session_id"),
				Username:  stringField(record, "username"),
				Command:   stringField(record, "command"),
				Timestamp: timestamp,
				PrevHash:  prevHash,
				Hash:      hash,
			})
			nodes = append(nodes, node)
		}
		_ = file.Close()
	}
	return entries, nodes, nil
}

func stringField(record map[string]interface{}, key string) string {
	value, _ := record[key].(string)
	return value
}

// withinRange reports whether a record falls inside the requested window. A
// record with an unparseable timestamp is included rather than skipped: leaving
// it out would silently break the chain it belongs to.
func withinRange(timestamp string, from, to *time.Time) bool {
	if from == nil && to == nil {
		return true
	}
	parsed, err := time.Parse(time.RFC3339Nano, timestamp)
	if err != nil {
		parsed, err = time.Parse(time.RFC3339, timestamp)
		if err != nil {
			return true
		}
	}
	if from != nil && parsed.Before(*from) {
		return false
	}
	if to != nil && parsed.After(*to) {
		return false
	}
	return true
}
