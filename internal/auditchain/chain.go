// Package auditchain computes and verifies the tamper-evidence chain over audit
// records.
//
// Each record carries a digest of itself and of the record before it. Removing
// a record, reordering two, or altering a field all break the linkage, so the
// question "has this log been edited" has an answer rather than an assumption.
//
// The computation lives here rather than in the producer so that the verifier
// cannot drift from it: a chain that is written one way and checked another
// would report tampering that never happened, and people would learn to ignore
// it.
package auditchain

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
)

// Entry is the subset of a record the chain covers.
//
// It deliberately does not cover every field. What it covers must be stable
// through storage and re-encoding, or verification fails for uninteresting
// reasons; what it must include is anything whose alteration would change the
// meaning of the record.
type Entry struct {
	ID        string
	EventType string
	SessionID string
	Username  string
	Command   string
	Timestamp string
	PrevHash  string
	Hash      string
}

// Compute returns the digest for an entry following prevHash.
func Compute(key []byte, prevHash string, entry Entry) string {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(prevHash))
	mac.Write([]byte(entry.ID))
	mac.Write([]byte(entry.EventType))
	mac.Write([]byte(entry.SessionID))
	mac.Write([]byte(entry.Username))
	mac.Write([]byte(entry.Command))
	mac.Write([]byte(entry.Timestamp))
	return hex.EncodeToString(mac.Sum(nil))
}

// Problem describes one break in a chain.
type Problem struct {
	// Index is the position within the node's sequence, so a report points at
	// a record rather than merely saying something is wrong.
	Index  int    `json:"index"`
	ID     string `json:"id"`
	Node   string `json:"node"`
	Kind   string `json:"kind"`
	Detail string `json:"detail"`
}

// Problem kinds.
const (
	// ProblemBrokenLink means a record does not follow the one before it, which
	// is what a deletion or a reordering looks like.
	ProblemBrokenLink = "broken_link"
	// ProblemBadDigest means a record's own digest does not match its contents,
	// which is what an edit looks like.
	ProblemBadDigest = "bad_digest"
	// ProblemMissingHash means a record carries no digest at all.
	ProblemMissingHash = "missing_hash"
)

// Result summarises a verification run.
type Result struct {
	Checked  int `json:"checked"`
	Verified int `json:"verified"`
	// Unverifiable counts records whose digest could not be recomputed because
	// no key was supplied. Their linkage is still checked.
	Unverifiable int       `json:"unverifiable"`
	Problems     []Problem `json:"problems"`
	Intact       bool      `json:"intact"`
}

// Verify checks the chains in a set of records.
//
// Records are grouped by node, because each node maintains its own chain: they
// run independently and interleaving their events into one sequence would make
// every record appear to follow one from a different machine.
//
// A nil or empty key checks linkage only. That is still worth doing — a deleted
// record breaks the links — but it does not detect an edit by someone who can
// recompute the digests, which is why the key matters.
func Verify(key []byte, records []Entry, nodeOf func(int) string) Result {
	byNode := make(map[string][]int)
	order := make([]string, 0)
	for i := range records {
		node := ""
		if nodeOf != nil {
			node = nodeOf(i)
		}
		if _, seen := byNode[node]; !seen {
			order = append(order, node)
		}
		byNode[node] = append(byNode[node], i)
	}
	sort.Strings(order)

	result := Result{Intact: true}
	for _, node := range order {
		indices := byNode[node]
		prevHash := ""
		for position, index := range indices {
			entry := records[index]
			result.Checked++

			if strings.TrimSpace(entry.Hash) == "" {
				result.Problems = append(result.Problems, Problem{
					Index: position, ID: entry.ID, Node: node,
					Kind:   ProblemMissingHash,
					Detail: "the record carries no integrity hash",
				})
				result.Intact = false
				prevHash = ""
				continue
			}

			// Linkage is checked first because it is what a deletion breaks,
			// and it can be checked without the key.
			if position > 0 && entry.PrevHash != prevHash {
				result.Problems = append(result.Problems, Problem{
					Index: position, ID: entry.ID, Node: node,
					Kind: ProblemBrokenLink,
					Detail: fmt.Sprintf("expected to follow %s but records %s; a record was removed, reordered, or inserted",
						abbreviate(prevHash), abbreviate(entry.PrevHash)),
				})
				result.Intact = false
			}

			if len(key) == 0 {
				result.Unverifiable++
			} else if expected := Compute(key, entry.PrevHash, entry); expected != entry.Hash {
				result.Problems = append(result.Problems, Problem{
					Index: position, ID: entry.ID, Node: node,
					Kind:   ProblemBadDigest,
					Detail: "the record's contents do not match its digest; it has been altered",
				})
				result.Intact = false
			} else {
				result.Verified++
			}

			prevHash = entry.Hash
		}
	}
	return result
}

func abbreviate(hash string) string {
	if hash == "" {
		return "(nothing)"
	}
	if len(hash) <= 12 {
		return hash
	}
	return hash[:12] + "…"
}
