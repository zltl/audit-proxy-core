package auditchain

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"
)

// Anchor is an immutable snapshot of a node's chain head for WORM storage.
type Anchor struct {
	NodeID    string    `json:"node_id"`
	LastHash  string    `json:"last_hash"`
	Count     int64     `json:"count"`
	Anchored  time.Time `json:"anchored_at"`
	Signature string    `json:"signature"`
}

// BuildAnchor seals the chain head with HMAC so tampering is detectable.
func BuildAnchor(nodeID, lastHash string, count int64, key []byte) (Anchor, error) {
	if len(key) == 0 {
		return Anchor{}, fmt.Errorf("auditchain: anchor key is required")
	}
	a := Anchor{
		NodeID:   nodeID,
		LastHash: lastHash,
		Count:    count,
		Anchored: time.Now().UTC(),
	}
	payload, err := json.Marshal(struct {
		NodeID   string `json:"node_id"`
		LastHash string `json:"last_hash"`
		Count    int64  `json:"count"`
		Anchored int64  `json:"anchored_at"`
	}{a.NodeID, a.LastHash, a.Count, a.Anchored.Unix()})
	if err != nil {
		return Anchor{}, err
	}
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write(payload)
	a.Signature = hex.EncodeToString(mac.Sum(nil))
	return a, nil
}

// VerifyAnchor checks the anchor signature.
func VerifyAnchor(a Anchor, key []byte) bool {
	payload, _ := json.Marshal(struct {
		NodeID   string `json:"node_id"`
		LastHash string `json:"last_hash"`
		Count    int64  `json:"count"`
		Anchored int64  `json:"anchored_at"`
	}{a.NodeID, a.LastHash, a.Count, a.Anchored.Unix()})
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write(payload)
	return hex.EncodeToString(mac.Sum(nil)) == a.Signature
}
