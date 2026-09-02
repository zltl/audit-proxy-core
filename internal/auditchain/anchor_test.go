package auditchain

import (
	"testing"
)

func TestBuildAndVerifyAnchor(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef")
	a, err := BuildAnchor("node-1", "abc123", 42, key)
	if err != nil {
		t.Fatal(err)
	}
	if !VerifyAnchor(a, key) {
		t.Fatal("anchor signature did not verify")
	}
	if VerifyAnchor(a, []byte("wrong-key-material-32-bytes-long!!")) {
		t.Fatal("wrong key should not verify")
	}
}
