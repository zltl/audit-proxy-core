package authn

import (
	"strings"
	"testing"
	"time"
)

// RFC 6238 appendix B test vectors. The published secret is the ASCII string
// "12345678901234567890"; base32 of that is GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ.
const rfc6238Secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"

func TestTOTPCodeRFC6238Vectors(t *testing.T) {
	cfg := TOTPConfig{Algorithm: "SHA1", Digits: 8, Period: 30 * time.Second}
	cases := []struct {
		unix int64
		want string
	}{
		{59, "94287082"},
		{1111111109, "07081804"},
		{1111111111, "14050471"},
		{1234567890, "89005924"},
		{2000000000, "69279037"},
		{20000000000, "65353130"},
	}
	for _, tc := range cases {
		got, err := TOTPCode(rfc6238Secret, time.Unix(tc.unix, 0).UTC(), cfg)
		if err != nil {
			t.Fatalf("TOTPCode(%d): %v", tc.unix, err)
		}
		if got != tc.want {
			t.Errorf("TOTPCode(%d) = %s, want %s", tc.unix, got, tc.want)
		}
	}
}

func TestValidateTOTPAcceptsCurrentCode(t *testing.T) {
	secret, err := GenerateTOTPSecret()
	if err != nil {
		t.Fatalf("GenerateTOTPSecret: %v", err)
	}
	now := time.Unix(1700000000, 0).UTC()
	cfg := DefaultTOTPConfig()

	code, err := TOTPCode(secret, now, cfg)
	if err != nil {
		t.Fatalf("TOTPCode: %v", err)
	}
	if !ValidateTOTPAt(secret, code, now, cfg) {
		t.Fatal("current code rejected")
	}
	if !ValidateTOTPAt(secret, code, now.Add(25*time.Second), cfg) {
		t.Fatal("code rejected inside the skew window")
	}
	if ValidateTOTPAt(secret, code, now.Add(5*time.Minute), cfg) {
		t.Fatal("stale code accepted well outside the skew window")
	}
}

func TestValidateTOTPRejectsBadInput(t *testing.T) {
	secret, err := GenerateTOTPSecret()
	if err != nil {
		t.Fatalf("GenerateTOTPSecret: %v", err)
	}
	cfg := DefaultTOTPConfig()
	now := time.Unix(1700000000, 0).UTC()

	for _, code := range []string{"", "12345", "1234567", "abcdef"} {
		if ValidateTOTPAt(secret, code, now, cfg) {
			t.Errorf("accepted invalid code %q", code)
		}
	}
	if ValidateTOTPAt("", "123456", now, cfg) {
		t.Error("accepted a code against an empty secret")
	}
	if ValidateTOTPAt("!!!not base32!!!", "123456", now, cfg) {
		t.Error("accepted a code against an undecodable secret")
	}
}

func TestGenerateTOTPSecretIsUnique(t *testing.T) {
	seen := make(map[string]bool)
	for i := 0; i < 16; i++ {
		s, err := GenerateTOTPSecret()
		if err != nil {
			t.Fatalf("GenerateTOTPSecret: %v", err)
		}
		if len(s) != 32 {
			t.Fatalf("expected 32 base32 chars for a 160-bit secret, got %d", len(s))
		}
		if seen[s] {
			t.Fatal("GenerateTOTPSecret returned a duplicate")
		}
		seen[s] = true
	}
}

func TestTOTPProvisioningURI(t *testing.T) {
	uri := TOTPProvisioningURI("SSHProxy", "alice", rfc6238Secret, DefaultTOTPConfig())
	for _, want := range []string{
		"otpauth://totp/SSHProxy:alice?",
		"secret=" + rfc6238Secret,
		"issuer=SSHProxy",
		"digits=6",
		"period=30",
		"algorithm=SHA1",
	} {
		if !strings.Contains(uri, want) {
			t.Errorf("provisioning URI %q missing %q", uri, want)
		}
	}
}

func TestTOTPUnsupportedAlgorithm(t *testing.T) {
	if _, err := TOTPCode(rfc6238Secret, time.Now(), TOTPConfig{Algorithm: "MD5", Digits: 6, Period: 30 * time.Second}); err == nil {
		t.Fatal("expected an error for an unsupported algorithm")
	}
}
