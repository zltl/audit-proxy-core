package authn

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/hex"
	"strings"
	"testing"

	"golang.org/x/crypto/bcrypt"
)

func testParams() Argon2Params {
	p := DefaultArgon2Params()
	// Keep unit tests fast; production callers use the defaults.
	p.Memory = 8 * 1024
	p.Iterations = 1
	return p
}

func TestHashPasswordRoundTrip(t *testing.T) {
	hash, err := HashPasswordWithParams("correct horse battery staple", testParams())
	if err != nil {
		t.Fatalf("HashPasswordWithParams: %v", err)
	}
	if !strings.HasPrefix(hash, "$argon2id$v=19$") {
		t.Fatalf("unexpected PHC prefix: %s", hash)
	}
	if !VerifyPassword("correct horse battery staple", hash) {
		t.Fatal("VerifyPassword rejected the correct password")
	}
	if VerifyPassword("wrong password", hash) {
		t.Fatal("VerifyPassword accepted a wrong password")
	}
}

func TestHashPasswordUsesFreshSalt(t *testing.T) {
	a, err := HashPasswordWithParams("same", testParams())
	if err != nil {
		t.Fatalf("hash a: %v", err)
	}
	b, err := HashPasswordWithParams("same", testParams())
	if err != nil {
		t.Fatalf("hash b: %v", err)
	}
	if a == b {
		t.Fatal("two hashes of the same password are identical; salt is not random")
	}
}

func TestVerifyPasswordBcrypt(t *testing.T) {
	raw, err := bcrypt.GenerateFromPassword([]byte("s3cret"), bcrypt.MinCost)
	if err != nil {
		t.Fatalf("bcrypt: %v", err)
	}
	if !VerifyPassword("s3cret", string(raw)) {
		t.Fatal("bcrypt hash not accepted")
	}
	if VerifyPassword("nope", string(raw)) {
		t.Fatal("bcrypt hash accepted a wrong password")
	}
}

func TestVerifyPasswordLegacyHMACSHA1(t *testing.T) {
	mac := hmac.New(sha1.New, []byte(legacyHMACSalt))
	mac.Write([]byte("legacy-pass"))
	legacy := hex.EncodeToString(mac.Sum(nil))

	if !VerifyPassword("legacy-pass", legacy) {
		t.Fatal("legacy HMAC-SHA1 hash not accepted; existing deployments would be locked out")
	}
	if VerifyPassword("other", legacy) {
		t.Fatal("legacy hash accepted a wrong password")
	}
	if !NeedsRehash(legacy) {
		t.Fatal("legacy hash should be flagged for rehash")
	}
}

func TestNeedsRehash(t *testing.T) {
	strong, err := HashPassword("pw")
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	if NeedsRehash(strong) {
		t.Fatal("hash created with defaults should not need a rehash")
	}

	weak, err := HashPasswordWithParams("pw", Argon2Params{
		Memory: 1024, Iterations: 1, Parallelism: 1, SaltLength: 16, KeyLength: 32,
	})
	if err != nil {
		t.Fatalf("weak hash: %v", err)
	}
	if !NeedsRehash(weak) {
		t.Fatal("under-parameterised hash should need a rehash")
	}
	if !NeedsRehash("") {
		t.Fatal("empty hash should need a rehash")
	}
}

func TestVerifyPasswordRejectsMalformed(t *testing.T) {
	for _, encoded := range []string{
		"",
		"   ",
		"$argon2id$",
		"$argon2id$v=19$m=8,t=1,p=1$notbase64!$alsonot!",
		"$argon2id$v=13$m=8192,t=1,p=1$c2FsdHNhbHRzYWx0c2E$aGFzaA",
		"not-a-hash",
		"zz" + strings.Repeat("0", 38),
	} {
		if VerifyPassword("anything", encoded) {
			t.Errorf("VerifyPassword accepted malformed hash %q", encoded)
		}
	}
}

func TestParseArgon2Params(t *testing.T) {
	p, err := ParseArgon2Params("m=32768,t=4,p=2")
	if err != nil {
		t.Fatalf("ParseArgon2Params: %v", err)
	}
	if p.Memory != 32768 || p.Iterations != 4 || p.Parallelism != 2 {
		t.Fatalf("unexpected params: %+v", p)
	}

	if _, err := ParseArgon2Params("m=32768,x=1"); err == nil {
		t.Fatal("expected error for unknown parameter")
	}
	if _, err := ParseArgon2Params("m"); err == nil {
		t.Fatal("expected error for malformed parameter")
	}
	if _, err := ParseArgon2Params("p=0"); err == nil {
		t.Fatal("expected error for zero parallelism")
	}

	def, err := ParseArgon2Params("")
	if err != nil {
		t.Fatalf("empty ParseArgon2Params: %v", err)
	}
	if def != DefaultArgon2Params() {
		t.Fatal("empty string should yield defaults")
	}
}
