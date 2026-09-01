package store

import (
	"errors"
	"strings"
	"testing"

	"github.com/ssh-proxy-core/ssh-proxy-core/internal/secrets"
)

func newSealedStore(t *testing.T) (*Store, *secrets.StaticProvider) {
	t.Helper()
	s := newTestStore(t)

	key, err := secrets.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	provider, err := secrets.NewStaticProvider(map[string][]byte{"k1": key}, "k1")
	if err != nil {
		t.Fatalf("NewStaticProvider: %v", err)
	}
	sealer, err := secrets.NewSealer(provider)
	if err != nil {
		t.Fatalf("NewSealer: %v", err)
	}
	s.SetSealer(sealer)
	return s, provider
}

func TestSecretRoundTripAndCiphertextAtRest(t *testing.T) {
	s, _ := newSealedStore(t)

	const plaintext = "s3cr3t-upstream-password"
	ref, err := s.PutSecretString("upstream_password", plaintext)
	if err != nil {
		t.Fatalf("PutSecretString: %v", err)
	}
	if ref == "" {
		t.Fatal("PutSecret returned an empty reference")
	}

	got, err := s.GetSecretString(ref)
	if err != nil {
		t.Fatalf("GetSecretString: %v", err)
	}
	if got != plaintext {
		t.Fatalf("GetSecretString = %q, want %q", got, plaintext)
	}

	// Nothing in the row may contain the plaintext.
	var kind, keyID, nonce, ciphertext, aad string
	query := `SELECT kind, key_id, nonce, ciphertext, aad FROM dp_secrets WHERE id = ?`
	if err := s.DB().QueryRow(query, ref).Scan(&kind, &keyID, &nonce, &ciphertext, &aad); err != nil {
		t.Fatalf("read raw row: %v", err)
	}
	for name, column := range map[string]string{
		"kind": kind, "key_id": keyID, "nonce": nonce, "ciphertext": ciphertext, "aad": aad,
	} {
		if strings.Contains(column, plaintext) {
			t.Errorf("column %s stores the plaintext", name)
		}
	}
	if kind != "upstream_password" {
		t.Errorf("kind = %q", kind)
	}
}

func TestSecretRefusesWithoutSealer(t *testing.T) {
	s := newTestStore(t)

	if s.HasSealer() {
		t.Fatal("a store opened without a key provider should report no sealer")
	}
	if _, err := s.PutSecretString("password", "plaintext"); !errors.Is(err, ErrNoSealer) {
		t.Fatalf("PutSecret without a sealer should refuse, got %v", err)
	}
	if _, err := s.GetSecret("sec-1"); !errors.Is(err, ErrNoSealer) {
		t.Fatalf("GetSecret without a sealer should refuse, got %v", err)
	}
	if _, err := s.RotateSecrets(); !errors.Is(err, ErrNoSealer) {
		t.Fatalf("RotateSecrets without a sealer should refuse, got %v", err)
	}
}

func TestSecretUpdateAndDelete(t *testing.T) {
	s, _ := newSealedStore(t)

	ref, err := s.PutSecretString("private_key", "original")
	if err != nil {
		t.Fatalf("PutSecretString: %v", err)
	}
	if err := s.UpdateSecret(ref, []byte("rotated")); err != nil {
		t.Fatalf("UpdateSecret: %v", err)
	}
	got, err := s.GetSecretString(ref)
	if err != nil {
		t.Fatalf("GetSecretString: %v", err)
	}
	if got != "rotated" {
		t.Fatalf("after update = %q, want rotated", got)
	}

	if err := s.DeleteSecret(ref); err != nil {
		t.Fatalf("DeleteSecret: %v", err)
	}
	if _, err := s.GetSecret(ref); !errors.Is(err, ErrNotFound) {
		t.Fatalf("a deleted secret should be ErrNotFound, got %v", err)
	}
	if err := s.DeleteSecret(ref); !errors.Is(err, ErrNotFound) {
		t.Fatalf("deleting twice should be ErrNotFound, got %v", err)
	}
}

func TestRotateSecretsMovesValuesToTheActiveKey(t *testing.T) {
	s, provider := newSealedStore(t)

	refs := make([]string, 0, 3)
	for _, value := range []string{"one", "two", "three"} {
		ref, err := s.PutSecretString("upstream_password", value)
		if err != nil {
			t.Fatalf("PutSecretString: %v", err)
		}
		refs = append(refs, ref)
	}

	if count, err := s.CountSecretsUnderKey("k1"); err != nil || count != 3 {
		t.Fatalf("CountSecretsUnderKey(k1) = (%d, %v), want 3", count, err)
	}

	newKey, err := secrets.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	if err := provider.AddKey("k2", newKey); err != nil {
		t.Fatalf("AddKey: %v", err)
	}
	if err := provider.SetActive("k2"); err != nil {
		t.Fatalf("SetActive: %v", err)
	}

	// Before rotating, existing values must still be readable under the old key.
	if got, err := s.GetSecretString(refs[0]); err != nil || got != "one" {
		t.Fatalf("value under the retired key = (%q, %v)", got, err)
	}

	rotated, err := s.RotateSecrets()
	if err != nil {
		t.Fatalf("RotateSecrets: %v", err)
	}
	if rotated != 3 {
		t.Fatalf("rotated %d secrets, want 3", rotated)
	}

	if count, err := s.CountSecretsUnderKey("k1"); err != nil || count != 0 {
		t.Fatalf("after rotation CountSecretsUnderKey(k1) = (%d, %v), want 0", count, err)
	}
	if count, err := s.CountSecretsUnderKey("k2"); err != nil || count != 3 {
		t.Fatalf("after rotation CountSecretsUnderKey(k2) = (%d, %v), want 3", count, err)
	}

	for i, want := range []string{"one", "two", "three"} {
		got, err := s.GetSecretString(refs[i])
		if err != nil {
			t.Fatalf("GetSecretString after rotation: %v", err)
		}
		if got != want {
			t.Fatalf("rotation changed a plaintext: got %q, want %q", got, want)
		}
	}

	// A second sweep has nothing left to do.
	if rotated, err := s.RotateSecrets(); err != nil || rotated != 0 {
		t.Fatalf("second RotateSecrets = (%d, %v), want (0, nil)", rotated, err)
	}
}

func TestSecretsAreBoundToTheirRow(t *testing.T) {
	s, _ := newSealedStore(t)

	first, err := s.PutSecretString("upstream_password", "password-a")
	if err != nil {
		t.Fatalf("PutSecretString: %v", err)
	}
	second, err := s.PutSecretString("upstream_password", "password-b")
	if err != nil {
		t.Fatalf("PutSecretString: %v", err)
	}

	// Copying one row's ciphertext over another's must not decrypt: the sealed
	// value is bound to the id it was created for.
	var nonce, ciphertext string
	if err := s.DB().QueryRow(`SELECT nonce, ciphertext FROM dp_secrets WHERE id = ?`, first).
		Scan(&nonce, &ciphertext); err != nil {
		t.Fatalf("read first row: %v", err)
	}
	if _, err := s.DB().Exec(`UPDATE dp_secrets SET nonce = ?, ciphertext = ? WHERE id = ?`,
		nonce, ciphertext, second); err != nil {
		t.Fatalf("transplant ciphertext: %v", err)
	}

	if _, err := s.GetSecret(second); err == nil {
		t.Fatal("a ciphertext moved to a different row should not decrypt")
	}
	if got, err := s.GetSecretString(first); err != nil || got != "password-a" {
		t.Fatalf("the untouched row should still open: (%q, %v)", got, err)
	}
}
