package secrets

import (
	"bytes"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func testSealer(t *testing.T) (*Sealer, *StaticProvider) {
	t.Helper()
	key, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	provider, err := NewStaticProvider(map[string][]byte{"k1": key}, "k1")
	if err != nil {
		t.Fatalf("NewStaticProvider: %v", err)
	}
	sealer, err := NewSealer(provider)
	if err != nil {
		t.Fatalf("NewSealer: %v", err)
	}
	return sealer, provider
}

func TestSealOpenRoundTrip(t *testing.T) {
	sealer, _ := testSealer(t)

	plaintext := []byte("hunter2-the-upstream-password")
	sealed, err := sealer.Seal("dp_secret:password:1", plaintext)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if bytes.Contains(sealed.Ciphertext, plaintext) {
		t.Fatal("the ciphertext contains the plaintext")
	}
	if len(sealed.Nonce) == 0 {
		t.Fatal("no nonce was recorded")
	}
	if sealed.KeyID != "k1" {
		t.Fatalf("KeyID = %q, want k1", sealed.KeyID)
	}

	opened, err := sealer.Open(sealed)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if !bytes.Equal(opened, plaintext) {
		t.Fatalf("Open returned %q, want %q", opened, plaintext)
	}
}

func TestSealUsesFreshNonce(t *testing.T) {
	sealer, _ := testSealer(t)

	first, err := sealer.SealString("ctx", "same")
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	second, err := sealer.SealString("ctx", "same")
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if bytes.Equal(first.Nonce, second.Nonce) {
		t.Fatal("two seals reused a nonce, which breaks GCM")
	}
	if bytes.Equal(first.Ciphertext, second.Ciphertext) {
		t.Fatal("sealing the same plaintext twice produced identical ciphertext")
	}
}

func TestOpenRejectsTampering(t *testing.T) {
	sealer, _ := testSealer(t)
	sealed, err := sealer.SealString("ctx", "secret")
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	t.Run("modified ciphertext", func(t *testing.T) {
		tampered := sealed
		tampered.Ciphertext = append([]byte(nil), sealed.Ciphertext...)
		tampered.Ciphertext[0] ^= 0xff
		if _, err := sealer.Open(tampered); !errors.Is(err, ErrDecrypt) {
			t.Fatalf("expected ErrDecrypt, got %v", err)
		}
	})

	t.Run("modified nonce", func(t *testing.T) {
		tampered := sealed
		tampered.Nonce = append([]byte(nil), sealed.Nonce...)
		tampered.Nonce[0] ^= 0xff
		if _, err := sealer.Open(tampered); !errors.Is(err, ErrDecrypt) {
			t.Fatalf("expected ErrDecrypt, got %v", err)
		}
	})

	t.Run("truncated nonce", func(t *testing.T) {
		tampered := sealed
		tampered.Nonce = sealed.Nonce[:len(sealed.Nonce)-1]
		if _, err := sealer.Open(tampered); !errors.Is(err, ErrDecrypt) {
			t.Fatalf("expected ErrDecrypt, got %v", err)
		}
	})

	t.Run("swapped context", func(t *testing.T) {
		// Moving a ciphertext to a row with a different purpose must not open,
		// or a stored SSH password could be replayed as, say, a TOTP seed.
		moved := sealed
		moved.Context = "dp_secret:totp:other"
		if _, err := sealer.Open(moved); !errors.Is(err, ErrDecrypt) {
			t.Fatalf("expected a context mismatch to fail, got %v", err)
		}
	})
}

func TestOpenUnderRetiredKeyAndRotation(t *testing.T) {
	sealer, provider := testSealer(t)

	sealed, err := sealer.SealString("ctx", "old-secret")
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	// Rotate: add a new key and make it active, keeping the old one available.
	newKey, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	if err := provider.AddKey("k2", newKey); err != nil {
		t.Fatalf("AddKey: %v", err)
	}
	if err := provider.SetActive("k2"); err != nil {
		t.Fatalf("SetActive: %v", err)
	}

	if !sealer.NeedsRotation(sealed) {
		t.Fatal("a value under the previous key should be flagged for rotation")
	}
	opened, err := sealer.OpenString(sealed)
	if err != nil {
		t.Fatalf("a value under a retired key must still open: %v", err)
	}
	if opened != "old-secret" {
		t.Fatalf("Open returned %q", opened)
	}

	resealed, err := sealer.Reseal(sealed)
	if err != nil {
		t.Fatalf("Reseal: %v", err)
	}
	if resealed.KeyID != "k2" {
		t.Fatalf("resealed under %q, want k2", resealed.KeyID)
	}
	if sealer.NeedsRotation(resealed) {
		t.Fatal("a freshly resealed value should not need rotation")
	}
	roundTrip, err := sealer.OpenString(resealed)
	if err != nil || roundTrip != "old-secret" {
		t.Fatalf("resealing changed the plaintext: (%q, %v)", roundTrip, err)
	}
}

func TestOpenWithMissingKeyFails(t *testing.T) {
	sealer, _ := testSealer(t)
	sealed, err := sealer.SealString("ctx", "secret")
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	sealed.KeyID = "does-not-exist"
	if _, err := sealer.Open(sealed); !errors.Is(err, ErrUnknownKeyID) {
		t.Fatalf("expected ErrUnknownKeyID, got %v", err)
	}
}

func TestProviderValidatesKeyMaterial(t *testing.T) {
	if _, err := NewStaticProvider(nil, "k1"); !errors.Is(err, ErrNoKey) {
		t.Fatalf("an empty key set should be ErrNoKey, got %v", err)
	}
	short := map[string][]byte{"k1": []byte("too-short")}
	if _, err := NewStaticProvider(short, "k1"); err == nil {
		t.Fatal("a key of the wrong length should be rejected")
	}
	valid, _ := GenerateKey()
	if _, err := NewStaticProvider(map[string][]byte{"k1": valid}, "k9"); err == nil {
		t.Fatal("an active id outside the key set should be rejected")
	}
	if _, err := NewSealer(nil); !errors.Is(err, ErrNoKey) {
		t.Fatalf("a nil provider should be ErrNoKey, got %v", err)
	}
}

func TestProviderCopiesKeyMaterial(t *testing.T) {
	key, _ := GenerateKey()
	original := append([]byte(nil), key...)
	provider, err := NewStaticProvider(map[string][]byte{"k1": key}, "k1")
	if err != nil {
		t.Fatalf("NewStaticProvider: %v", err)
	}

	// Mutating the caller's slice must not change the provider's key, or a
	// caller reusing a buffer would silently invalidate every stored secret.
	for i := range key {
		key[i] ^= 0xff
	}
	stored, err := provider.Key("k1")
	if err != nil {
		t.Fatalf("Key: %v", err)
	}
	if !bytes.Equal(stored, original) {
		t.Fatal("the provider aliased the caller's key material")
	}
}

func TestLoadStaticProvider(t *testing.T) {
	key, _ := GenerateKey()
	hexKey := hex.EncodeToString(key)

	t.Run("literal", func(t *testing.T) {
		provider, err := LoadStaticProvider(hexKey)
		if err != nil {
			t.Fatalf("LoadStaticProvider: %v", err)
		}
		if provider.ActiveKeyID() != KeyIDFor(key) {
			t.Fatal("the key id should be derived from the material")
		}
	})

	t.Run("file reference", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "kek.hex")
		if err := os.WriteFile(path, []byte(hexKey+"\n"), 0o600); err != nil {
			t.Fatalf("write key file: %v", err)
		}
		provider, err := LoadStaticProvider("file:" + path)
		if err != nil {
			t.Fatalf("LoadStaticProvider(file:): %v", err)
		}
		if provider.ActiveKeyID() != KeyIDFor(key) {
			t.Fatal("the file-loaded key produced a different id")
		}
	})

	t.Run("rejects bad input", func(t *testing.T) {
		if _, err := LoadStaticProvider(""); !errors.Is(err, ErrNoKey) {
			t.Fatalf("empty spec should be ErrNoKey, got %v", err)
		}
		if _, err := LoadStaticProvider("not-hex"); err == nil {
			t.Fatal("non-hex material should be rejected")
		}
		if _, err := LoadStaticProvider(hex.EncodeToString([]byte("short"))); err == nil {
			t.Fatal("a short key should be rejected")
		}
		if _, err := LoadStaticProvider("file:/nonexistent/path"); err == nil {
			t.Fatal("a missing key file should be reported")
		}
	})
}

func TestKeyIDIsStableAndDistinct(t *testing.T) {
	a, _ := GenerateKey()
	b, _ := GenerateKey()

	if KeyIDFor(a) != KeyIDFor(a) {
		t.Fatal("the same key produced two different ids")
	}
	if KeyIDFor(a) == KeyIDFor(b) {
		t.Fatal("different keys produced the same id")
	}
	if !strings.HasPrefix(KeyIDFor(a), "k") {
		t.Fatalf("key id %q should be recognisable as one", KeyIDFor(a))
	}
}
