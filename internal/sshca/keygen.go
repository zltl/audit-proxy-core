package sshca

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"os"

	"golang.org/x/crypto/ssh"
)

// keyPairSigner wraps an ssh.Signer and retains the raw crypto private key
// so SavePrivateKey can marshal it back to PEM.
type keyPairSigner struct {
	ssh.Signer
	rawKey interface{}
}

// PrivateKey returns the underlying crypto private key.
func (k *keyPairSigner) PrivateKey() interface{} {
	return k.rawKey
}

// GenerateED25519Key generates a new ED25519 SSH key pair.
func GenerateED25519Key() (ssh.Signer, error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate ed25519 key: %w", err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		return nil, fmt.Errorf("create signer: %w", err)
	}
	return &keyPairSigner{Signer: signer, rawKey: priv}, nil
}

// GenerateRSAKey generates a new RSA SSH key pair with the given bit size.
func GenerateRSAKey(bits int) (ssh.Signer, error) {
	if bits < 2048 {
		return nil, fmt.Errorf("RSA key size must be at least 2048 bits")
	}
	priv, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, fmt.Errorf("generate rsa key: %w", err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		return nil, fmt.Errorf("create signer: %w", err)
	}
	return &keyPairSigner{Signer: signer, rawKey: priv}, nil
}

// GenerateECDSAKey generates a new ECDSA SSH key pair using P-256.
func GenerateECDSAKey() (ssh.Signer, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate ecdsa key: %w", err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		return nil, fmt.Errorf("create signer: %w", err)
	}
	return &keyPairSigner{Signer: signer, rawKey: priv}, nil
}

// SavePrivateKey writes a private key to a PEM-encoded file with 0600 permissions.
// The signer must have been created by one of the Generate*Key or LoadPrivateKey
// functions in this package (they retain the raw crypto key).
func SavePrivateKey(path string, signer ssh.Signer) error {
	var rawKey interface{}
	if kp, ok := signer.(interface{ PrivateKey() interface{} }); ok {
		rawKey = kp.PrivateKey()
	}
	if rawKey == nil {
		return fmt.Errorf("unable to extract private key from signer")
	}
	der, err := x509.MarshalPKCS8PrivateKey(rawKey)
	if err != nil {
		return fmt.Errorf("marshal private key: %w", err)
	}
	pemBlock := &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: der,
	}
	return os.WriteFile(path, pem.EncodeToMemory(pemBlock), 0600)
}

// LoadPrivateKey reads a PEM-encoded private key file and returns an ssh.Signer.
func LoadPrivateKey(path string) (ssh.Signer, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read key file: %w", err)
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found in %s", path)
	}

	var privKey interface{}
	switch block.Type {
	case "PRIVATE KEY":
		privKey, err = x509.ParsePKCS8PrivateKey(block.Bytes)
	case "RSA PRIVATE KEY":
		privKey, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	case "EC PRIVATE KEY":
		privKey, err = x509.ParseECPrivateKey(block.Bytes)
	default:
		return nil, fmt.Errorf("unsupported PEM type: %s", block.Type)
	}
	if err != nil {
		return nil, fmt.Errorf("parse private key: %w", err)
	}

	signer, err := ssh.NewSignerFromKey(privKey)
	if err != nil {
		return nil, fmt.Errorf("create signer from key: %w", err)
	}
	return &keyPairSigner{Signer: signer, rawKey: privKey}, nil
}

// PublicKeyFingerprint returns the SHA256 fingerprint of a public key in
// the standard "SHA256:..." format.
func PublicKeyFingerprint(key ssh.PublicKey) string {
	h := sha256.Sum256(key.Marshal())
	return "SHA256:" + base64.RawStdEncoding.EncodeToString(h[:])
}
