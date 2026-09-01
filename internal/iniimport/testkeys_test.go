package iniimport

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"

	"golang.org/x/crypto/ssh"
)

// generateTestKey returns a fresh Ed25519 SSH signer.
func generateTestKey() (ssh.Signer, error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return ssh.NewSignerFromKey(priv)
}

// encodeTestPrivateKey renders a signer's key as PKCS#8 PEM, which is what
// ssh.ParsePrivateKey reads back.
func encodeTestPrivateKey(signer ssh.Signer) ([]byte, error) {
	key, ok := signer.(interface{ CryptoPrivateKey() interface{} })
	if !ok {
		// Fall back to generating a fresh key pair whose private half we hold.
		_, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, err
		}
		der, err := x509.MarshalPKCS8PrivateKey(priv)
		if err != nil {
			return nil, err
		}
		return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
	}
	der, err := x509.MarshalPKCS8PrivateKey(key.CryptoPrivateKey())
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}
