package sshca

import (
	"encoding/base64"
	"fmt"
	"strings"

	"golang.org/x/crypto/ssh"
)

// CertOption is a functional option for customizing certificate fields.
type CertOption func(*ssh.Certificate)

// WithForceCommand sets the force-command critical option on the certificate.
func WithForceCommand(cmd string) CertOption {
	return func(cert *ssh.Certificate) {
		if cert.CriticalOptions == nil {
			cert.CriticalOptions = make(map[string]string)
		}
		cert.CriticalOptions["force-command"] = cmd
	}
}

// WithSourceAddress restricts the certificate to the given source CIDR addresses.
func WithSourceAddress(addrs ...string) CertOption {
	return func(cert *ssh.Certificate) {
		if cert.CriticalOptions == nil {
			cert.CriticalOptions = make(map[string]string)
		}
		cert.CriticalOptions["source-address"] = strings.Join(addrs, ",")
	}
}

// WithExtensions merges additional extensions into the certificate.
func WithExtensions(exts map[string]string) CertOption {
	return func(cert *ssh.Certificate) {
		if cert.Extensions == nil {
			cert.Extensions = make(map[string]string)
		}
		for k, v := range exts {
			cert.Extensions[k] = v
		}
	}
}

// ParseCertificate parses a raw SSH certificate from authorized_keys format bytes.
func ParseCertificate(raw []byte) (*ssh.Certificate, error) {
	pubKey, _, _, _, err := ssh.ParseAuthorizedKey(raw)
	if err != nil {
		return nil, fmt.Errorf("parse authorized key: %w", err)
	}
	cert, ok := pubKey.(*ssh.Certificate)
	if !ok {
		return nil, fmt.Errorf("parsed key is not a certificate")
	}
	return cert, nil
}

// FormatCertificate returns a human-readable representation of an SSH certificate.
func FormatCertificate(cert *ssh.Certificate) string {
	var b strings.Builder

	certType := "user"
	if cert.CertType == ssh.HostCert {
		certType = "host"
	}

	fmt.Fprintf(&b, "Type: %s certificate\n", certType)
	fmt.Fprintf(&b, "Serial: %d\n", cert.Serial)
	fmt.Fprintf(&b, "Key ID: %s\n", cert.KeyId)
	fmt.Fprintf(&b, "Principals:\n")
	for _, p := range cert.ValidPrincipals {
		fmt.Fprintf(&b, "  - %s\n", p)
	}
	fmt.Fprintf(&b, "Valid After: %s\n", FormatUnixTime(cert.ValidAfter))
	fmt.Fprintf(&b, "Valid Before: %s\n", FormatUnixTime(cert.ValidBefore))
	fmt.Fprintf(&b, "Public Key: %s %s\n", cert.Key.Type(), PublicKeyFingerprint(cert.Key))

	if len(cert.CriticalOptions) > 0 {
		fmt.Fprintf(&b, "Critical Options:\n")
		for k, v := range cert.CriticalOptions {
			if v == "" {
				fmt.Fprintf(&b, "  - %s\n", k)
			} else {
				fmt.Fprintf(&b, "  - %s: %s\n", k, v)
			}
		}
	}

	if len(cert.Extensions) > 0 {
		fmt.Fprintf(&b, "Extensions:\n")
		for k := range cert.Extensions {
			fmt.Fprintf(&b, "  - %s\n", k)
		}
	}

	fmt.Fprintf(&b, "Signing CA: %s %s\n", cert.SignatureKey.Type(), PublicKeyFingerprint(cert.SignatureKey))

	return b.String()
}

// ValidateCertificate checks that a certificate is signed by the given CA key
// and is currently within its validity period.
func ValidateCertificate(cert *ssh.Certificate, caKey ssh.PublicKey) error {
	// Verify the signature matches the CA public key.
	certCAFingerprint := PublicKeyFingerprint(cert.SignatureKey)
	expectedFingerprint := PublicKeyFingerprint(caKey)
	if certCAFingerprint != expectedFingerprint {
		return fmt.Errorf("certificate signed by unknown CA: got %s, want %s", certCAFingerprint, expectedFingerprint)
	}

	// Use the ssh.CertChecker to validate the certificate.
	checker := &ssh.CertChecker{
		IsUserAuthority: func(auth ssh.PublicKey) bool {
			return PublicKeyFingerprint(auth) == expectedFingerprint
		},
		IsHostAuthority: func(auth ssh.PublicKey, address string) bool {
			return PublicKeyFingerprint(auth) == expectedFingerprint
		},
	}

	if cert.CertType == ssh.UserCert {
		// CheckCert requires a principal; use the first valid principal.
		principal := ""
		if len(cert.ValidPrincipals) > 0 {
			principal = cert.ValidPrincipals[0]
		}
		if err := checker.CheckCert(principal, cert); err != nil {
			return fmt.Errorf("certificate validation failed: %w", err)
		}
	} else if cert.CertType == ssh.HostCert {
		// CheckHostKey needs host:port format.
		addr := ""
		if len(cert.ValidPrincipals) > 0 {
			addr = cert.ValidPrincipals[0] + ":22"
		}
		if err := checker.CheckHostKey(addr, nil, cert); err != nil {
			return fmt.Errorf("certificate validation failed: %w", err)
		}
	}

	return nil
}

// MarshalCertAuthorizedKeys returns the certificate in authorized_keys format.
func MarshalCertAuthorizedKeys(cert *ssh.Certificate) string {
	b := cert.Marshal()
	return cert.Type() + " " + base64.StdEncoding.EncodeToString(b)
}
