package sshca

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func TestGenerateED25519Key(t *testing.T) {
	signer, err := GenerateED25519Key()
	if err != nil {
		t.Fatalf("GenerateED25519Key() error: %v", err)
	}
	if signer == nil {
		t.Fatal("expected non-nil signer")
	}
	if got := signer.PublicKey().Type(); got != "ssh-ed25519" {
		t.Errorf("key type = %q, want ssh-ed25519", got)
	}
}

func TestGenerateRSAKey(t *testing.T) {
	signer, err := GenerateRSAKey(2048)
	if err != nil {
		t.Fatalf("GenerateRSAKey(2048) error: %v", err)
	}
	if signer == nil {
		t.Fatal("expected non-nil signer")
	}
	if got := signer.PublicKey().Type(); got != "ssh-rsa" {
		t.Errorf("key type = %q, want ssh-rsa", got)
	}
}

func TestGenerateRSAKeyTooSmall(t *testing.T) {
	_, err := GenerateRSAKey(1024)
	if err == nil {
		t.Fatal("expected error for 1024-bit RSA key")
	}
}

func TestGenerateECDSAKey(t *testing.T) {
	signer, err := GenerateECDSAKey()
	if err != nil {
		t.Fatalf("GenerateECDSAKey() error: %v", err)
	}
	if signer == nil {
		t.Fatal("expected non-nil signer")
	}
	if got := signer.PublicKey().Type(); got != "ecdsa-sha2-nistp256" {
		t.Errorf("key type = %q, want ecdsa-sha2-nistp256", got)
	}
}

func TestSaveAndLoadPrivateKey(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test_key")

	original, err := GenerateED25519Key()
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	if err := SavePrivateKey(path, original); err != nil {
		t.Fatalf("SavePrivateKey() error: %v", err)
	}

	// Check file permissions.
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat key file: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0600 {
		t.Errorf("file permissions = %o, want 0600", perm)
	}

	loaded, err := LoadPrivateKey(path)
	if err != nil {
		t.Fatalf("LoadPrivateKey() error: %v", err)
	}

	// Verify the loaded key produces the same public key.
	origFP := PublicKeyFingerprint(original.PublicKey())
	loadedFP := PublicKeyFingerprint(loaded.PublicKey())
	if origFP != loadedFP {
		t.Errorf("fingerprints differ: original=%s, loaded=%s", origFP, loadedFP)
	}
}

func TestSaveAndLoadRSAKey(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test_rsa_key")

	original, err := GenerateRSAKey(2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	if err := SavePrivateKey(path, original); err != nil {
		t.Fatalf("SavePrivateKey() error: %v", err)
	}

	loaded, err := LoadPrivateKey(path)
	if err != nil {
		t.Fatalf("LoadPrivateKey() error: %v", err)
	}

	origFP := PublicKeyFingerprint(original.PublicKey())
	loadedFP := PublicKeyFingerprint(loaded.PublicKey())
	if origFP != loadedFP {
		t.Errorf("fingerprints differ: original=%s, loaded=%s", origFP, loadedFP)
	}
}

func TestPublicKeyFingerprint(t *testing.T) {
	signer, err := GenerateED25519Key()
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	fp := PublicKeyFingerprint(signer.PublicKey())
	if !strings.HasPrefix(fp, "SHA256:") {
		t.Errorf("fingerprint = %q, want SHA256:... prefix", fp)
	}
	if len(fp) < 10 {
		t.Errorf("fingerprint too short: %q", fp)
	}
}

func TestLoadPrivateKeyNotFound(t *testing.T) {
	_, err := LoadPrivateKey("/nonexistent/path/key")
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}

func testCA(t *testing.T) *CA {
	t.Helper()
	ca, err := New(&CAConfig{})
	if err != nil {
		t.Fatalf("New CA: %v", err)
	}
	return ca
}

func TestNewCA(t *testing.T) {
	ca := testCA(t)
	if ca.HostPublicKey() == "" {
		t.Error("host public key is empty")
	}
	if ca.UserPublicKey() == "" {
		t.Error("user public key is empty")
	}
}

func TestNewCAWithPaths(t *testing.T) {
	dir := t.TempDir()
	hostPath := filepath.Join(dir, "host_ca")
	userPath := filepath.Join(dir, "user_ca")

	ca, err := New(&CAConfig{
		HostKeyPath: hostPath,
		UserKeyPath: userPath,
	})
	if err != nil {
		t.Fatalf("New CA: %v", err)
	}

	// Keys should have been written.
	if _, err := os.Stat(hostPath); err != nil {
		t.Errorf("host key file not created: %v", err)
	}
	if _, err := os.Stat(userPath); err != nil {
		t.Errorf("user key file not created: %v", err)
	}

	// Creating a second CA from the same paths should load the same keys.
	ca2, err := New(&CAConfig{
		HostKeyPath: hostPath,
		UserKeyPath: userPath,
	})
	if err != nil {
		t.Fatalf("New CA (reload): %v", err)
	}
	if ca.HostPublicKey() != ca2.HostPublicKey() {
		t.Error("host public keys differ after reload")
	}
	if ca.UserPublicKey() != ca2.UserPublicKey() {
		t.Error("user public keys differ after reload")
	}
}

func TestSignUserCert(t *testing.T) {
	ca := testCA(t)

	userKey, err := GenerateED25519Key()
	if err != nil {
		t.Fatalf("generate user key: %v", err)
	}

	cert, err := ca.SignUserCert(userKey.PublicKey(), "testuser", []string{"testuser"}, 1*time.Hour)
	if err != nil {
		t.Fatalf("SignUserCert() error: %v", err)
	}

	if cert.CertType != ssh.UserCert {
		t.Errorf("cert type = %d, want %d (UserCert)", cert.CertType, ssh.UserCert)
	}
	if cert.KeyId == "" {
		t.Error("cert key ID is empty")
	}
	if len(cert.ValidPrincipals) != 1 || cert.ValidPrincipals[0] != "testuser" {
		t.Errorf("principals = %v, want [testuser]", cert.ValidPrincipals)
	}

	// Must have default extensions.
	for _, ext := range []string{"permit-pty", "permit-user-rc", "permit-port-forwarding", "permit-agent-forwarding"} {
		if _, ok := cert.Extensions[ext]; !ok {
			t.Errorf("missing extension: %s", ext)
		}
	}
}

func TestSignUserCertValidation(t *testing.T) {
	ca := testCA(t)

	userKey, err := GenerateED25519Key()
	if err != nil {
		t.Fatalf("generate user key: %v", err)
	}

	cert, err := ca.SignUserCert(userKey.PublicKey(), "testuser", []string{"testuser"}, 1*time.Hour)
	if err != nil {
		t.Fatalf("SignUserCert() error: %v", err)
	}

	if err := ValidateCertificate(cert, ca.userKeyPub); err != nil {
		t.Errorf("ValidateCertificate() error: %v", err)
	}
}

func TestSignHostCert(t *testing.T) {
	ca := testCA(t)

	hostKey, err := GenerateED25519Key()
	if err != nil {
		t.Fatalf("generate host key: %v", err)
	}

	cert, err := ca.SignHostCert(hostKey.PublicKey(), "server1.example.com", 24*time.Hour)
	if err != nil {
		t.Fatalf("SignHostCert() error: %v", err)
	}

	if cert.CertType != ssh.HostCert {
		t.Errorf("cert type = %d, want %d (HostCert)", cert.CertType, ssh.HostCert)
	}
	if len(cert.ValidPrincipals) != 1 || cert.ValidPrincipals[0] != "server1.example.com" {
		t.Errorf("principals = %v, want [server1.example.com]", cert.ValidPrincipals)
	}
}

func TestSignHostCertValidation(t *testing.T) {
	ca := testCA(t)

	hostKey, err := GenerateED25519Key()
	if err != nil {
		t.Fatalf("generate host key: %v", err)
	}

	cert, err := ca.SignHostCert(hostKey.PublicKey(), "server1.example.com", 24*time.Hour)
	if err != nil {
		t.Fatalf("SignHostCert() error: %v", err)
	}

	if err := ValidateCertificate(cert, ca.hostKeyPub); err != nil {
		t.Errorf("ValidateCertificate() error: %v", err)
	}
}

func TestSignUserCertWithForceCommand(t *testing.T) {
	ca := testCA(t)

	userKey, err := GenerateED25519Key()
	if err != nil {
		t.Fatalf("generate user key: %v", err)
	}

	cert, err := ca.SignUserCert(
		userKey.PublicKey(), "deploy", []string{"deploy"}, 1*time.Hour,
		WithForceCommand("/usr/bin/deploy.sh"),
	)
	if err != nil {
		t.Fatalf("SignUserCert() error: %v", err)
	}

	if cmd, ok := cert.CriticalOptions["force-command"]; !ok || cmd != "/usr/bin/deploy.sh" {
		t.Errorf("force-command = %q, want /usr/bin/deploy.sh", cmd)
	}
}

func TestSignUserCertWithSourceAddress(t *testing.T) {
	ca := testCA(t)

	userKey, err := GenerateED25519Key()
	if err != nil {
		t.Fatalf("generate user key: %v", err)
	}

	cert, err := ca.SignUserCert(
		userKey.PublicKey(), "user1", []string{"user1"}, 1*time.Hour,
		WithSourceAddress("10.0.0.0/8", "192.168.1.0/24"),
	)
	if err != nil {
		t.Fatalf("SignUserCert() error: %v", err)
	}

	addr, ok := cert.CriticalOptions["source-address"]
	if !ok {
		t.Fatal("missing source-address critical option")
	}
	if addr != "10.0.0.0/8,192.168.1.0/24" {
		t.Errorf("source-address = %q, want 10.0.0.0/8,192.168.1.0/24", addr)
	}
}

func TestSignUserCertWithCustomExtensions(t *testing.T) {
	ca := testCA(t)

	userKey, err := GenerateED25519Key()
	if err != nil {
		t.Fatalf("generate user key: %v", err)
	}

	cert, err := ca.SignUserCert(
		userKey.PublicKey(), "user1", []string{"user1"}, 1*time.Hour,
		WithExtensions(map[string]string{"permit-X11-forwarding": ""}),
	)
	if err != nil {
		t.Fatalf("SignUserCert() error: %v", err)
	}

	if _, ok := cert.Extensions["permit-X11-forwarding"]; !ok {
		t.Error("missing custom extension permit-X11-forwarding")
	}
	// Default extensions should still be present.
	if _, ok := cert.Extensions["permit-pty"]; !ok {
		t.Error("missing default extension permit-pty")
	}
}

func TestSignUserCertNoPrincipals(t *testing.T) {
	ca := testCA(t)

	userKey, err := GenerateED25519Key()
	if err != nil {
		t.Fatalf("generate user key: %v", err)
	}

	_, err = ca.SignUserCert(userKey.PublicKey(), "user1", nil, 1*time.Hour)
	if err == nil {
		t.Fatal("expected error for empty principals")
	}
}

func TestSignHostCertNoHostname(t *testing.T) {
	ca := testCA(t)

	hostKey, err := GenerateED25519Key()
	if err != nil {
		t.Fatalf("generate host key: %v", err)
	}

	_, err = ca.SignHostCert(hostKey.PublicKey(), "", 24*time.Hour)
	if err == nil {
		t.Fatal("expected error for empty hostname")
	}
}

func TestSignUserCertTTLExceedsMax(t *testing.T) {
	ca, err := New(&CAConfig{
		MaxCertTTL: 1 * time.Hour,
	})
	if err != nil {
		t.Fatalf("New CA: %v", err)
	}

	userKey, err := GenerateED25519Key()
	if err != nil {
		t.Fatalf("generate user key: %v", err)
	}

	_, err = ca.SignUserCert(userKey.PublicKey(), "user1", []string{"user1"}, 2*time.Hour)
	if err == nil {
		t.Fatal("expected error for TTL exceeding max")
	}
}

func TestSignUserCertAllowedPrincipals(t *testing.T) {
	ca, err := New(&CAConfig{
		AllowedPrincipals: []string{"deploy", "ubuntu"},
	})
	if err != nil {
		t.Fatalf("New CA: %v", err)
	}

	userKey, err := GenerateED25519Key()
	if err != nil {
		t.Fatalf("generate user key: %v", err)
	}

	// Allowed principal should work.
	_, err = ca.SignUserCert(userKey.PublicKey(), "deploy", []string{"deploy"}, 1*time.Hour)
	if err != nil {
		t.Errorf("expected success for allowed principal: %v", err)
	}

	// Disallowed principal should fail.
	_, err = ca.SignUserCert(userKey.PublicKey(), "root", []string{"root"}, 1*time.Hour)
	if err == nil {
		t.Error("expected error for disallowed principal")
	}
}

func TestCertificateExpiry(t *testing.T) {
	ca := testCA(t)

	userKey, err := GenerateED25519Key()
	if err != nil {
		t.Fatalf("generate user key: %v", err)
	}

	cert, err := ca.SignUserCert(userKey.PublicKey(), "testuser", []string{"testuser"}, 1*time.Hour)
	if err != nil {
		t.Fatalf("SignUserCert() error: %v", err)
	}

	// Certificate should not be expired yet.
	now := time.Now()
	validAfter := time.Unix(int64(cert.ValidAfter), 0)
	validBefore := time.Unix(int64(cert.ValidBefore), 0)

	if now.Before(validAfter) {
		t.Errorf("cert not yet valid: now=%v, validAfter=%v", now, validAfter)
	}
	if now.After(validBefore) {
		t.Errorf("cert already expired: now=%v, validBefore=%v", now, validBefore)
	}

	// ValidBefore should be approximately 1 hour from now.
	expected := now.Add(1 * time.Hour)
	diff := validBefore.Sub(expected)
	if diff < -1*time.Minute || diff > 1*time.Minute {
		t.Errorf("validBefore off by %v from expected", diff)
	}
}

func TestValidateCertificateWrongCA(t *testing.T) {
	ca := testCA(t)

	userKey, err := GenerateED25519Key()
	if err != nil {
		t.Fatalf("generate user key: %v", err)
	}

	cert, err := ca.SignUserCert(userKey.PublicKey(), "testuser", []string{"testuser"}, 1*time.Hour)
	if err != nil {
		t.Fatalf("SignUserCert() error: %v", err)
	}

	// Validate against a different CA's public key.
	otherCA := testCA(t)
	err = ValidateCertificate(cert, otherCA.userKeyPub)
	if err == nil {
		t.Fatal("expected error validating against wrong CA")
	}
}

func TestFormatCertificate(t *testing.T) {
	ca := testCA(t)

	userKey, err := GenerateED25519Key()
	if err != nil {
		t.Fatalf("generate user key: %v", err)
	}

	cert, err := ca.SignUserCert(userKey.PublicKey(), "testuser", []string{"testuser", "admin"}, 1*time.Hour)
	if err != nil {
		t.Fatalf("SignUserCert() error: %v", err)
	}

	output := FormatCertificate(cert)
	if !strings.Contains(output, "user certificate") {
		t.Error("format output should contain 'user certificate'")
	}
	if !strings.Contains(output, "testuser") {
		t.Error("format output should contain principal 'testuser'")
	}
	if !strings.Contains(output, "admin") {
		t.Error("format output should contain principal 'admin'")
	}
	if !strings.Contains(output, "permit-pty") {
		t.Error("format output should contain extension 'permit-pty'")
	}
}

func TestParseCertificate(t *testing.T) {
	ca := testCA(t)

	userKey, err := GenerateED25519Key()
	if err != nil {
		t.Fatalf("generate user key: %v", err)
	}

	cert, err := ca.SignUserCert(userKey.PublicKey(), "testuser", []string{"testuser"}, 1*time.Hour)
	if err != nil {
		t.Fatalf("SignUserCert() error: %v", err)
	}

	// Marshal and parse back.
	raw := MarshalCertAuthorizedKeys(cert)
	parsed, err := ParseCertificate([]byte(raw))
	if err != nil {
		t.Fatalf("ParseCertificate() error: %v", err)
	}

	if parsed.Serial != cert.Serial {
		t.Errorf("serial = %d, want %d", parsed.Serial, cert.Serial)
	}
	if parsed.KeyId != cert.KeyId {
		t.Errorf("key ID = %q, want %q", parsed.KeyId, cert.KeyId)
	}
}

func TestCertSerialUniqueness(t *testing.T) {
	ca := testCA(t)

	userKey, err := GenerateED25519Key()
	if err != nil {
		t.Fatalf("generate user key: %v", err)
	}

	serials := make(map[uint64]bool)
	for i := 0; i < 100; i++ {
		cert, err := ca.SignUserCert(userKey.PublicKey(), "testuser", []string{"testuser"}, 1*time.Hour)
		if err != nil {
			t.Fatalf("SignUserCert() #%d error: %v", i, err)
		}
		if serials[cert.Serial] {
			t.Fatalf("duplicate serial %d at iteration %d", cert.Serial, i)
		}
		serials[cert.Serial] = true
	}
}

func TestListAndRevokeCerts(t *testing.T) {
	ca := testCA(t)

	userKey, err := GenerateED25519Key()
	if err != nil {
		t.Fatalf("generate user key: %v", err)
	}

	cert, err := ca.SignUserCert(userKey.PublicKey(), "testuser", []string{"testuser"}, 1*time.Hour)
	if err != nil {
		t.Fatalf("SignUserCert() error: %v", err)
	}

	certs := ca.ListIssuedCerts()
	if len(certs) != 1 {
		t.Fatalf("expected 1 cert, got %d", len(certs))
	}
	if certs[0].Revoked {
		t.Error("cert should not be revoked yet")
	}

	if err := ca.RevokeCert(cert.Serial); err != nil {
		t.Fatalf("RevokeCert() error: %v", err)
	}

	if !ca.IsRevoked(cert.Serial) {
		t.Error("cert should be revoked")
	}

	certs = ca.ListIssuedCerts()
	if !certs[0].Revoked {
		t.Error("listed cert should show as revoked")
	}
}

func TestRevokeNonexistentCert(t *testing.T) {
	ca := testCA(t)
	err := ca.RevokeCert(99999)
	if err == nil {
		t.Fatal("expected error revoking nonexistent cert")
	}
}

func TestDefaultTTL(t *testing.T) {
	ca := testCA(t)

	userKey, err := GenerateED25519Key()
	if err != nil {
		t.Fatalf("generate user key: %v", err)
	}

	// Pass 0 TTL to use default.
	cert, err := ca.SignUserCert(userKey.PublicKey(), "testuser", []string{"testuser"}, 0)
	if err != nil {
		t.Fatalf("SignUserCert() error: %v", err)
	}

	validBefore := time.Unix(int64(cert.ValidBefore), 0)
	expected := time.Now().Add(8 * time.Hour)
	diff := validBefore.Sub(expected)
	if diff < -1*time.Minute || diff > 1*time.Minute {
		t.Errorf("default TTL: validBefore off by %v from expected 8h", diff)
	}
}

func TestHostPublicKeyFormat(t *testing.T) {
	ca := testCA(t)
	pk := ca.HostPublicKey()
	if !strings.HasPrefix(pk, "ssh-ed25519 ") {
		t.Errorf("host public key should start with 'ssh-ed25519 ', got: %s", pk[:min(30, len(pk))])
	}
}

func TestUserPublicKeyFormat(t *testing.T) {
	ca := testCA(t)
	pk := ca.UserPublicKey()
	if !strings.HasPrefix(pk, "ssh-ed25519 ") {
		t.Errorf("user public key should start with 'ssh-ed25519 ', got: %s", pk[:min(30, len(pk))])
	}
}
