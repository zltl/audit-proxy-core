package iniimport

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/zltl/audit-proxy-core/internal/authn"
	"github.com/zltl/audit-proxy-core/internal/secrets"
	"github.com/zltl/audit-proxy-core/internal/store"
)

func newStore(t *testing.T, withSealer bool) *store.Store {
	t.Helper()
	st, err := store.Open("sqlite", filepath.Join(t.TempDir(), "store.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	if withSealer {
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
		st.SetSealer(sealer)
	}
	return st
}

func writeINI(t *testing.T, contents string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.ini")
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatalf("write config.ini: %v", err)
	}
	return path
}

// The example configuration this project ships, trimmed to the sections that
// carry identity, authorization, and routing.
const sampleINI = `
[server]
bind_addr = 0.0.0.0
port = 2222

[limits]
max_sessions = 100
session_timeout = 3600
per_user_max_sessions = 4

[ip_acl]
mode = blacklist
rules = 127.0.0.0/8:allow, 10.0.0.0/8:allow, 192.0.2.0/24:deny

[user:test]
password_hash = $6$saltsalt$U5d2t4MFT.Hn/auqLjcfU6R/lm2Y71FvBwABEOht/UpRtNzcFvzGl/oU6V38pYgY8ZpicOa.0ESff5jRNylZM.
password_changed_at = 1735689600
enabled = true

[user:admin]
password_hash = $6$saltsalt$U5d2t4MFT.Hn/auqLjcfU6R/lm2Y71FvBwABEOht/UpRtNzcFvzGl/oU6V38pYgY8ZpicOa.0ESff5jRNylZM.
enabled = true

[user:retired]
password_hash = $6$saltsalt$U5d2t4MFT.Hn/auqLjcfU6R/lm2Y71FvBwABEOht/UpRtNzcFvzGl/oU6V38pYgY8ZpicOa.0ESff5jRNylZM.
enabled = false

[route:admin]
upstream = 10.0.1.10
port = 22
user = root

[route:test]
upstream = 10.0.1.10
port = 22
user = appuser

[route:*]
upstream = 10.0.2.20
port = 2222
user = guest

[policy:admin]
allow = all

[policy:test]
allow = shell, exec, scp, sftp
deny = port_forward, x11, agent

[policy:*]
allow = shell, exec, download
deny = upload, port_forward
`

func TestImportSampleConfiguration(t *testing.T) {
	st := newStore(t, true)
	path := writeINI(t, sampleINI)

	result, err := Import(path, st, Options{})
	if err != nil {
		t.Fatalf("Import: %v", err)
	}

	if result.Users != 3 {
		t.Errorf("imported %d users, want 3", result.Users)
	}
	// Two routes share a host, so they collapse into one target.
	if result.Targets != 2 {
		t.Errorf("imported %d targets, want 2", result.Targets)
	}
	if result.AccessRules != 3 {
		t.Errorf("imported %d access rules, want 3", result.AccessRules)
	}
	if result.IPRules != 3 {
		t.Errorf("imported %d ip rules, want 3", result.IPRules)
	}

	// The imported password hash must still authenticate, or the migration
	// locks every existing user out.
	user, err := st.GetUser("test")
	if err != nil {
		t.Fatalf("GetUser: %v", err)
	}
	if !authn.VerifyPassword("test123", user.PasswordHash) {
		t.Fatal("the imported crypt(3) hash no longer verifies the original password")
	}
	if !user.Enabled() {
		t.Error("an enabled user was imported as disabled")
	}
	if user.PasswordChangedAt.IsZero() {
		t.Error("password_changed_at was not carried over")
	}

	retired, err := st.GetUser("retired")
	if err != nil {
		t.Fatalf("GetUser retired: %v", err)
	}
	if retired.Enabled() {
		t.Error("a disabled user was imported as active")
	}
}

func TestImportPreservesPolicyMeaning(t *testing.T) {
	st := newStore(t, true)
	path := writeINI(t, sampleINI)
	if _, err := Import(path, st, Options{}); err != nil {
		t.Fatalf("Import: %v", err)
	}

	rules, err := st.ListEnabledAccessRules()
	if err != nil {
		t.Fatalf("ListEnabledAccessRules: %v", err)
	}

	byHost, err := st.FindTargetByAddress("10.0.1.10", 22)
	if err != nil {
		t.Fatalf("FindTargetByAddress: %v", err)
	}
	fallbackTarget, err := st.FindTargetByAddress("10.0.2.20", 2222)
	if err != nil {
		t.Fatalf("FindTargetByAddress fallback: %v", err)
	}

	t.Run("admin keeps full access", func(t *testing.T) {
		d := store.EvaluateRules(rules, store.AccessRequest{
			Username: "admin", Target: byHost, UpstreamLogin: "root",
		})
		if !d.Allowed {
			t.Fatalf("admin was refused: %s", d.Reason)
		}
		if !d.Features.Has(store.FeatureLocalForward) || !d.Features.Has(store.FeatureSFTP) {
			t.Errorf("allow=all did not survive the import: %s", d.Features)
		}
	})

	t.Run("test keeps its denials", func(t *testing.T) {
		d := store.EvaluateRules(rules, store.AccessRequest{
			Username: "test", Target: byHost, UpstreamLogin: "appuser",
		})
		if !d.Allowed {
			t.Fatalf("test was refused: %s", d.Reason)
		}
		if !d.Features.Has(store.FeatureShell) || !d.Features.Has(store.FeatureSFTP) {
			t.Errorf("allowed features were lost: %s", d.Features)
		}
		// deny = port_forward covered all three forwarding kinds in the legacy
		// syntax; that has to keep holding.
		for _, denied := range []store.FeatureSet{
			store.FeatureLocalForward, store.FeatureRemoteForward,
			store.FeatureDynamicForward, store.FeatureX11, store.FeatureAgentForward,
		} {
			if d.Features.Has(denied) {
				t.Errorf("a denied feature survived the import: %s in %s", denied, d.Features)
			}
		}
	})

	t.Run("upstream account is pinned", func(t *testing.T) {
		d := store.EvaluateRules(rules, store.AccessRequest{
			Username: "test", Target: byHost, UpstreamLogin: "root",
		})
		if d.Allowed {
			t.Fatal("the test user should not be able to log in as root; the route pinned appuser")
		}
	})

	t.Run("wildcard route applies to anyone else", func(t *testing.T) {
		d := store.EvaluateRules(rules, store.AccessRequest{
			Username: "someone-else", Target: fallbackTarget, UpstreamLogin: "guest",
		})
		if !d.Allowed {
			t.Fatalf("the wildcard route did not apply: %s", d.Reason)
		}
		if d.Features.Has(store.FeatureUpload) {
			t.Error("deny = upload was lost for the wildcard route")
		}
	})

	t.Run("per-user session limit carried over", func(t *testing.T) {
		d := store.EvaluateRules(rules, store.AccessRequest{
			Username: "admin", Target: byHost, UpstreamLogin: "root",
		})
		if d.MaxConcurrent != 4 {
			t.Errorf("MaxConcurrent = %d, want the per_user_max_sessions value 4", d.MaxConcurrent)
		}
		if d.MaxSessionTTL.Seconds() != 3600 {
			t.Errorf("MaxSessionTTL = %v, want the session_timeout value", d.MaxSessionTTL)
		}
	})
}

func TestImportSpecificRulesOutrankTheWildcard(t *testing.T) {
	st := newStore(t, true)
	path := writeINI(t, sampleINI)
	if _, err := Import(path, st, Options{}); err != nil {
		t.Fatalf("Import: %v", err)
	}
	rules, err := st.ListEnabledAccessRules()
	if err != nil {
		t.Fatalf("ListEnabledAccessRules: %v", err)
	}

	// The catch-all route must be considered last, or it would shadow the
	// per-user routes and hand everyone the same access.
	last := rules[len(rules)-1]
	if last.SubjectKind != store.SubjectAny {
		t.Fatalf("the wildcard rule should sort last, got %+v", last)
	}
	for _, r := range rules[:len(rules)-1] {
		if r.Priority >= last.Priority {
			t.Errorf("specific rule %q has priority %d, not ahead of the wildcard's %d",
				r.Name, r.Priority, last.Priority)
		}
	}
}

func TestImportIsRepeatable(t *testing.T) {
	st := newStore(t, true)
	path := writeINI(t, sampleINI)

	first, err := Import(path, st, Options{})
	if err != nil {
		t.Fatalf("first Import: %v", err)
	}
	second, err := Import(path, st, Options{})
	if err != nil {
		t.Fatalf("second Import: %v", err)
	}
	if first.Users != second.Users || first.Targets != second.Targets {
		t.Errorf("counts differ between runs: %+v vs %+v", first, second)
	}

	users, err := st.ListUsers()
	if err != nil {
		t.Fatalf("ListUsers: %v", err)
	}
	if len(users) != 3 {
		t.Fatalf("re-importing duplicated users: %d rows", len(users))
	}
	targets, err := st.ListTargets()
	if err != nil {
		t.Fatalf("ListTargets: %v", err)
	}
	if len(targets) != 2 {
		t.Fatalf("re-importing duplicated targets: %d rows", len(targets))
	}
	rules, err := st.ListAccessRules()
	if err != nil {
		t.Fatalf("ListAccessRules: %v", err)
	}
	if len(rules) != 3 {
		t.Fatalf("re-importing duplicated access rules: %d rows", len(rules))
	}
}

func TestImportPublicKeys(t *testing.T) {
	st := newStore(t, true)

	signer, err := generateTestKey()
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	authorized := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(signer.PublicKey())))

	keyFile := filepath.Join(t.TempDir(), "extra.pub")
	secondSigner, err := generateTestKey()
	if err != nil {
		t.Fatalf("generate second key: %v", err)
	}
	if err := os.WriteFile(keyFile, ssh.MarshalAuthorizedKey(secondSigner.PublicKey()), 0o600); err != nil {
		t.Fatalf("write pubkey file: %v", err)
	}

	path := writeINI(t, "[user:alice]\npubkey = "+authorized+" alice@laptop\npubkey_file = "+keyFile+"\npubkey = not-a-valid-key\n")

	result, err := Import(path, st, Options{})
	if err != nil {
		t.Fatalf("Import: %v", err)
	}
	if result.PublicKeys != 2 {
		t.Fatalf("imported %d public keys, want 2", result.PublicKeys)
	}
	if len(result.Warnings) == 0 {
		t.Error("the unparseable key should have produced a warning rather than being dropped silently")
	}

	_, owner, err := st.FindPublicKey(ssh.FingerprintSHA256(signer.PublicKey()))
	if err != nil {
		t.Fatalf("FindPublicKey: %v", err)
	}
	if owner.Username != "alice" {
		t.Fatalf("key resolved to %q", owner.Username)
	}
}

func TestImportPrivateKeyRequiresOptInAndSealer(t *testing.T) {
	signer, err := generateTestKey()
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	pem, err := encodeTestPrivateKey(signer)
	if err != nil {
		t.Fatalf("encode key: %v", err)
	}
	keyPath := filepath.Join(t.TempDir(), "id_ed25519")
	if err := os.WriteFile(keyPath, pem, 0o600); err != nil {
		t.Fatalf("write private key: %v", err)
	}
	ini := "[route:admin]\nupstream = 10.0.1.10\nuser = root\nprivkey = " + keyPath + "\n"

	t.Run("not imported by default", func(t *testing.T) {
		st := newStore(t, true)
		result, err := Import(writeINI(t, ini), st, Options{})
		if err != nil {
			t.Fatalf("Import: %v", err)
		}
		if result.Secrets != 0 {
			t.Fatal("private key material must not be moved into the database without an explicit opt-in")
		}
		if len(result.Warnings) == 0 {
			t.Error("skipping the key should be reported")
		}
		creds, err := st.ListCredentials()
		if err != nil {
			t.Fatalf("ListCredentials: %v", err)
		}
		if len(creds) != 1 || creds[0].Kind != store.CredentialAgent {
			t.Fatalf("expected a placeholder credential, got %+v", creds)
		}
	})

	t.Run("imported on request", func(t *testing.T) {
		st := newStore(t, true)
		result, err := Import(writeINI(t, ini), st, Options{ImportPrivateKeys: true})
		if err != nil {
			t.Fatalf("Import: %v", err)
		}
		if result.Secrets != 1 {
			t.Fatalf("sealed %d secrets, want 1", result.Secrets)
		}
		creds, err := st.ListCredentials()
		if err != nil {
			t.Fatalf("ListCredentials: %v", err)
		}
		if len(creds) != 1 || creds[0].Kind != store.CredentialPrivateKey || creds[0].SecretRef == "" {
			t.Fatalf("credential does not reference sealed material: %+v", creds)
		}
		material, err := st.GetSecret(creds[0].SecretRef)
		if err != nil {
			t.Fatalf("GetSecret: %v", err)
		}
		if _, err := ssh.ParsePrivateKey(material); err != nil {
			t.Fatalf("the stored material is not the private key: %v", err)
		}
	})

	t.Run("refused without an encryption key", func(t *testing.T) {
		st := newStore(t, false)
		result, err := Import(writeINI(t, ini), st, Options{ImportPrivateKeys: true})
		if err != nil {
			t.Fatalf("Import: %v", err)
		}
		if result.Secrets != 0 {
			t.Fatal("key material was stored without an encryption key configured")
		}
		if len(result.Warnings) == 0 {
			t.Error("the refusal should be reported to the operator")
		}
	})
}

func TestImportWhitelistModeAddsDefaultDeny(t *testing.T) {
	st := newStore(t, true)
	path := writeINI(t, "[ip_acl]\nmode = whitelist\nrules = 10.0.0.0/8, 192.168.0.0/16\n")

	if _, err := Import(path, st, Options{}); err != nil {
		t.Fatalf("Import: %v", err)
	}

	allowed, _, err := st.CheckSourceIP("10.1.2.3")
	if err != nil {
		t.Fatalf("CheckSourceIP: %v", err)
	}
	if !allowed {
		t.Error("a whitelisted network was refused")
	}
	allowed, _, err = st.CheckSourceIP("8.8.8.8")
	if err != nil {
		t.Fatalf("CheckSourceIP: %v", err)
	}
	if allowed {
		t.Error("whitelist mode must refuse anything not listed; the implicit default deny is missing")
	}
}

func TestImportTOTPSecretIsSealed(t *testing.T) {
	st := newStore(t, true)
	path := writeINI(t, "[user:mona]\npassword_hash = $6$saltsalt$x\ntotp_secret = JBSWY3DPEHPK3PXP\n")

	result, err := Import(path, st, Options{})
	if err != nil {
		t.Fatalf("Import: %v", err)
	}
	if result.Secrets != 1 {
		t.Fatalf("sealed %d secrets, want 1", result.Secrets)
	}

	user, err := st.GetUser("mona")
	if err != nil {
		t.Fatalf("GetUser: %v", err)
	}
	if user.MFAType != store.MFATOTP || user.MFASecretRef == "" {
		t.Fatalf("MFA was not carried over: %+v", user)
	}
	if user.MFAPending {
		t.Error("a TOTP secret that was already in use should not be marked as a pending enrolment")
	}
	if strings.Contains(user.MFASecretRef, "JBSWY3DPEHPK3PXP") {
		t.Fatal("the reference contains the secret itself")
	}
	secret, err := st.GetSecretString(user.MFASecretRef)
	if err != nil {
		t.Fatalf("GetSecretString: %v", err)
	}
	if secret != "JBSWY3DPEHPK3PXP" {
		t.Fatalf("sealed secret = %q", secret)
	}
}

func TestImportReportsUnknownPolicyFeatures(t *testing.T) {
	st := newStore(t, true)
	path := writeINI(t, "[route:alice]\nupstream = 10.0.1.1\nuser = root\n\n[policy:alice]\nallow = shell, teleport\n")

	result, err := Import(path, st, Options{})
	if err != nil {
		t.Fatalf("Import: %v", err)
	}
	found := false
	for _, w := range result.Warnings {
		if strings.Contains(w, "teleport") {
			found = true
		}
	}
	if !found {
		t.Fatalf("an unknown feature name should be reported, got warnings %v", result.Warnings)
	}
}
