package pdp

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc/metadata"

	auditproxyv1 "github.com/zltl/audit-proxy-core/api/proto/auditproxy/v1"
	"github.com/zltl/audit-proxy-core/internal/authn"
	"github.com/zltl/audit-proxy-core/internal/secrets"
	"github.com/zltl/audit-proxy-core/internal/store"
)

type fixture struct {
	t      *testing.T
	store  *store.Store
	server *Server
	target store.Target
}

func newFixture(t *testing.T) *fixture {
	t.Helper()

	st, err := store.Open("sqlite", filepath.Join(t.TempDir(), "pdp.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

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

	srv, err := New(st, Config{StateSecret: []byte("test-state-secret")})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	target, err := st.CreateTarget(store.Target{
		Name: "web-1", Host: "10.0.1.10", Port: 22, Group: "web",
		Tags: map[string]string{"env": "prod"}, Enabled: true,
	})
	if err != nil {
		t.Fatalf("CreateTarget: %v", err)
	}

	return &fixture{t: t, store: st, server: srv, target: target}
}

func (f *fixture) addUser(username, password string) store.User {
	f.t.Helper()
	hash, err := authn.HashPassword(password)
	if err != nil {
		f.t.Fatalf("HashPassword: %v", err)
	}
	user, err := f.store.CreateUser(store.User{Username: username, PasswordHash: hash})
	if err != nil {
		f.t.Fatalf("CreateUser: %v", err)
	}
	return user
}

func (f *fixture) allowRule(rule store.AccessRule) store.AccessRule {
	f.t.Helper()
	if rule.Effect == "" {
		rule.Effect = store.EffectAllow
	}
	if rule.SubjectKind == "" {
		rule.SubjectKind = store.SubjectAny
	}
	if rule.TargetSelector == "" {
		rule.TargetSelector = "*"
	}
	rule.Enabled = true
	saved, err := f.store.PutAccessRule(rule)
	if err != nil {
		f.t.Fatalf("PutAccessRule: %v", err)
	}
	return saved
}

// --------------------------------------------------------------------------
// Authentication
// --------------------------------------------------------------------------

func TestAuthenticatePassword(t *testing.T) {
	f := newFixture(t)
	f.addUser("alice", "correct-password-1")

	resp, err := f.server.Authenticate(context.Background(), &auditproxyv1.AuthenticateRequest{
		Username: "alice",
		Method:   auditproxyv1.AuthMethod_AUTH_METHOD_PASSWORD,
		Password: "correct-password-1",
	})
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if resp.GetResult() != auditproxyv1.AuthResult_AUTH_RESULT_SUCCESS {
		t.Fatalf("result = %v, reason %q", resp.GetResult(), resp.GetReason())
	}
	if resp.GetUsername() != "alice" {
		t.Errorf("username = %q", resp.GetUsername())
	}
}

func TestAuthenticateRejectsBadCredentials(t *testing.T) {
	f := newFixture(t)
	f.addUser("alice", "correct-password-1")

	cases := []struct {
		name string
		req  *auditproxyv1.AuthenticateRequest
	}{
		{"wrong password", &auditproxyv1.AuthenticateRequest{
			Username: "alice", Method: auditproxyv1.AuthMethod_AUTH_METHOD_PASSWORD,
			Password: "wrong",
		}},
		{"unknown user", &auditproxyv1.AuthenticateRequest{
			Username: "nobody", Method: auditproxyv1.AuthMethod_AUTH_METHOD_PASSWORD,
			Password: "correct-password-1",
		}},
		{"empty username", &auditproxyv1.AuthenticateRequest{
			Method: auditproxyv1.AuthMethod_AUTH_METHOD_PASSWORD, Password: "x",
		}},
		{"unsupported method", &auditproxyv1.AuthenticateRequest{
			Username: "alice", Method: auditproxyv1.AuthMethod_AUTH_METHOD_NONE,
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp, err := f.server.Authenticate(context.Background(), tc.req)
			if err != nil {
				t.Fatalf("Authenticate: %v", err)
			}
			if resp.GetResult() != auditproxyv1.AuthResult_AUTH_RESULT_FAILURE {
				t.Fatalf("result = %v, want FAILURE", resp.GetResult())
			}
		})
	}
}

func TestAuthenticateDoesNotRevealWhetherAnAccountExists(t *testing.T) {
	f := newFixture(t)
	f.addUser("alice", "correct-password-1")

	known, err := f.server.Authenticate(context.Background(), &auditproxyv1.AuthenticateRequest{
		Username: "alice", Method: auditproxyv1.AuthMethod_AUTH_METHOD_PASSWORD, Password: "wrong",
	})
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	unknown, err := f.server.Authenticate(context.Background(), &auditproxyv1.AuthenticateRequest{
		Username: "ghost", Method: auditproxyv1.AuthMethod_AUTH_METHOD_PASSWORD, Password: "wrong",
	})
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if known.GetReason() != unknown.GetReason() {
		t.Fatalf("refusal wording differs between a known and an unknown account: %q vs %q",
			known.GetReason(), unknown.GetReason())
	}
}

func TestAuthenticateRejectsDisabledAccount(t *testing.T) {
	f := newFixture(t)
	f.addUser("dormant", "some-password-12")
	if _, err := f.store.UpdateUser("dormant", func(u *store.User) error {
		u.Status = store.UserDisabled
		return nil
	}); err != nil {
		t.Fatalf("UpdateUser: %v", err)
	}

	resp, err := f.server.Authenticate(context.Background(), &auditproxyv1.AuthenticateRequest{
		Username: "dormant", Method: auditproxyv1.AuthMethod_AUTH_METHOD_PASSWORD,
		Password: "some-password-12",
	})
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if resp.GetResult() == auditproxyv1.AuthResult_AUTH_RESULT_SUCCESS {
		t.Fatal("a disabled account authenticated")
	}
}

func TestAuthenticatePublicKeyRequiresProvenPossession(t *testing.T) {
	f := newFixture(t)
	user := f.addUser("carol", "unused-password-1")
	if _, err := f.store.AddPublicKey(store.PublicKey{
		UserID: user.ID, Fingerprint: "SHA256:carol", Algorithm: "ssh-ed25519",
		PublicKey: "ssh-ed25519 AAAA carol",
	}); err != nil {
		t.Fatalf("AddPublicKey: %v", err)
	}

	// Without proof of possession the fingerprint is only a claim; accepting it
	// would let anyone log in as the owner of a known public key.
	resp, err := f.server.Authenticate(context.Background(), &auditproxyv1.AuthenticateRequest{
		Username: "carol", Method: auditproxyv1.AuthMethod_AUTH_METHOD_PUBLIC_KEY,
		PublicKeyFingerprint: "SHA256:carol",
	})
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if resp.GetResult() == auditproxyv1.AuthResult_AUTH_RESULT_SUCCESS {
		t.Fatal("an unverified public key was accepted")
	}

	resp, err = f.server.Authenticate(context.Background(), &auditproxyv1.AuthenticateRequest{
		Username: "carol", Method: auditproxyv1.AuthMethod_AUTH_METHOD_PUBLIC_KEY,
		PublicKeyFingerprint: "SHA256:carol", SignatureVerified: true,
	})
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if resp.GetResult() != auditproxyv1.AuthResult_AUTH_RESULT_SUCCESS {
		t.Fatalf("a verified key was refused: %s", resp.GetReason())
	}
}

func TestAuthenticatePublicKeyBoundToItsOwner(t *testing.T) {
	f := newFixture(t)
	carol := f.addUser("carol", "unused-password-1")
	f.addUser("mallory", "unused-password-2")
	if _, err := f.store.AddPublicKey(store.PublicKey{
		UserID: carol.ID, Fingerprint: "SHA256:carol", PublicKey: "ssh-ed25519 AAAA carol",
	}); err != nil {
		t.Fatalf("AddPublicKey: %v", err)
	}

	// Presenting somebody else's key must not authenticate as them or as you.
	resp, err := f.server.Authenticate(context.Background(), &auditproxyv1.AuthenticateRequest{
		Username: "mallory", Method: auditproxyv1.AuthMethod_AUTH_METHOD_PUBLIC_KEY,
		PublicKeyFingerprint: "SHA256:carol", SignatureVerified: true,
	})
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if resp.GetResult() == auditproxyv1.AuthResult_AUTH_RESULT_SUCCESS {
		t.Fatal("a key registered to another user authenticated")
	}
}

func TestAuthenticateExpiredPublicKey(t *testing.T) {
	f := newFixture(t)
	user := f.addUser("carol", "unused-password-1")
	if _, err := f.store.AddPublicKey(store.PublicKey{
		UserID: user.ID, Fingerprint: "SHA256:old", PublicKey: "ssh-ed25519 AAAA old",
		ExpiresAt: time.Now().Add(-time.Hour),
	}); err != nil {
		t.Fatalf("AddPublicKey: %v", err)
	}

	resp, err := f.server.Authenticate(context.Background(), &auditproxyv1.AuthenticateRequest{
		Username: "carol", Method: auditproxyv1.AuthMethod_AUTH_METHOD_PUBLIC_KEY,
		PublicKeyFingerprint: "SHA256:old", SignatureVerified: true,
	})
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if resp.GetResult() == auditproxyv1.AuthResult_AUTH_RESULT_SUCCESS {
		t.Fatal("an expired key authenticated")
	}
}

func TestAuthenticateSecondFactor(t *testing.T) {
	f := newFixture(t)
	f.addUser("mona", "first-factor-pass")

	secret, err := authn.GenerateTOTPSecret()
	if err != nil {
		t.Fatalf("GenerateTOTPSecret: %v", err)
	}
	ref, err := f.store.PutSecretString("totp", secret)
	if err != nil {
		t.Fatalf("PutSecretString: %v", err)
	}
	if _, err := f.store.UpdateUser("mona", func(u *store.User) error {
		u.MFAType = store.MFATOTP
		u.MFASecretRef = ref
		return nil
	}); err != nil {
		t.Fatalf("UpdateUser: %v", err)
	}

	first, err := f.server.Authenticate(context.Background(), &auditproxyv1.AuthenticateRequest{
		Username: "mona", Method: auditproxyv1.AuthMethod_AUTH_METHOD_PASSWORD,
		Password: "first-factor-pass",
	})
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if first.GetResult() != auditproxyv1.AuthResult_AUTH_RESULT_PARTIAL {
		t.Fatalf("a correct password alone should not complete authentication: %v", first.GetResult())
	}
	if first.GetStateToken() == "" || len(first.GetPrompts()) == 0 {
		t.Fatalf("expected a challenge with state, got %+v", first)
	}

	wrong, err := f.server.Authenticate(context.Background(), &auditproxyv1.AuthenticateRequest{
		Username: "mona", Method: auditproxyv1.AuthMethod_AUTH_METHOD_KEYBOARD_INTERACTIVE,
		StateToken: first.GetStateToken(), Responses: []string{"000000"},
	})
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if wrong.GetResult() == auditproxyv1.AuthResult_AUTH_RESULT_SUCCESS {
		t.Fatal("a wrong code completed authentication")
	}

	code, err := authn.TOTPCode(secret, time.Now(), authn.DefaultTOTPConfig())
	if err != nil {
		t.Fatalf("TOTPCode: %v", err)
	}
	final, err := f.server.Authenticate(context.Background(), &auditproxyv1.AuthenticateRequest{
		Username: "mona", Method: auditproxyv1.AuthMethod_AUTH_METHOD_KEYBOARD_INTERACTIVE,
		StateToken: wrong.GetStateToken(), Responses: []string{code},
	})
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if final.GetResult() != auditproxyv1.AuthResult_AUTH_RESULT_SUCCESS {
		t.Fatalf("a valid code did not complete authentication: %s", final.GetReason())
	}
}

func TestSecondFactorRejectsForgedState(t *testing.T) {
	f := newFixture(t)
	f.addUser("mona", "first-factor-pass")

	for _, token := range []string{
		"",
		"garbage",
		"eyJ1IjoibW9uYSIsInMiOiJhd2FpdF9tZmEiLCJlIjo5OTk5OTk5OTk5fQ.bad-signature",
	} {
		resp, err := f.server.Authenticate(context.Background(), &auditproxyv1.AuthenticateRequest{
			Username: "mona", Method: auditproxyv1.AuthMethod_AUTH_METHOD_KEYBOARD_INTERACTIVE,
			StateToken: token, Responses: []string{"123456"},
		})
		if err != nil {
			t.Fatalf("Authenticate: %v", err)
		}
		if resp.GetResult() == auditproxyv1.AuthResult_AUTH_RESULT_SUCCESS {
			t.Fatalf("a forged state token was accepted: %q", token)
		}
	}
}

func TestSecondFactorStateExpires(t *testing.T) {
	f := newFixture(t)
	f.addUser("mona", "first-factor-pass")
	secret, _ := authn.GenerateTOTPSecret()
	ref, _ := f.store.PutSecretString("totp", secret)
	if _, err := f.store.UpdateUser("mona", func(u *store.User) error {
		u.MFAType = store.MFATOTP
		u.MFASecretRef = ref
		return nil
	}); err != nil {
		t.Fatalf("UpdateUser: %v", err)
	}

	base := time.Now()
	f.server.SetClock(func() time.Time { return base })
	first, err := f.server.Authenticate(context.Background(), &auditproxyv1.AuthenticateRequest{
		Username: "mona", Method: auditproxyv1.AuthMethod_AUTH_METHOD_PASSWORD,
		Password: "first-factor-pass",
	})
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}

	f.server.SetClock(func() time.Time { return base.Add(stateTokenTTL + time.Minute) })
	code, _ := authn.TOTPCode(secret, base.Add(stateTokenTTL+time.Minute), authn.DefaultTOTPConfig())
	resp, err := f.server.Authenticate(context.Background(), &auditproxyv1.AuthenticateRequest{
		Username: "mona", Method: auditproxyv1.AuthMethod_AUTH_METHOD_KEYBOARD_INTERACTIVE,
		StateToken: first.GetStateToken(), Responses: []string{code},
	})
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if resp.GetResult() == auditproxyv1.AuthResult_AUTH_RESULT_SUCCESS {
		t.Fatal("an expired half-finished login was resumed")
	}
}

func TestSecondFactorAttemptsAreBounded(t *testing.T) {
	f := newFixture(t)
	f.addUser("mona", "first-factor-pass")
	secret, _ := authn.GenerateTOTPSecret()
	ref, _ := f.store.PutSecretString("totp", secret)
	if _, err := f.store.UpdateUser("mona", func(u *store.User) error {
		u.MFAType = store.MFATOTP
		u.MFASecretRef = ref
		return nil
	}); err != nil {
		t.Fatalf("UpdateUser: %v", err)
	}

	resp, err := f.server.Authenticate(context.Background(), &auditproxyv1.AuthenticateRequest{
		Username: "mona", Method: auditproxyv1.AuthMethod_AUTH_METHOD_PASSWORD,
		Password: "first-factor-pass",
	})
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}

	token := resp.GetStateToken()
	for i := 0; i < maxMFAAttempts+1; i++ {
		resp, err = f.server.Authenticate(context.Background(), &auditproxyv1.AuthenticateRequest{
			Username: "mona", Method: auditproxyv1.AuthMethod_AUTH_METHOD_KEYBOARD_INTERACTIVE,
			StateToken: token, Responses: []string{"000000"},
		})
		if err != nil {
			t.Fatalf("Authenticate: %v", err)
		}
		if next := resp.GetStateToken(); next != "" {
			token = next
		}
	}
	if !strings.Contains(resp.GetReason(), "too many") {
		t.Fatalf("an accepted password should not allow unlimited code guesses; last reason: %q",
			resp.GetReason())
	}
}

func TestAccountLockoutAfterRepeatedFailures(t *testing.T) {
	f := newFixture(t)
	f.addUser("alice", "correct-password-1")
	f.server.config.MaxAuthFailures = 3

	for i := 0; i < 3; i++ {
		if _, err := f.server.Authenticate(context.Background(), &auditproxyv1.AuthenticateRequest{
			Username: "alice", Method: auditproxyv1.AuthMethod_AUTH_METHOD_PASSWORD, Password: "wrong",
		}); err != nil {
			t.Fatalf("Authenticate: %v", err)
		}
	}

	// Even the correct password is refused while the account is locked.
	resp, err := f.server.Authenticate(context.Background(), &auditproxyv1.AuthenticateRequest{
		Username: "alice", Method: auditproxyv1.AuthMethod_AUTH_METHOD_PASSWORD,
		Password: "correct-password-1",
	})
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if resp.GetResult() == auditproxyv1.AuthResult_AUTH_RESULT_SUCCESS {
		t.Fatal("guessing was not rate limited")
	}
	if !strings.Contains(resp.GetReason(), "locked") {
		t.Errorf("the refusal should say the account is locked, got %q", resp.GetReason())
	}
}

func TestSuccessfulLoginClearsFailureCount(t *testing.T) {
	f := newFixture(t)
	f.addUser("alice", "correct-password-1")
	f.server.config.MaxAuthFailures = 3

	for i := 0; i < 2; i++ {
		if _, err := f.server.Authenticate(context.Background(), &auditproxyv1.AuthenticateRequest{
			Username: "alice", Method: auditproxyv1.AuthMethod_AUTH_METHOD_PASSWORD, Password: "wrong",
		}); err != nil {
			t.Fatalf("Authenticate: %v", err)
		}
	}
	if _, err := f.server.Authenticate(context.Background(), &auditproxyv1.AuthenticateRequest{
		Username: "alice", Method: auditproxyv1.AuthMethod_AUTH_METHOD_PASSWORD,
		Password: "correct-password-1",
	}); err != nil {
		t.Fatalf("Authenticate: %v", err)
	}

	// Two more failures must not lock the account, because the counter reset.
	for i := 0; i < 2; i++ {
		if _, err := f.server.Authenticate(context.Background(), &auditproxyv1.AuthenticateRequest{
			Username: "alice", Method: auditproxyv1.AuthMethod_AUTH_METHOD_PASSWORD, Password: "wrong",
		}); err != nil {
			t.Fatalf("Authenticate: %v", err)
		}
	}
	resp, err := f.server.Authenticate(context.Background(), &auditproxyv1.AuthenticateRequest{
		Username: "alice", Method: auditproxyv1.AuthMethod_AUTH_METHOD_PASSWORD,
		Password: "correct-password-1",
	})
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if resp.GetResult() != auditproxyv1.AuthResult_AUTH_RESULT_SUCCESS {
		t.Fatalf("the account should not be locked: %s", resp.GetReason())
	}
}

func TestAuthenticateRefusesBlockedSourceNetwork(t *testing.T) {
	f := newFixture(t)
	f.addUser("alice", "correct-password-1")
	if _, err := f.store.PutIPRule(store.IPRule{CIDR: "203.0.113.0/24", Action: store.IPDeny}); err != nil {
		t.Fatalf("PutIPRule: %v", err)
	}

	resp, err := f.server.Authenticate(context.Background(), &auditproxyv1.AuthenticateRequest{
		Username: "alice", Method: auditproxyv1.AuthMethod_AUTH_METHOD_PASSWORD,
		Password: "correct-password-1",
		Client:   &auditproxyv1.ClientInfo{SourceIp: "203.0.113.7"},
	})
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if resp.GetResult() == auditproxyv1.AuthResult_AUTH_RESULT_SUCCESS {
		t.Fatal("a blocked network authenticated")
	}
}

// --------------------------------------------------------------------------
// Session authorization
// --------------------------------------------------------------------------

func TestAuthorizeSessionFailsClosed(t *testing.T) {
	f := newFixture(t)

	resp, err := f.server.AuthorizeSession(context.Background(), &auditproxyv1.AuthorizeSessionRequest{
		Username: "alice", Target: "web-1", UpstreamLogin: "root",
	})
	if err != nil {
		t.Fatalf("AuthorizeSession: %v", err)
	}
	if resp.GetAllowed() {
		t.Fatal("with no rules configured, access must be refused")
	}
}

func TestAuthorizeSessionReturnsConstraints(t *testing.T) {
	f := newFixture(t)
	f.allowRule(store.AccessRule{
		ID: "r1", Name: "prod shell", Priority: 10,
		Features:      store.FeatureShell | store.FeatureExec | store.FeaturePTY,
		MaxSessionTTL: 2 * time.Hour, IdleTimeout: 10 * time.Minute,
		RecordPolicy: store.RecordFull, CommandPolicyID: "cp-1",
		UpstreamLogins: []string{"deploy"},
	})

	resp, err := f.server.AuthorizeSession(context.Background(), &auditproxyv1.AuthorizeSessionRequest{
		Username: "alice", Target: "web-1", UpstreamLogin: "deploy",
	})
	if err != nil {
		t.Fatalf("AuthorizeSession: %v", err)
	}
	if !resp.GetAllowed() {
		t.Fatalf("expected the rule to allow: %s", resp.GetReason())
	}
	if resp.GetTargetHost() != "10.0.1.10" || resp.GetTargetPort() != 22 {
		t.Errorf("resolved address = %s:%d", resp.GetTargetHost(), resp.GetTargetPort())
	}
	if resp.GetMaxSessionSeconds() != 7200 || resp.GetIdleTimeoutSeconds() != 600 {
		t.Errorf("limits not carried: %+v", resp)
	}
	if resp.GetCommandPolicyId() != "cp-1" {
		t.Errorf("command policy not carried: %q", resp.GetCommandPolicyId())
	}
	names := strings.Join(resp.GetFeatures(), ",")
	if !strings.Contains(names, "shell") || strings.Contains(names, "local_forward") {
		t.Errorf("features = %s", names)
	}
}

func TestAuthorizeSessionRefusesDisabledAndMaintenanceTargets(t *testing.T) {
	f := newFixture(t)
	f.allowRule(store.AccessRule{ID: "r1", Features: store.FeatureShell})

	if _, err := f.store.UpdateTarget("web-1", func(tt *store.Target) error {
		tt.Maintenance = true
		return nil
	}); err != nil {
		t.Fatalf("UpdateTarget: %v", err)
	}
	resp, err := f.server.AuthorizeSession(context.Background(), &auditproxyv1.AuthorizeSessionRequest{
		Username: "alice", Target: "web-1",
	})
	if err != nil {
		t.Fatalf("AuthorizeSession: %v", err)
	}
	if resp.GetAllowed() {
		t.Fatal("a target in maintenance accepted a session")
	}

	if _, err := f.store.UpdateTarget("web-1", func(tt *store.Target) error {
		tt.Maintenance = false
		tt.Enabled = false
		return nil
	}); err != nil {
		t.Fatalf("UpdateTarget: %v", err)
	}
	resp, err = f.server.AuthorizeSession(context.Background(), &auditproxyv1.AuthorizeSessionRequest{
		Username: "alice", Target: "web-1",
	})
	if err != nil {
		t.Fatalf("AuthorizeSession: %v", err)
	}
	if resp.GetAllowed() {
		t.Fatal("a disabled target accepted a session")
	}
}

func TestAuthorizeSessionUnknownTarget(t *testing.T) {
	f := newFixture(t)
	f.allowRule(store.AccessRule{ID: "r1", Features: store.FeatureShell})

	resp, err := f.server.AuthorizeSession(context.Background(), &auditproxyv1.AuthorizeSessionRequest{
		Username: "alice", Target: "not-registered",
	})
	if err != nil {
		t.Fatalf("AuthorizeSession: %v", err)
	}
	if resp.GetAllowed() {
		t.Fatal("an unregistered target was allowed")
	}
}

type staticGrants struct{ user, target string }

func (g staticGrants) HasGrant(username, target string) bool {
	return username == g.user && target == g.target
}

func TestJustInTimeGrantWidensButDoesNotOverrideDenial(t *testing.T) {
	f := newFixture(t)
	f.server.SetGrantChecker(staticGrants{user: "alice", target: "web-1"})

	// With no rules at all, the grant supplies access.
	resp, err := f.server.AuthorizeSession(context.Background(), &auditproxyv1.AuthorizeSessionRequest{
		Username: "alice", Target: "web-1",
	})
	if err != nil {
		t.Fatalf("AuthorizeSession: %v", err)
	}
	if !resp.GetAllowed() {
		t.Fatalf("a just-in-time grant should allow access: %s", resp.GetReason())
	}
	if !strings.Contains(strings.Join(resp.GetFeatures(), ","), "shell") {
		t.Errorf("a grant should carry the interactive basics, got %v", resp.GetFeatures())
	}

	// Somebody without a grant is still refused.
	resp, err = f.server.AuthorizeSession(context.Background(), &auditproxyv1.AuthorizeSessionRequest{
		Username: "bob", Target: "web-1",
	})
	if err != nil {
		t.Fatalf("AuthorizeSession: %v", err)
	}
	if resp.GetAllowed() {
		t.Fatal("a user without a grant was allowed")
	}
}

// --------------------------------------------------------------------------
// Channel authorization
// --------------------------------------------------------------------------

func (f *fixture) openSession(features store.FeatureSet) string {
	f.t.Helper()
	sess, err := f.store.CreateSession(store.Session{
		NodeID: "node-a", Username: "alice", TargetID: f.target.ID,
		Status: store.SessionActive, Features: features,
	})
	if err != nil {
		f.t.Fatalf("CreateSession: %v", err)
	}
	return sess.ID
}

func TestAuthorizeChannelEnforcesFeatureMask(t *testing.T) {
	f := newFixture(t)
	sessionID := f.openSession(store.FeatureShell | store.FeaturePTY | store.FeatureExec)

	cases := []struct {
		name    string
		req     *auditproxyv1.AuthorizeChannelRequest
		allowed bool
	}{
		{"shell is granted", &auditproxyv1.AuthorizeChannelRequest{
			SessionId: sessionID, ChannelType: auditproxyv1.ChannelType_CHANNEL_TYPE_SESSION,
			RequestType: auditproxyv1.ChannelRequestType_CHANNEL_REQUEST_SHELL,
		}, true},
		{"pty is granted", &auditproxyv1.AuthorizeChannelRequest{
			SessionId: sessionID, ChannelType: auditproxyv1.ChannelType_CHANNEL_TYPE_SESSION,
			RequestType: auditproxyv1.ChannelRequestType_CHANNEL_REQUEST_PTY,
		}, true},
		{"local forwarding is not", &auditproxyv1.AuthorizeChannelRequest{
			SessionId: sessionID, ChannelType: auditproxyv1.ChannelType_CHANNEL_TYPE_DIRECT_TCPIP,
			DestHost: "10.0.0.9", DestPort: 5432,
		}, false},
		{"remote forwarding is not", &auditproxyv1.AuthorizeChannelRequest{
			SessionId: sessionID, ChannelType: auditproxyv1.ChannelType_CHANNEL_TYPE_FORWARDED_TCPIP,
		}, false},
		{"agent forwarding is not", &auditproxyv1.AuthorizeChannelRequest{
			SessionId: sessionID, ChannelType: auditproxyv1.ChannelType_CHANNEL_TYPE_AGENT,
		}, false},
		{"x11 is not", &auditproxyv1.AuthorizeChannelRequest{
			SessionId: sessionID, ChannelType: auditproxyv1.ChannelType_CHANNEL_TYPE_X11,
		}, false},
		{"sftp is not", &auditproxyv1.AuthorizeChannelRequest{
			SessionId: sessionID, ChannelType: auditproxyv1.ChannelType_CHANNEL_TYPE_SESSION,
			RequestType: auditproxyv1.ChannelRequestType_CHANNEL_REQUEST_SUBSYSTEM, Payload: "sftp",
		}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp, err := f.server.AuthorizeChannel(context.Background(), tc.req)
			if err != nil {
				t.Fatalf("AuthorizeChannel: %v", err)
			}
			if resp.GetAllowed() != tc.allowed {
				t.Fatalf("allowed = %v, want %v (%s)", resp.GetAllowed(), tc.allowed, resp.GetReason())
			}
			if !tc.allowed && resp.GetRequiredFeature() == "" {
				t.Error("a refusal should name the missing capability")
			}
		})
	}
}

func TestAuthorizeChannelChargesSCPAgainstTransfer(t *testing.T) {
	f := newFixture(t)
	// Exec is granted but file transfer is not, which is exactly the case a
	// mask that only looked at the request type would get wrong: scp is an exec.
	sessionID := f.openSession(store.FeatureExec | store.FeatureShell)

	resp, err := f.server.AuthorizeChannel(context.Background(), &auditproxyv1.AuthorizeChannelRequest{
		SessionId:   sessionID,
		ChannelType: auditproxyv1.ChannelType_CHANNEL_TYPE_SESSION,
		RequestType: auditproxyv1.ChannelRequestType_CHANNEL_REQUEST_EXEC,
		Payload:     "scp -t /tmp/upload",
	})
	if err != nil {
		t.Fatalf("AuthorizeChannel: %v", err)
	}
	if resp.GetAllowed() {
		t.Fatal("scp was allowed through the exec capability, bypassing the transfer policy")
	}

	ordinary, err := f.server.AuthorizeChannel(context.Background(), &auditproxyv1.AuthorizeChannelRequest{
		SessionId:   sessionID,
		ChannelType: auditproxyv1.ChannelType_CHANNEL_TYPE_SESSION,
		RequestType: auditproxyv1.ChannelRequestType_CHANNEL_REQUEST_EXEC,
		Payload:     "uptime",
	})
	if err != nil {
		t.Fatalf("AuthorizeChannel: %v", err)
	}
	if !ordinary.GetAllowed() {
		t.Fatalf("an ordinary exec should be permitted: %s", ordinary.GetReason())
	}
}

func TestAuthorizeChannelRejectsUnknownOrClosedSession(t *testing.T) {
	f := newFixture(t)
	sessionID := f.openSession(store.FeatureAll)
	if err := f.store.CloseSession(sessionID, store.SessionClosed, "", 0, 0); err != nil {
		t.Fatalf("CloseSession: %v", err)
	}

	for _, id := range []string{sessionID, "no-such-session"} {
		resp, err := f.server.AuthorizeChannel(context.Background(), &auditproxyv1.AuthorizeChannelRequest{
			SessionId: id, ChannelType: auditproxyv1.ChannelType_CHANNEL_TYPE_SESSION,
			RequestType: auditproxyv1.ChannelRequestType_CHANNEL_REQUEST_SHELL,
		})
		if err != nil {
			t.Fatalf("AuthorizeChannel: %v", err)
		}
		if resp.GetAllowed() {
			t.Fatalf("session %q should not authorize a channel", id)
		}
	}
}

// --------------------------------------------------------------------------
// Command authorization
// --------------------------------------------------------------------------

// commandStream captures what AuthorizeCommand sends.
type commandStream struct {
	auditproxyv1.AccessDecisionService_AuthorizeCommandServer
	ctx      context.Context
	mu       sync.Mutex
	messages []*auditproxyv1.AuthorizeCommandResponse
}

func newCommandStream(ctx context.Context) *commandStream {
	return &commandStream{ctx: ctx}
}

func (s *commandStream) Send(resp *auditproxyv1.AuthorizeCommandResponse) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.messages = append(s.messages, resp)
	return nil
}
func (s *commandStream) Context() context.Context     { return s.ctx }
func (s *commandStream) SetHeader(metadata.MD) error  { return nil }
func (s *commandStream) SendHeader(metadata.MD) error { return nil }
func (s *commandStream) SetTrailer(metadata.MD)       {}

func (s *commandStream) last() *auditproxyv1.AuthorizeCommandResponse {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.messages) == 0 {
		return nil
	}
	return s.messages[len(s.messages)-1]
}

func (f *fixture) commandPolicy(rules ...store.CommandRule) string {
	f.t.Helper()
	policy, err := f.store.PutCommandPolicy(store.CommandPolicy{Name: "test-policy"})
	if err != nil {
		f.t.Fatalf("PutCommandPolicy: %v", err)
	}
	for i, rule := range rules {
		rule.PolicyID = policy.ID
		rule.Enabled = true
		if rule.Priority == 0 {
			rule.Priority = (i + 1) * 10
		}
		if _, err := f.store.PutCommandRule(rule); err != nil {
			f.t.Fatalf("PutCommandRule: %v", err)
		}
	}
	return policy.ID
}

func TestAuthorizeCommandDecisions(t *testing.T) {
	f := newFixture(t)
	policyID := f.commandPolicy(
		store.CommandRule{ID: "deny-rm", Pattern: `rm\s+-rf\s+/`, Action: store.CommandDeny,
			Message: "refusing a recursive delete of the root filesystem", Severity: "critical"},
		store.CommandRule{ID: "rewrite-shutdown", Pattern: `^shutdown`, Action: store.CommandRewrite,
			Rewrite: "echo 'shutdown is not permitted'"},
		store.CommandRule{ID: "audit-sudo", Pattern: `^sudo\s`, Action: store.CommandAudit},
	)

	cases := []struct {
		command string
		want    auditproxyv1.CommandDecision
	}{
		{"rm -rf /", auditproxyv1.CommandDecision_COMMAND_DECISION_DENY},
		{"shutdown -h now", auditproxyv1.CommandDecision_COMMAND_DECISION_REWRITE},
		{"sudo systemctl restart nginx", auditproxyv1.CommandDecision_COMMAND_DECISION_AUDIT},
		{"ls -la", auditproxyv1.CommandDecision_COMMAND_DECISION_ALLOW},
	}
	for _, tc := range cases {
		t.Run(tc.command, func(t *testing.T) {
			stream := newCommandStream(context.Background())
			err := f.server.AuthorizeCommand(&auditproxyv1.AuthorizeCommandRequest{
				SessionId: "s1", Username: "alice", Command: tc.command, CommandPolicyId: policyID,
			}, stream)
			if err != nil {
				t.Fatalf("AuthorizeCommand: %v", err)
			}
			got := stream.last()
			if got.GetDecision() != tc.want {
				t.Fatalf("decision = %v, want %v (%s)", got.GetDecision(), tc.want, got.GetReason())
			}
			if tc.want == auditproxyv1.CommandDecision_COMMAND_DECISION_REWRITE &&
				got.GetRewrittenCommand() == "" {
				t.Error("a rewrite decision must supply the replacement")
			}
		})
	}
}

func TestAuthorizeCommandSkipsUncompilablePatterns(t *testing.T) {
	f := newFixture(t)
	policyID := f.commandPolicy(
		store.CommandRule{ID: "broken", Pattern: `([unclosed`, Action: store.CommandDeny, Priority: 10},
		store.CommandRule{ID: "works", Pattern: `^rm\s`, Action: store.CommandDeny, Priority: 20},
	)

	// A rule that cannot compile must neither match everything nor stop later
	// rules from being considered.
	stream := newCommandStream(context.Background())
	if err := f.server.AuthorizeCommand(&auditproxyv1.AuthorizeCommandRequest{
		SessionId: "s1", Command: "ls", CommandPolicyId: policyID,
	}, stream); err != nil {
		t.Fatalf("AuthorizeCommand: %v", err)
	}
	if stream.last().GetDecision() != auditproxyv1.CommandDecision_COMMAND_DECISION_ALLOW {
		t.Fatalf("a broken pattern matched an unrelated command: %+v", stream.last())
	}

	stream = newCommandStream(context.Background())
	if err := f.server.AuthorizeCommand(&auditproxyv1.AuthorizeCommandRequest{
		SessionId: "s1", Command: "rm file", CommandPolicyId: policyID,
	}, stream); err != nil {
		t.Fatalf("AuthorizeCommand: %v", err)
	}
	if stream.last().GetDecision() != auditproxyv1.CommandDecision_COMMAND_DECISION_DENY {
		t.Fatalf("a broken earlier rule prevented a later one from applying: %+v", stream.last())
	}
}

func TestAuthorizeCommandWithoutPolicyAllows(t *testing.T) {
	f := newFixture(t)
	stream := newCommandStream(context.Background())
	if err := f.server.AuthorizeCommand(&auditproxyv1.AuthorizeCommandRequest{
		SessionId: "s1", Command: "rm -rf /",
	}, stream); err != nil {
		t.Fatalf("AuthorizeCommand: %v", err)
	}
	if stream.last().GetDecision() != auditproxyv1.CommandDecision_COMMAND_DECISION_ALLOW {
		t.Fatal("with no policy attached the command should pass through unscreened")
	}
}

type scriptedApprover struct {
	approve   bool
	failAwait error
	requested chan string
}

func (a *scriptedApprover) Request(_ context.Context, _, _, _, _, _ string) (string, error) {
	id := "approval-1"
	if a.requested != nil {
		a.requested <- id
	}
	return id, nil
}

func (a *scriptedApprover) Await(_ context.Context, _ string) (bool, string, error) {
	if a.failAwait != nil {
		return false, "", a.failAwait
	}
	return a.approve, "reviewer", nil
}

func TestAuthorizeCommandApprovalFlow(t *testing.T) {
	f := newFixture(t)
	policyID := f.commandPolicy(store.CommandRule{
		ID: "approve-restart", Pattern: `^systemctl restart`, Action: store.CommandApprove,
		Message: "restarting a service needs a second pair of eyes",
	})

	t.Run("approved", func(t *testing.T) {
		f.server.SetCommandApprover(&scriptedApprover{approve: true})
		stream := newCommandStream(context.Background())
		if err := f.server.AuthorizeCommand(&auditproxyv1.AuthorizeCommandRequest{
			SessionId: "s1", Username: "alice", Command: "systemctl restart nginx",
			CommandPolicyId: policyID,
		}, stream); err != nil {
			t.Fatalf("AuthorizeCommand: %v", err)
		}
		if len(stream.messages) != 2 {
			t.Fatalf("expected a pending message then an outcome, got %d", len(stream.messages))
		}
		if stream.messages[0].GetDecision() != auditproxyv1.CommandDecision_COMMAND_DECISION_PENDING_APPROVAL {
			t.Errorf("first message = %v, want PENDING_APPROVAL", stream.messages[0].GetDecision())
		}
		if stream.messages[1].GetDecision() != auditproxyv1.CommandDecision_COMMAND_DECISION_ALLOW {
			t.Errorf("second message = %v, want ALLOW", stream.messages[1].GetDecision())
		}
	})

	t.Run("denied", func(t *testing.T) {
		f.server.SetCommandApprover(&scriptedApprover{approve: false})
		stream := newCommandStream(context.Background())
		if err := f.server.AuthorizeCommand(&auditproxyv1.AuthorizeCommandRequest{
			SessionId: "s1", Command: "systemctl restart nginx", CommandPolicyId: policyID,
		}, stream); err != nil {
			t.Fatalf("AuthorizeCommand: %v", err)
		}
		if stream.last().GetDecision() != auditproxyv1.CommandDecision_COMMAND_DECISION_DENY {
			t.Fatalf("last = %v, want DENY", stream.last().GetDecision())
		}
	})

	t.Run("approval times out", func(t *testing.T) {
		f.server.SetCommandApprover(&scriptedApprover{failAwait: errors.New("timed out")})
		stream := newCommandStream(context.Background())
		if err := f.server.AuthorizeCommand(&auditproxyv1.AuthorizeCommandRequest{
			SessionId: "s1", Command: "systemctl restart nginx", CommandPolicyId: policyID,
		}, stream); err != nil {
			t.Fatalf("AuthorizeCommand: %v", err)
		}
		if stream.last().GetDecision() != auditproxyv1.CommandDecision_COMMAND_DECISION_DENY {
			t.Fatal("an approval that never arrives must not become an allow")
		}
	})
}

func TestApprovalRuleWithoutWorkflowDenies(t *testing.T) {
	f := newFixture(t)
	policyID := f.commandPolicy(store.CommandRule{
		ID: "approve-restart", Pattern: `^systemctl restart`, Action: store.CommandApprove,
	})
	f.server.SetCommandApprover(nil)

	stream := newCommandStream(context.Background())
	if err := f.server.AuthorizeCommand(&auditproxyv1.AuthorizeCommandRequest{
		SessionId: "s1", Command: "systemctl restart nginx", CommandPolicyId: policyID,
	}, stream); err != nil {
		t.Fatalf("AuthorizeCommand: %v", err)
	}
	if stream.last().GetDecision() != auditproxyv1.CommandDecision_COMMAND_DECISION_DENY {
		t.Fatal("a rule requiring approval with nowhere to send it must refuse, not allow")
	}
}
