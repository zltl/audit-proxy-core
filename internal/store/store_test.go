package store

import (
	"errors"
	"path/filepath"
	"testing"
	"time"
)

func newTestStore(t *testing.T) *Store {
	t.Helper()
	dsn := filepath.Join(t.TempDir(), "store.db")
	s, err := Open("sqlite", dsn)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func TestOpenAppliesMigrationsAndSeedsRoles(t *testing.T) {
	s := newTestStore(t)

	version, err := s.SchemaVersion()
	if err != nil {
		t.Fatalf("SchemaVersion: %v", err)
	}
	if version != SchemaVersion {
		t.Fatalf("schema version = %d, want %d", version, SchemaVersion)
	}

	roles, err := s.ListRoles()
	if err != nil {
		t.Fatalf("ListRoles: %v", err)
	}
	if len(roles) != len(BuiltinRoles) {
		t.Fatalf("expected %d built-in roles, got %d", len(BuiltinRoles), len(roles))
	}
	for _, r := range roles {
		if !r.Builtin {
			t.Errorf("seeded role %q should be marked built-in", r.Name)
		}
	}
}

func TestMigrationsAreIdempotent(t *testing.T) {
	dsn := filepath.Join(t.TempDir(), "store.db")

	first, err := Open("sqlite", dsn)
	if err != nil {
		t.Fatalf("first Open: %v", err)
	}
	if _, err := first.CreateUser(User{Username: "keep-me"}); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	if err := first.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	second, err := Open("sqlite", dsn)
	if err != nil {
		t.Fatalf("reopening a migrated database failed: %v", err)
	}
	defer func() { _ = second.Close() }()

	if _, err := second.GetUser("keep-me"); err != nil {
		t.Fatalf("data did not survive reopening: %v", err)
	}
}

func TestUserLifecycle(t *testing.T) {
	s := newTestStore(t)

	created, err := s.CreateUser(User{
		Username:     "alice",
		DisplayName:  "Alice",
		Email:        "alice@example.com",
		PasswordHash: "$argon2id$stub",
	})
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	if created.ID == "" {
		t.Fatal("CreateUser did not assign an id")
	}
	if created.Status != UserActive || created.Source != SourceLocal || created.MFAType != MFANone {
		t.Fatalf("defaults not applied: %+v", created)
	}

	if _, err := s.CreateUser(User{Username: "alice"}); !errors.Is(err, ErrConflict) {
		t.Fatalf("duplicate username should conflict, got %v", err)
	}

	fetched, err := s.GetUser("alice")
	if err != nil {
		t.Fatalf("GetUser: %v", err)
	}
	if fetched.Email != "alice@example.com" {
		t.Fatalf("round-trip lost fields: %+v", fetched)
	}

	byID, err := s.GetUserByID(created.ID)
	if err != nil || byID.Username != "alice" {
		t.Fatalf("GetUserByID = (%+v, %v)", byID, err)
	}

	updated, err := s.UpdateUser("alice", func(u *User) error {
		u.Status = UserDisabled
		u.MFAType = MFATOTP
		u.MFASecretRef = "sec-1"
		u.MFAPending = true
		return nil
	})
	if err != nil {
		t.Fatalf("UpdateUser: %v", err)
	}
	if updated.Enabled() {
		t.Fatal("disabled user still reports as enabled")
	}
	if updated.MFAType != MFATOTP || updated.MFASecretRef != "sec-1" || !updated.MFAPending {
		t.Fatalf("MFA fields not persisted: %+v", updated)
	}

	if _, err := s.GetUser("nobody"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing user should be ErrNotFound, got %v", err)
	}

	if err := s.DeleteUser("alice"); err != nil {
		t.Fatalf("DeleteUser: %v", err)
	}
	if _, err := s.GetUser("alice"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("user still present after delete: %v", err)
	}
}

func TestUpdateUserPropagatesMutatorError(t *testing.T) {
	s := newTestStore(t)
	if _, err := s.CreateUser(User{Username: "bob"}); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	sentinel := errors.New("nope")
	if _, err := s.UpdateUser("bob", func(u *User) error {
		u.Email = "should-not-persist@example.com"
		return sentinel
	}); !errors.Is(err, sentinel) {
		t.Fatalf("UpdateUser should return the mutator error, got %v", err)
	}

	// The aborted mutation must not have been written.
	after, err := s.GetUser("bob")
	if err != nil {
		t.Fatalf("GetUser: %v", err)
	}
	if after.Email != "" {
		t.Fatalf("a failed mutation was persisted: %+v", after)
	}
}

func TestPublicKeyLookupResolvesOwner(t *testing.T) {
	s := newTestStore(t)
	user, err := s.CreateUser(User{Username: "carol"})
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	if _, err := s.AddPublicKey(PublicKey{
		UserID:      user.ID,
		Fingerprint: "SHA256:abc",
		Algorithm:   "ssh-ed25519",
		PublicKey:   "ssh-ed25519 AAAA carol@laptop",
		Comment:     "laptop",
	}); err != nil {
		t.Fatalf("AddPublicKey: %v", err)
	}

	// A fingerprint is globally unique; reusing one must be refused rather than
	// silently reassigning the key to a different account.
	other, err := s.CreateUser(User{Username: "mallory"})
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	if _, err := s.AddPublicKey(PublicKey{
		UserID:      other.ID,
		Fingerprint: "SHA256:abc",
		PublicKey:   "ssh-ed25519 AAAA mallory@laptop",
	}); !errors.Is(err, ErrConflict) {
		t.Fatalf("duplicate fingerprint should conflict, got %v", err)
	}

	key, owner, err := s.FindPublicKey("SHA256:abc")
	if err != nil {
		t.Fatalf("FindPublicKey: %v", err)
	}
	if owner.Username != "carol" {
		t.Fatalf("key resolved to the wrong owner: %q", owner.Username)
	}
	if key.Comment != "laptop" {
		t.Fatalf("key fields lost: %+v", key)
	}

	if _, _, err := s.FindPublicKey("SHA256:missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown fingerprint should be ErrNotFound, got %v", err)
	}

	// Deleting the user must take their keys with them, or a later account
	// reusing the fingerprint would inherit the grant.
	if err := s.DeleteUser("carol"); err != nil {
		t.Fatalf("DeleteUser: %v", err)
	}
	if _, _, err := s.FindPublicKey("SHA256:abc"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("public key outlived its owner: %v", err)
	}
}

func TestPublicKeyExpiry(t *testing.T) {
	now := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)
	active := PublicKey{ExpiresAt: now.Add(time.Hour)}
	expired := PublicKey{ExpiresAt: now.Add(-time.Hour)}
	permanent := PublicKey{}

	if active.Expired(now) {
		t.Error("a key valid for another hour reported as expired")
	}
	if !expired.Expired(now) {
		t.Error("a key that lapsed an hour ago reported as valid")
	}
	if permanent.Expired(now) {
		t.Error("a key with no expiry reported as expired")
	}
}

func TestTargetLifecycleAndSelectors(t *testing.T) {
	s := newTestStore(t)

	web, err := s.CreateTarget(Target{
		Name:  "web-1",
		Host:  "10.0.1.10",
		Group: "web",
		Tags:  map[string]string{"env": "prod", "team": "platform"},
	})
	if err != nil {
		t.Fatalf("CreateTarget: %v", err)
	}
	if web.Port != 22 || web.Weight != 1 {
		t.Fatalf("defaults not applied: %+v", web)
	}
	if _, err := s.CreateTarget(Target{Name: "web-1", Host: "other"}); !errors.Is(err, ErrConflict) {
		t.Fatalf("duplicate target name should conflict, got %v", err)
	}

	if _, err := s.CreateTarget(Target{
		Name: "db-1", Host: "10.0.2.10", Port: 2222, Group: "db",
		Tags: map[string]string{"env": "staging"},
	}); err != nil {
		t.Fatalf("CreateTarget db: %v", err)
	}

	cases := []struct {
		selector string
		want     []string
	}{
		{"*", []string{"db-1", "web-1"}},
		{"web-1", []string{"web-1"}},
		{"web-*", []string{"web-1"}},
		{"group:db", []string{"db-1"}},
		{"tag:env=prod", []string{"web-1"}},
		{"tag:env", []string{"db-1", "web-1"}},
		{"host:10.0.2.*", []string{"db-1"}},
		{"10.0.1.10", []string{"web-1"}},
		{"nothing-matches", nil},
	}
	for _, tc := range cases {
		matched, err := s.MatchTargets(tc.selector)
		if err != nil {
			t.Fatalf("MatchTargets(%q): %v", tc.selector, err)
		}
		got := make([]string, 0, len(matched))
		for _, m := range matched {
			got = append(got, m.Name)
		}
		if len(got) != len(tc.want) {
			t.Errorf("MatchTargets(%q) = %v, want %v", tc.selector, got, tc.want)
			continue
		}
		for i := range got {
			if got[i] != tc.want[i] {
				t.Errorf("MatchTargets(%q) = %v, want %v", tc.selector, got, tc.want)
				break
			}
		}
	}

	found, err := s.FindTargetByAddress("10.0.2.10", 2222)
	if err != nil || found.Name != "db-1" {
		t.Fatalf("FindTargetByAddress = (%+v, %v)", found, err)
	}
	if _, err := s.FindTargetByAddress("10.0.2.10", 22); !errors.Is(err, ErrNotFound) {
		t.Fatalf("port must be part of the match, got %v", err)
	}

	updated, err := s.UpdateTarget("web-1", func(tt *Target) error {
		tt.Maintenance = true
		tt.Weight = 5
		return nil
	})
	if err != nil {
		t.Fatalf("UpdateTarget: %v", err)
	}
	if !updated.Maintenance || updated.Weight != 5 {
		t.Fatalf("update not persisted: %+v", updated)
	}

	if err := s.DeleteTarget("web-1"); err != nil {
		t.Fatalf("DeleteTarget: %v", err)
	}
	if _, err := s.GetTarget("web-1"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("target still present: %v", err)
	}
}

func TestHostKeyTrustStore(t *testing.T) {
	s := newTestStore(t)
	target, err := s.CreateTarget(Target{Name: "app-1", Host: "10.0.3.1"})
	if err != nil {
		t.Fatalf("CreateTarget: %v", err)
	}

	if _, err := s.PutHostKey(HostKey{
		TargetID:    target.ID,
		Algorithm:   "ssh-ed25519",
		PublicKey:   "AAAAC3Nz...",
		Fingerprint: "SHA256:host1",
		Source:      HostKeyTOFU,
		Status:      HostKeyPending,
	}); err != nil {
		t.Fatalf("PutHostKey: %v", err)
	}

	pending, err := s.ListPendingHostKeys()
	if err != nil {
		t.Fatalf("ListPendingHostKeys: %v", err)
	}
	if len(pending) != 1 || pending[0].Fingerprint != "SHA256:host1" {
		t.Fatalf("expected one pending key, got %+v", pending)
	}
	if !pending[0].TrustedAt.IsZero() {
		t.Fatal("a pending key must not carry a trusted timestamp")
	}

	if err := s.SetHostKeyStatus(target.ID, "SHA256:host1", HostKeyTrusted); err != nil {
		t.Fatalf("SetHostKeyStatus: %v", err)
	}
	keys, err := s.ListHostKeys(target.ID)
	if err != nil {
		t.Fatalf("ListHostKeys: %v", err)
	}
	if len(keys) != 1 || keys[0].Status != HostKeyTrusted {
		t.Fatalf("key was not promoted: %+v", keys)
	}
	if keys[0].TrustedAt.IsZero() {
		t.Fatal("promotion should stamp trusted_at")
	}

	// Re-recording the same key must update rather than duplicate it.
	if _, err := s.PutHostKey(HostKey{
		TargetID:    target.ID,
		Fingerprint: "SHA256:host1",
		Algorithm:   "ssh-ed25519",
		PublicKey:   "AAAAC3Nz...",
		Status:      HostKeyRevoked,
	}); err != nil {
		t.Fatalf("PutHostKey update: %v", err)
	}
	keys, err = s.ListHostKeys(target.ID)
	if err != nil {
		t.Fatalf("ListHostKeys: %v", err)
	}
	if len(keys) != 1 {
		t.Fatalf("expected the key to be updated in place, got %d rows", len(keys))
	}
	if keys[0].Status != HostKeyRevoked {
		t.Fatalf("status not updated: %+v", keys[0])
	}

	// Deleting the target must not leave orphaned trust entries behind.
	if err := s.DeleteTarget("app-1"); err != nil {
		t.Fatalf("DeleteTarget: %v", err)
	}
	keys, err = s.ListHostKeys(target.ID)
	if err != nil {
		t.Fatalf("ListHostKeys: %v", err)
	}
	if len(keys) != 0 {
		t.Fatalf("host keys outlived their target: %+v", keys)
	}
}

func TestCredentialsResolveDirectBeforeSelector(t *testing.T) {
	s := newTestStore(t)
	target, err := s.CreateTarget(Target{Name: "app-2", Host: "10.0.4.1", Group: "app"})
	if err != nil {
		t.Fatalf("CreateTarget: %v", err)
	}

	if _, err := s.PutCredential(Credential{
		TargetSelector: "group:app",
		Login:          "deploy",
		Kind:           CredentialCACert,
	}); err != nil {
		t.Fatalf("PutCredential selector: %v", err)
	}
	if _, err := s.PutCredential(Credential{
		TargetID:  target.ID,
		Login:     "root",
		Kind:      CredentialPrivateKey,
		SecretRef: "sec-root",
	}); err != nil {
		t.Fatalf("PutCredential direct: %v", err)
	}

	creds, err := s.CredentialsForTarget(target)
	if err != nil {
		t.Fatalf("CredentialsForTarget: %v", err)
	}
	if len(creds) != 2 {
		t.Fatalf("expected both credentials to apply, got %d", len(creds))
	}
	if creds[0].Login != "root" {
		t.Fatalf("a target-specific credential should come first, got %q", creds[0].Login)
	}

	if _, err := s.PutCredential(Credential{Login: "x", Kind: CredentialPassword}); err == nil {
		t.Fatal("a credential with neither target nor selector should be rejected")
	}
}

func TestCredentialRotationWindow(t *testing.T) {
	now := time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC)
	never := Credential{}
	if never.NeedsRotation(now) {
		t.Error("a credential with no rotation interval should never be due")
	}
	fresh := Credential{RotateAfter: 24 * time.Hour, LastRotatedAt: now.Add(-time.Hour)}
	if fresh.NeedsRotation(now) {
		t.Error("a credential rotated an hour ago is not due after 24h")
	}
	stale := Credential{RotateAfter: 24 * time.Hour, LastRotatedAt: now.Add(-48 * time.Hour)}
	if !stale.NeedsRotation(now) {
		t.Error("a credential rotated 48h ago is due after 24h")
	}
	unrotated := Credential{RotateAfter: 24 * time.Hour}
	if !unrotated.NeedsRotation(now) {
		t.Error("a credential that was never rotated is due immediately")
	}
}

func TestRoleBindings(t *testing.T) {
	s := newTestStore(t)

	if _, err := s.BindRole(RoleBinding{Subject: "dave", Role: "operator"}); err != nil {
		t.Fatalf("BindRole: %v", err)
	}
	// Re-binding is idempotent rather than an error, so a converging config
	// apply does not fail on the second run.
	if _, err := s.BindRole(RoleBinding{Subject: "dave", Role: "operator"}); err != nil {
		t.Fatalf("re-binding should be idempotent: %v", err)
	}
	if _, err := s.BindRole(RoleBinding{Subject: "dave", Role: "viewer"}); err != nil {
		t.Fatalf("BindRole viewer: %v", err)
	}

	roles, err := s.RolesForUser("dave")
	if err != nil {
		t.Fatalf("RolesForUser: %v", err)
	}
	if len(roles) != 2 || roles[0] != "operator" || roles[1] != "viewer" {
		t.Fatalf("RolesForUser = %v", roles)
	}

	if err := s.UnbindRole(SubjectUser, "dave", "viewer"); err != nil {
		t.Fatalf("UnbindRole: %v", err)
	}
	roles, _ = s.RolesForUser("dave")
	if len(roles) != 1 || roles[0] != "operator" {
		t.Fatalf("after unbind RolesForUser = %v", roles)
	}

	if err := s.DeleteRole("admin"); err == nil {
		t.Fatal("built-in roles must not be deletable")
	}
}
