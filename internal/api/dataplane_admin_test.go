package api

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/ssh-proxy-core/ssh-proxy-core/internal/authn"
	"github.com/ssh-proxy-core/ssh-proxy-core/internal/middleware"
	"github.com/ssh-proxy-core/ssh-proxy-core/internal/secrets"
	"github.com/ssh-proxy-core/ssh-proxy-core/internal/store"
)

// setupDPAdmin builds an API with a data-plane store attached.
func setupDPAdmin(t *testing.T) (*API, *http.ServeMux, *store.Store) {
	t.Helper()
	api, mux, _ := setupTestAPI(t)

	st, err := store.Open("sqlite", filepath.Join(t.TempDir(), "dp.db"))
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

	api.SetDataPlaneStore(st)
	api.RegisterDataPlaneRoutes(mux)
	return api, mux, st
}

func TestDPUserLifecycleThroughTheAPI(t *testing.T) {
	_, mux, st := setupDPAdmin(t)

	rr := doRequest(mux, http.MethodPost, "/api/v2/dp/users", map[string]interface{}{
		"username": "alice", "display_name": "Alice", "password": "alice-password-1",
		"roles": []string{"operator"},
	})
	if rr.Code != http.StatusCreated {
		t.Fatalf("create = %d: %s", rr.Code, rr.Body.String())
	}
	created := parseResponse(t, rr).Data.(map[string]interface{})
	if created["username"] != "alice" {
		t.Fatalf("created = %+v", created)
	}

	// The response must never carry credential material, however convenient it
	// would be: an administration API that can read it is a vault with a door.
	body := rr.Body.String()
	for _, forbidden := range []string{"password_hash", "pass_hash", "alice-password-1", "$argon2id$"} {
		if strings.Contains(body, forbidden) {
			t.Fatalf("the response leaked %q: %s", forbidden, body)
		}
	}

	// The password must nonetheless work.
	stored, err := st.GetUser("alice")
	if err != nil {
		t.Fatalf("GetUser: %v", err)
	}
	if !authn.VerifyPassword("alice-password-1", stored.PasswordHash) {
		t.Fatal("the stored password does not verify")
	}

	roles, err := st.RolesForUser("alice")
	if err != nil || len(roles) != 1 || roles[0] != "operator" {
		t.Fatalf("roles = %v (%v)", roles, err)
	}

	rr = doRequest(mux, http.MethodGet, "/api/v2/dp/users/alice", nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("get = %d: %s", rr.Code, rr.Body.String())
	}

	rr = doRequest(mux, http.MethodPatch, "/api/v2/dp/users/alice", map[string]interface{}{
		"email": "alice@example.com",
	})
	if rr.Code != http.StatusOK {
		t.Fatalf("patch = %d: %s", rr.Code, rr.Body.String())
	}
	stored, _ = st.GetUser("alice")
	if stored.Email != "alice@example.com" {
		t.Fatalf("email = %q", stored.Email)
	}

	rr = doRequest(mux, http.MethodDelete, "/api/v2/dp/users/alice", nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("delete = %d: %s", rr.Code, rr.Body.String())
	}
	if _, err := st.GetUser("alice"); err == nil {
		t.Fatal("the user still exists after deletion")
	}
}

func TestDPDisablingAnAccountRevokesItsSessions(t *testing.T) {
	_, mux, st := setupDPAdmin(t)

	if _, err := st.CreateUser(store.User{Username: "mallory"}); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	session, err := st.CreateSession(store.Session{Username: "mallory", NodeID: "node-a"})
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}

	rr := doRequest(mux, http.MethodPatch, "/api/v2/dp/users/mallory", map[string]interface{}{
		"status": "disabled",
	})
	if rr.Code != http.StatusOK {
		t.Fatalf("patch = %d: %s", rr.Code, rr.Body.String())
	}

	// Disabling an account has to reach the sessions already open, or the
	// person keeps working until they happen to reconnect.
	updated, err := st.GetSession(session.ID)
	if err != nil {
		t.Fatalf("GetSession: %v", err)
	}
	if !updated.RevokeRequested {
		t.Fatal("disabling the account left its live session running")
	}
}

func TestDPRejectsInvalidUserInput(t *testing.T) {
	_, mux, _ := setupDPAdmin(t)

	cases := []struct {
		name string
		body map[string]interface{}
	}{
		{"no username", map[string]interface{}{"password": "long-enough-password"}},
		{"weak password", map[string]interface{}{"username": "bob", "password": "short"}},
	}
	for _, tc := range cases {
		rr := doRequest(mux, http.MethodPost, "/api/v2/dp/users", tc.body)
		if rr.Code != http.StatusBadRequest {
			t.Errorf("%s: status = %d, want 400 (%s)", tc.name, rr.Code, rr.Body.String())
		}
	}

	doRequest(mux, http.MethodPost, "/api/v2/dp/users", map[string]interface{}{
		"username": "bob", "password": "bob-password-123",
	})
	rr := doRequest(mux, http.MethodPatch, "/api/v2/dp/users/bob", map[string]interface{}{
		"status": "banished",
	})
	if rr.Code != http.StatusBadRequest {
		t.Errorf("an unknown status should be rejected, got %d", rr.Code)
	}
}

func TestDPPublicKeyManagement(t *testing.T) {
	_, mux, st := setupDPAdmin(t)
	doRequest(mux, http.MethodPost, "/api/v2/dp/users", map[string]interface{}{
		"username": "carol", "password": "carol-password-1",
	})

	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	signer, _ := ssh.NewSignerFromKey(priv)
	authorized := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(signer.PublicKey())))

	rr := doRequest(mux, http.MethodPost, "/api/v2/dp/users/carol/keys", map[string]interface{}{
		"public_key": authorized + " carol@laptop",
		"expires_at": time.Now().Add(24 * time.Hour).UTC().Format(time.RFC3339),
	})
	if rr.Code != http.StatusCreated {
		t.Fatalf("add key = %d: %s", rr.Code, rr.Body.String())
	}

	fingerprint := ssh.FingerprintSHA256(signer.PublicKey())
	_, owner, err := st.FindPublicKey(fingerprint)
	if err != nil || owner.Username != "carol" {
		t.Fatalf("FindPublicKey = (%+v, %v)", owner, err)
	}

	rr = doRequest(mux, http.MethodPost, "/api/v2/dp/users/carol/keys", map[string]interface{}{
		"public_key": "this is not a key",
	})
	if rr.Code != http.StatusBadRequest {
		t.Errorf("an unparseable key should be rejected, got %d", rr.Code)
	}

	rr = doRequest(mux, http.MethodDelete, "/api/v2/dp/users/carol/keys/"+fingerprint, nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("delete key = %d: %s", rr.Code, rr.Body.String())
	}
	if _, _, err := st.FindPublicKey(fingerprint); err == nil {
		t.Fatal("the key still resolves after deletion")
	}
}

func TestDPTargetAndHostKeyManagement(t *testing.T) {
	_, mux, st := setupDPAdmin(t)

	rr := doRequest(mux, http.MethodPost, "/api/v2/dp/targets", map[string]interface{}{
		"name": "web-1", "host": "10.0.1.10", "port": 22,
		"tags": map[string]string{"env": "prod"},
	})
	if rr.Code != http.StatusCreated {
		t.Fatalf("create target = %d: %s", rr.Code, rr.Body.String())
	}

	target, err := st.GetTarget("web-1")
	if err != nil {
		t.Fatalf("GetTarget: %v", err)
	}

	// A key learned on first contact appears in the pending queue, which is how
	// an operator finds work to do without checking every target.
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	signer, _ := ssh.NewSignerFromKey(priv)
	fingerprint := ssh.FingerprintSHA256(signer.PublicKey())
	if _, err := st.PutHostKey(store.HostKey{
		TargetID:    target.ID,
		Algorithm:   signer.PublicKey().Type(),
		PublicKey:   base64.StdEncoding.EncodeToString(signer.PublicKey().Marshal()),
		Fingerprint: fingerprint,
		Status:      store.HostKeyPending,
		Source:      store.HostKeyTOFU,
	}); err != nil {
		t.Fatalf("PutHostKey: %v", err)
	}

	rr = doRequest(mux, http.MethodGet, "/api/v2/dp/host-keys/pending", nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("pending = %d: %s", rr.Code, rr.Body.String())
	}
	if parseResponse(t, rr).Total != 1 {
		t.Fatalf("expected one pending key: %s", rr.Body.String())
	}

	rr = doRequest(mux, http.MethodPut,
		"/api/v2/dp/targets/web-1/host-keys/"+fingerprint,
		map[string]interface{}{"status": "trusted"})
	if rr.Code != http.StatusOK {
		t.Fatalf("trust = %d: %s", rr.Code, rr.Body.String())
	}
	keys, _ := st.ListHostKeys(target.ID)
	if len(keys) != 1 || keys[0].Status != store.HostKeyTrusted {
		t.Fatalf("host key was not promoted: %+v", keys)
	}

	rr = doRequest(mux, http.MethodPut,
		"/api/v2/dp/targets/web-1/host-keys/"+fingerprint,
		map[string]interface{}{"status": "nonsense"})
	if rr.Code != http.StatusBadRequest {
		t.Errorf("an unknown status should be rejected, got %d", rr.Code)
	}

	rr = doRequest(mux, http.MethodPatch, "/api/v2/dp/targets/web-1",
		map[string]interface{}{"maintenance": true})
	if rr.Code != http.StatusOK {
		t.Fatalf("patch target = %d: %s", rr.Code, rr.Body.String())
	}
	target, _ = st.GetTarget("web-1")
	if !target.Maintenance {
		t.Fatal("maintenance flag was not applied")
	}
}

func TestDPCredentialSecretIsWriteOnly(t *testing.T) {
	_, mux, st := setupDPAdmin(t)
	doRequest(mux, http.MethodPost, "/api/v2/dp/targets", map[string]interface{}{
		"name": "web-1", "host": "10.0.1.10",
	})

	rr := doRequest(mux, http.MethodPost, "/api/v2/dp/credentials", map[string]interface{}{
		"target_name": "web-1", "login": "deploy", "kind": "password",
		"secret": "the-upstream-password", "rotate_after": "720h",
	})
	if rr.Code != http.StatusCreated {
		t.Fatalf("create credential = %d: %s", rr.Code, rr.Body.String())
	}
	if strings.Contains(rr.Body.String(), "the-upstream-password") {
		t.Fatalf("the response echoed the secret: %s", rr.Body.String())
	}

	rr = doRequest(mux, http.MethodGet, "/api/v2/dp/credentials", nil)
	if strings.Contains(rr.Body.String(), "the-upstream-password") {
		t.Fatalf("listing credentials disclosed the secret: %s", rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), `"has_secret":true`) {
		t.Errorf("the listing should say a secret is present without revealing it: %s", rr.Body.String())
	}

	// The material must still be usable by the decision point.
	credentials, err := st.ListCredentials()
	if err != nil || len(credentials) != 1 {
		t.Fatalf("ListCredentials = (%v, %v)", credentials, err)
	}
	secret, err := st.GetSecretString(credentials[0].SecretRef)
	if err != nil {
		t.Fatalf("GetSecretString: %v", err)
	}
	if secret != "the-upstream-password" {
		t.Fatalf("stored secret = %q", secret)
	}
}

func TestDPCredentialValidation(t *testing.T) {
	_, mux, _ := setupDPAdmin(t)
	doRequest(mux, http.MethodPost, "/api/v2/dp/targets", map[string]interface{}{
		"name": "web-1", "host": "10.0.1.10",
	})

	cases := []struct {
		name string
		body map[string]interface{}
	}{
		{"unknown kind", map[string]interface{}{
			"target_name": "web-1", "login": "deploy", "kind": "magic"}},
		{"password without a secret", map[string]interface{}{
			"target_name": "web-1", "login": "deploy", "kind": "password"}},
		{"private key that is not one", map[string]interface{}{
			"target_name": "web-1", "login": "deploy", "kind": "private_key",
			"secret": "not a key"}},
	}
	for _, tc := range cases {
		rr := doRequest(mux, http.MethodPost, "/api/v2/dp/credentials", tc.body)
		if rr.Code != http.StatusBadRequest {
			t.Errorf("%s: status = %d, want 400 (%s)", tc.name, rr.Code, rr.Body.String())
		}
	}
}

func TestDPAccessRuleRoundTripAndValidation(t *testing.T) {
	_, mux, st := setupDPAdmin(t)

	rr := doRequest(mux, http.MethodPost, "/api/v2/dp/rules", map[string]interface{}{
		"id": "r1", "name": "SRE to prod", "priority": 20,
		"subject_kind": "role", "subject": "sre", "target_selector": "tag:env=prod",
		"upstream_logins": []string{"deploy"},
		"features":        []string{"shell", "exec", "pty"},
		"denied_features": []string{"agent_forward"},
		"max_session_ttl": "4h", "idle_timeout": "15m",
		"record_policy": "full",
	})
	if rr.Code != http.StatusOK {
		t.Fatalf("put rule = %d: %s", rr.Code, rr.Body.String())
	}

	stored, err := st.GetAccessRule("r1")
	if err != nil {
		t.Fatalf("GetAccessRule: %v", err)
	}
	if !stored.Features.Has(store.FeatureShell) || stored.DeniedFeatures != store.FeatureAgentForward {
		t.Fatalf("features did not round trip: %s / %s", stored.Features, stored.DeniedFeatures)
	}
	if stored.MaxSessionTTL != 4*time.Hour || stored.IdleTimeout != 15*time.Minute {
		t.Fatalf("durations did not round trip: %v / %v", stored.MaxSessionTTL, stored.IdleTimeout)
	}

	// A rule is legible in the response: names, not a bitmask.
	rr = doRequest(mux, http.MethodGet, "/api/v2/dp/rules", nil)
	if !strings.Contains(rr.Body.String(), `"shell"`) {
		t.Errorf("the rule listing should name features: %s", rr.Body.String())
	}

	// A misspelled feature must be reported, not silently dropped: the rule
	// would otherwise grant less than its author wrote.
	rr = doRequest(mux, http.MethodPost, "/api/v2/dp/rules", map[string]interface{}{
		"id": "r2", "features": []string{"shell", "teleport"},
	})
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("an unknown feature should be rejected, got %d: %s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "teleport") {
		t.Errorf("the error should name the bad feature: %s", rr.Body.String())
	}

	for _, body := range []map[string]interface{}{
		{"id": "r3", "effect": "maybe"},
		{"id": "r4", "subject_kind": "alien"},
		{"id": "r5", "record_policy": "sometimes"},
		{"id": "r6", "max_session_ttl": "forever"},
	} {
		rr := doRequest(mux, http.MethodPost, "/api/v2/dp/rules", body)
		if rr.Code != http.StatusBadRequest {
			t.Errorf("invalid rule %+v was accepted with status %d", body, rr.Code)
		}
	}

	rr = doRequest(mux, http.MethodDelete, "/api/v2/dp/rules/r1", nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("delete rule = %d: %s", rr.Code, rr.Body.String())
	}
}

func TestDPEvaluateAnswersWhatWouldHappen(t *testing.T) {
	_, mux, st := setupDPAdmin(t)

	if _, err := st.CreateTarget(store.Target{
		Name: "web-1", Host: "10.0.1.10", Enabled: true,
		Tags: map[string]string{"env": "prod"},
	}); err != nil {
		t.Fatalf("CreateTarget: %v", err)
	}
	if _, err := st.PutAccessRule(store.AccessRule{
		ID: "r1", Priority: 10, Effect: store.EffectAllow,
		SubjectKind: store.SubjectUser, Subject: "alice", TargetSelector: "web-1",
		Features: store.FeatureShell, Enabled: true,
	}); err != nil {
		t.Fatalf("PutAccessRule: %v", err)
	}

	// Reading an ordered rule set is not the same as knowing what it does, so
	// being able to ask is what makes a change reviewable before it goes live.
	rr := doRequest(mux, http.MethodPost, "/api/v2/dp/rules/evaluate", map[string]interface{}{
		"username": "alice", "target": "web-1",
	})
	if rr.Code != http.StatusOK {
		t.Fatalf("evaluate = %d: %s", rr.Code, rr.Body.String())
	}
	data := parseResponse(t, rr).Data.(map[string]interface{})
	if data["allowed"] != true {
		t.Fatalf("alice should be allowed: %+v", data)
	}
	if data["rule_id"] != "r1" {
		t.Errorf("the answer should say which rule decided: %+v", data)
	}

	rr = doRequest(mux, http.MethodPost, "/api/v2/dp/rules/evaluate", map[string]interface{}{
		"username": "bob", "target": "web-1",
	})
	data = parseResponse(t, rr).Data.(map[string]interface{})
	if data["allowed"] != false {
		t.Fatalf("bob should be refused: %+v", data)
	}
	if data["reason"] == "" {
		t.Error("a refusal should explain itself")
	}
}

func TestDPSessionTerminationIsRecorded(t *testing.T) {
	_, mux, st := setupDPAdmin(t)
	session, err := st.CreateSession(store.Session{Username: "alice", NodeID: "node-a"})
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}

	rr := doRequest(mux, http.MethodPost,
		"/api/v2/dp/sessions/"+session.ID+"/terminate",
		map[string]interface{}{"reason": "suspicious activity"})
	if rr.Code != http.StatusAccepted {
		t.Fatalf("terminate = %d: %s", rr.Code, rr.Body.String())
	}

	// The request is recorded rather than executed here: only the node holding
	// the socket can close it.
	updated, err := st.GetSession(session.ID)
	if err != nil {
		t.Fatalf("GetSession: %v", err)
	}
	if !updated.RevokeRequested || updated.RevokeReason != "suspicious activity" {
		t.Fatalf("revocation was not recorded: %+v", updated)
	}
}

func TestDPRoutesRequireAdministrator(t *testing.T) {
	// Every endpoint under this prefix changes who can reach what, so none of
	// them should be reachable by an operator.
	policy := middleware.DefaultAuthzConfig()
	for _, path := range []string{
		"/api/v2/dp/users", "/api/v2/dp/targets", "/api/v2/dp/credentials",
		"/api/v2/dp/rules", "/api/v2/dp/ip-rules", "/api/v2/dp/sessions",
	} {
		for _, method := range []string{http.MethodGet, http.MethodPost, http.MethodDelete} {
			if policy.Allows(middleware.RoleOperator, method, path) {
				t.Errorf("%s %s is reachable by an operator", method, path)
			}
			if !policy.Allows(middleware.RoleAdmin, method, path) {
				t.Errorf("%s %s is not reachable by an admin", method, path)
			}
		}
	}
}

func TestDPRoutesReportWhenTheStoreIsAbsent(t *testing.T) {
	_, mux, _ := setupTestAPI(t)
	api := &API{}
	api.RegisterDataPlaneRoutes(mux)

	rr := doRequest(mux, http.MethodGet, "/api/v2/dp/users", nil)
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503 when the store is not configured", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "pdp_listen_addr") {
		t.Errorf("the error should say how to enable it: %s", rr.Body.String())
	}
}

func TestDPHandlesFingerprintsContainingASlash(t *testing.T) {
	_, mux, st := setupDPAdmin(t)
	if _, err := st.CreateTarget(store.Target{Name: "web-1", Host: "10.0.1.10", Enabled: true}); err != nil {
		t.Fatalf("CreateTarget: %v", err)
	}
	target, _ := st.GetTarget("web-1")

	// SHA256 fingerprints are base64, so roughly one in three contains a
	// forward slash. Relying on a random key to produce one makes this a bug
	// that appears intermittently in production and never in review.
	fingerprint := "SHA256:abc/def+ghi/jkl"
	if _, err := st.PutHostKey(store.HostKey{
		TargetID: target.ID, Fingerprint: fingerprint, Status: store.HostKeyPending,
	}); err != nil {
		t.Fatalf("PutHostKey: %v", err)
	}

	rr := doRequest(mux, http.MethodPut,
		"/api/v2/dp/targets/web-1/host-keys/"+fingerprint,
		map[string]interface{}{"status": "trusted"})
	if rr.Code != http.StatusOK {
		t.Fatalf("trusting a key whose fingerprint contains a slash = %d: %s", rr.Code, rr.Body.String())
	}
	keys, _ := st.ListHostKeys(target.ID)
	if len(keys) != 1 || keys[0].Status != store.HostKeyTrusted {
		t.Fatalf("host key was not promoted: %+v", keys)
	}

	rr = doRequest(mux, http.MethodDelete,
		"/api/v2/dp/targets/web-1/host-keys/"+fingerprint, nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("deleting it = %d: %s", rr.Code, rr.Body.String())
	}
}
