package server

import (
	"context"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/zltl/audit-proxy-core/internal/authn"
	"github.com/zltl/audit-proxy-core/internal/config"
	"github.com/zltl/audit-proxy-core/internal/middleware"
	"github.com/zltl/audit-proxy-core/internal/models"
	"golang.org/x/crypto/bcrypt"
)

// newLoginTestServer builds a control plane whose user store can be seeded, and
// returns both the Server (for direct access to the user store) and an httptest
// server exercising the real middleware chain.
func newLoginTestServer(t *testing.T) (*Server, *httptest.Server) {
	t.Helper()

	adminHash, err := bcrypt.GenerateFromPassword([]byte("bootstrap-password"), bcrypt.MinCost)
	if err != nil {
		t.Fatalf("bcrypt: %v", err)
	}

	cfg := &config.Config{
		ListenAddr:    "127.0.0.1:0",
		SessionSecret: "login-test-secret",
		AdminUser:     "bootstrap",
		AdminPassHash: string(adminHash),
		AuditLogDir:   t.TempDir(),
		RecordingDir:  t.TempDir(),
		DataDir:       t.TempDir(),
	}

	srv, err := New(cfg)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	ts := httptest.NewServer(srv.srv.Handler)
	t.Cleanup(func() {
		_ = srv.Shutdown(context.Background())
		ts.Close()
	})
	return srv, ts
}

func seedUser(t *testing.T, srv *Server, user models.User, password string) {
	t.Helper()
	hash, err := authn.HashPassword(password)
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	user.PassHash = hash
	if user.CreatedAt.IsZero() {
		user.CreatedAt = time.Now().UTC()
	}
	if err := srv.apiHandler.CreateUser(user); err != nil {
		t.Fatalf("seed user %q: %v", user.Username, err)
	}
}

// newLoginClient returns a client that keeps cookies but does not follow
// redirects, so the test can inspect each step of the login exchange.
func newLoginClient(t *testing.T) *http.Client {
	t.Helper()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("cookiejar.New: %v", err)
	}
	return &http.Client{
		Jar: jar,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

func postLogin(t *testing.T, client *http.Client, base string, form url.Values) *http.Response {
	t.Helper()
	// Obtain a CSRF token the same way a browser would.
	pageResp, err := client.Get(base + "/login")
	if err != nil {
		t.Fatalf("GET /login: %v", err)
	}
	_ = pageResp.Body.Close()
	token := pageResp.Header.Get("X-CSRF-Token")
	if token == "" {
		u, _ := url.Parse(base)
		for _, c := range client.Jar.Cookies(u) {
			if c.Name == "csrf_token" {
				token = c.Value
			}
		}
	}
	form.Set("csrf_token", token)

	resp, err := client.PostForm(base+"/login", form)
	if err != nil {
		t.Fatalf("POST /login: %v", err)
	}
	return resp
}

func sessionRoleFor(t *testing.T, client *http.Client, base string) (string, string) {
	t.Helper()
	u, err := url.Parse(base)
	if err != nil {
		t.Fatalf("url.Parse: %v", err)
	}
	for _, c := range client.Jar.Cookies(u) {
		if c.Name != "session" {
			continue
		}
		principal, ok := middleware.ValidateSessionClaims(&http.Request{
			Header: http.Header{"Cookie": []string{c.Name + "=" + c.Value}},
		}, "login-test-secret")
		if !ok {
			t.Fatalf("session cookie did not validate: %q", c.Value)
		}
		return principal.Username, principal.Role
	}
	return "", ""
}

func TestLoginUsesTheAccountsConfiguredRole(t *testing.T) {
	srv, ts := newLoginTestServer(t)
	seedUser(t, srv, models.User{Username: "vera", Role: middleware.RoleViewer, Enabled: true}, "vera-password-1")

	client := newLoginClient(t)
	resp := postLogin(t, client, ts.URL, url.Values{
		"username": {"vera"},
		"password": {"vera-password-1"},
	})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("expected a redirect after login, got %d", resp.StatusCode)
	}

	username, role := sessionRoleFor(t, client, ts.URL)
	if username != "vera" {
		t.Fatalf("session username = %q", username)
	}
	if role != middleware.RoleViewer {
		t.Fatalf("session role = %q, want %q; a viewer must not be minted as admin", role, middleware.RoleViewer)
	}

	// And the role must actually restrict what the session can do.
	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/v2/users", strings.NewReader(`{}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CSRF-Token", csrfTokenFor(t, client, ts.URL))
	adminResp, err := client.Do(req)
	if err != nil {
		t.Fatalf("POST /api/v2/users: %v", err)
	}
	defer adminResp.Body.Close()
	if adminResp.StatusCode != http.StatusForbidden {
		t.Fatalf("viewer reached an admin endpoint: status %d", adminResp.StatusCode)
	}
}

func csrfTokenFor(t *testing.T, client *http.Client, base string) string {
	t.Helper()
	u, err := url.Parse(base)
	if err != nil {
		t.Fatalf("url.Parse: %v", err)
	}
	for _, c := range client.Jar.Cookies(u) {
		if c.Name == "csrf_token" {
			return c.Value
		}
	}
	return ""
}

func TestLoginRejectsWrongPasswordAndDisabledAccounts(t *testing.T) {
	srv, ts := newLoginTestServer(t)
	seedUser(t, srv, models.User{Username: "olive", Role: middleware.RoleOperator, Enabled: true}, "olive-password-1")
	seedUser(t, srv, models.User{Username: "dormant", Role: middleware.RoleAdmin, Enabled: false}, "dormant-password")

	for _, tc := range []struct{ name, user, pass string }{
		{"wrong password", "olive", "not-the-password"},
		{"disabled account", "dormant", "dormant-password"},
		{"unknown user", "ghost", "whatever-password"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client := newLoginClient(t)
			resp := postLogin(t, client, ts.URL, url.Values{
				"username": {tc.user},
				"password": {tc.pass},
			})
			defer resp.Body.Close()
			if resp.StatusCode == http.StatusSeeOther {
				t.Fatal("login succeeded when it should have failed")
			}
			if username, _ := sessionRoleFor(t, client, ts.URL); username != "" {
				t.Fatalf("a session cookie was issued for a failed login (%q)", username)
			}
		})
	}
}

func TestLoginRequiresSecondFactorWhenMFAEnabled(t *testing.T) {
	srv, ts := newLoginTestServer(t)
	secret, err := authn.GenerateTOTPSecret()
	if err != nil {
		t.Fatalf("GenerateTOTPSecret: %v", err)
	}
	seedUser(t, srv, models.User{
		Username:   "mona",
		Role:       middleware.RoleOperator,
		Enabled:    true,
		MFAEnabled: true,
		MFASecret:  secret,
	}, "mona-password-12")

	client := newLoginClient(t)

	// Step one: the correct password alone must not produce a session.
	resp := postLogin(t, client, ts.URL, url.Values{
		"username": {"mona"},
		"password": {"mona-password-12"},
	})
	body := readBody(t, resp)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected the MFA form, got status %d", resp.StatusCode)
	}
	if !strings.Contains(body, "totp_code") {
		t.Fatalf("expected the response to prompt for a code, got: %s", body)
	}
	if username, _ := sessionRoleFor(t, client, ts.URL); username != "" {
		t.Fatal("a session was issued before the second factor was verified")
	}

	// Step two: a wrong code still must not produce a session.
	resp = postLogin(t, client, ts.URL, url.Values{"totp_code": {"000000"}})
	_ = readBody(t, resp)
	if username, _ := sessionRoleFor(t, client, ts.URL); username != "" {
		t.Fatal("a session was issued after a failed second factor")
	}

	// Step three: the real code completes the login.
	code, err := authn.TOTPCode(secret, time.Now(), authn.DefaultTOTPConfig())
	if err != nil {
		t.Fatalf("TOTPCode: %v", err)
	}
	resp = postLogin(t, client, ts.URL, url.Values{"totp_code": {code}})
	_ = readBody(t, resp)
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("expected a redirect after a valid code, got %d", resp.StatusCode)
	}
	username, role := sessionRoleFor(t, client, ts.URL)
	if username != "mona" || role != middleware.RoleOperator {
		t.Fatalf("session = (%q, %q), want (mona, operator)", username, role)
	}
}

func TestLoginUpgradesLegacyPasswordHash(t *testing.T) {
	srv, ts := newLoginTestServer(t)

	// Seed a bcrypt hash, which VerifyPassword accepts but NeedsRehash flags.
	legacy, err := bcrypt.GenerateFromPassword([]byte("legacy-password-1"), bcrypt.MinCost)
	if err != nil {
		t.Fatalf("bcrypt: %v", err)
	}
	if err := srv.apiHandler.CreateUser(models.User{
		Username: "lenny",
		Role:     middleware.RoleViewer,
		Enabled:  true,
		PassHash: string(legacy),
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}

	client := newLoginClient(t)
	resp := postLogin(t, client, ts.URL, url.Values{
		"username": {"lenny"},
		"password": {"legacy-password-1"},
	})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("legacy hash login failed with status %d", resp.StatusCode)
	}

	user, ok, err := srv.apiHandler.LookupUser("lenny")
	if err != nil || !ok {
		t.Fatalf("LookupUser: %v (found=%v)", err, ok)
	}
	if !strings.HasPrefix(user.PassHash, "$argon2id$") {
		t.Fatalf("password hash was not upgraded: %q", user.PassHash)
	}
	if !authn.VerifyPassword("legacy-password-1", user.PassHash) {
		t.Fatal("upgraded hash no longer verifies the original password")
	}
}

func TestBootstrapAdminStillWorksWithoutUserRows(t *testing.T) {
	_, ts := newLoginTestServer(t)

	client := newLoginClient(t)
	resp := postLogin(t, client, ts.URL, url.Values{
		"username": {"bootstrap"},
		"password": {"bootstrap-password"},
	})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("bootstrap admin login failed with status %d", resp.StatusCode)
	}
	username, role := sessionRoleFor(t, client, ts.URL)
	if username != "bootstrap" || role != middleware.RoleAdmin {
		t.Fatalf("session = (%q, %q), want (bootstrap, admin)", username, role)
	}
}

func readBody(t *testing.T, resp *http.Response) string {
	t.Helper()
	defer resp.Body.Close()
	buf := make([]byte, 64*1024)
	n, _ := resp.Body.Read(buf)
	return string(buf[:n])
}
