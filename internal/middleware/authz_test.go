package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRoleAtLeast(t *testing.T) {
	cases := []struct {
		have, want string
		ok         bool
	}{
		{RoleAdmin, RoleAdmin, true},
		{RoleAdmin, RoleOperator, true},
		{RoleAdmin, RoleViewer, true},
		{RoleOperator, RoleAdmin, false},
		{RoleOperator, RoleOperator, true},
		{RoleOperator, RoleViewer, true},
		{RoleViewer, RoleOperator, false},
		{RoleViewer, RoleViewer, true},
		{"", RoleViewer, true},
		{"", RoleOperator, false},
		{"", RoleAdmin, false},
		{"ADMIN", RoleAdmin, true},
		{"bogus", RoleOperator, false},
	}
	for _, tc := range cases {
		if got := RoleAtLeast(tc.have, tc.want); got != tc.ok {
			t.Errorf("RoleAtLeast(%q, %q) = %v, want %v", tc.have, tc.want, got, tc.ok)
		}
	}
}

func TestDefaultAuthzRequiredRole(t *testing.T) {
	cfg := DefaultAuthzConfig().prepare()
	cases := []struct {
		method, path, want string
	}{
		// Defaults.
		{http.MethodGet, "/api/v2/sessions", RoleViewer},
		{http.MethodGet, "/dashboard", RoleViewer},
		{http.MethodPost, "/api/v2/something-new", RoleOperator},

		// Identity management is admin-only in both directions.
		{http.MethodGet, "/api/v2/users", RoleAdmin},
		{http.MethodPost, "/api/v2/users", RoleAdmin},
		{http.MethodPost, "/api/v2/users/alice/password", RoleAdmin},
		{http.MethodPut, "/api/v2/users/alice/mfa", RoleAdmin},

		// Reachability changes are admin; reads are lower.
		{http.MethodGet, "/api/v2/servers", RoleViewer},
		{http.MethodPost, "/api/v2/servers", RoleAdmin},
		{http.MethodDelete, "/api/v2/servers/web-1", RoleAdmin},
		{http.MethodGet, "/api/v2/config", RoleOperator},
		{http.MethodPut, "/api/v2/config", RoleAdmin},
		// Self-service certificates: the handler binds principals to the caller.
		{http.MethodPost, "/api/v2/ca/sign-user", RoleViewer},
		{http.MethodGet, "/api/v2/ca/public-keys", RoleViewer},
		{http.MethodGet, "/api/v2/ca/crl", RoleViewer},
		{http.MethodPost, "/api/v2/ca/sign-host", RoleAdmin},
		{http.MethodPost, "/api/v2/ca/revoke", RoleAdmin},
		{http.MethodGet, "/api/v2/ca/certs", RoleOperator},
		{http.MethodPut, "/api/v2/jit/policy", RoleAdmin},
		{http.MethodPost, "/api/v2/commands/rules", RoleAdmin},
		{http.MethodPost, "/api/v2/gateway/proxies", RoleAdmin},

		// Platform lifecycle.
		{http.MethodPost, "/api/v2/system/upgrade", RoleAdmin},
		{http.MethodGet, "/api/v2/system/info", RoleAdmin},
		{http.MethodPost, "/api/v2/cluster/nodes", RoleAdmin},
		{http.MethodGet, "/api/v2/cluster/nodes", RoleViewer},

		// Audit is read-only from outside.
		{http.MethodGet, "/api/v2/audit/events", RoleViewer},
		{http.MethodDelete, "/api/v2/audit/events/1", RoleAdmin},

		// Operations.
		{http.MethodPost, "/api/v2/sessions/abc/kill", RoleOperator},
		{http.MethodPost, "/api/v2/automation/jobs/1/run", RoleOperator},
		{http.MethodGet, "/ws/terminal", RoleOperator},

		// The v3 alias resolves to the same rules as v2.
		{http.MethodPost, "/api/v3/users", RoleAdmin},
		{http.MethodPost, "/api/v3/system/upgrade", RoleAdmin},
		{http.MethodGet, "/api/v3/sessions", RoleViewer},
	}
	for _, tc := range cases {
		if got := cfg.RequiredRole(tc.method, tc.path); got != tc.want {
			t.Errorf("RequiredRole(%s %s) = %q, want %q", tc.method, tc.path, got, tc.want)
		}
	}
}

func TestAuthorizeMiddleware(t *testing.T) {
	reached := false
	handler := Authorize(DefaultAuthzConfig())(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		reached = true
		w.WriteHeader(http.StatusOK)
	}))

	cases := []struct {
		name       string
		role       string
		method     string
		path       string
		wantStatus int
	}{
		{"admin creates user", RoleAdmin, http.MethodPost, "/api/v2/users", http.StatusOK},
		{"operator cannot create user", RoleOperator, http.MethodPost, "/api/v2/users", http.StatusForbidden},
		{"viewer cannot create user", RoleViewer, http.MethodPost, "/api/v2/users", http.StatusForbidden},
		{"viewer reads sessions", RoleViewer, http.MethodGet, "/api/v2/sessions", http.StatusOK},
		{"viewer cannot kill a session", RoleViewer, http.MethodPost, "/api/v2/sessions/x/kill", http.StatusForbidden},
		{"operator kills a session", RoleOperator, http.MethodPost, "/api/v2/sessions/x/kill", http.StatusOK},
		{"operator cannot upgrade the system", RoleOperator, http.MethodPost, "/api/v2/system/upgrade", http.StatusForbidden},
		{"roleless session is read-only", "", http.MethodGet, "/api/v2/sessions", http.StatusOK},
		{"roleless session cannot mutate", "", http.MethodPost, "/api/v2/sessions/x/kill", http.StatusForbidden},
		{"public health needs nothing", "", http.MethodGet, "/api/v1/health", http.StatusOK},
		{"login page is public", "", http.MethodPost, "/login", http.StatusOK},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			reached = false
			req := httptest.NewRequest(tc.method, tc.path, nil)
			if tc.role != "" {
				req.Header.Set("X-Auth-Role", tc.role)
			}
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)

			if rec.Code != tc.wantStatus {
				t.Fatalf("status = %d, want %d (body %q)", rec.Code, tc.wantStatus, rec.Body.String())
			}
			if wantReached := tc.wantStatus == http.StatusOK; reached != wantReached {
				t.Fatalf("handler reached = %v, want %v", reached, wantReached)
			}
		})
	}
}

func TestAuthorizeMostSpecificRuleWins(t *testing.T) {
	cfg := AuthzConfig{
		ReadRole:  RoleViewer,
		WriteRole: RoleOperator,
		Rules: []RouteRule{
			// Deliberately declared least-specific first.
			{Prefix: "/api/v2/", Role: RoleViewer},
			{Prefix: "/api/v2/secrets/", Role: RoleAdmin},
		},
	}.prepare()

	if got := cfg.RequiredRole(http.MethodGet, "/api/v2/secrets/db"); got != RoleAdmin {
		t.Fatalf("longer prefix should win: got %q", got)
	}
	if got := cfg.RequiredRole(http.MethodGet, "/api/v2/other"); got != RoleViewer {
		t.Fatalf("shorter prefix should still apply elsewhere: got %q", got)
	}
}

func TestRequireRoleHandler(t *testing.T) {
	h := RequireRole(RoleAdmin, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusTeapot)
	}))

	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	req.Header.Set("X-Auth-Role", RoleOperator)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("operator should be rejected, got %d", rec.Code)
	}

	req.Header.Set("X-Auth-Role", RoleAdmin)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusTeapot {
		t.Fatalf("admin should pass through, got %d", rec.Code)
	}
}
