package server

import (
	"io/fs"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ssh-proxy-core/ssh-proxy-core/web"
)

func TestDashboardPageUsesCurrentAPIs(t *testing.T) {
	dataPlane := httptest.NewServer(http.NotFoundHandler())
	t.Cleanup(dataPlane.Close)

	cfg, controlPlane := newControlPlaneTestServer(t, dataPlane.URL, "dp-secret-token")
	client := newAuthenticatedClient(t, controlPlane.URL, cfg.SessionSecret)

	resp := mustRequest(t, client, http.MethodGet, controlPlane.URL+"/dashboard", nil, nil)
	if resp.StatusCode != http.StatusOK {
		body := string(mustReadBody(t, resp))
		t.Fatalf("GET /dashboard status = %d body = %s", resp.StatusCode, body)
	}
	_ = mustReadBody(t, resp)

	body := mustReadEmbeddedTemplate(t, "templates/pages/dashboard.html")
	for _, needle := range []string{
		"/api/v2/dashboard/stats",
		"/api/v2/sessions",
		"/api/v2/audit/events",
		"/api/v2/servers",
		"/ws/dashboard",
		"/api/v2/config/reload",
	} {
		if !strings.Contains(body, needle) {
			t.Fatalf("dashboard page missing %q", needle)
		}
	}
}

func TestManagementPagesUseCurrentAPIs(t *testing.T) {
	dataPlane := httptest.NewServer(http.NotFoundHandler())
	t.Cleanup(dataPlane.Close)

	cfg, controlPlane := newControlPlaneTestServer(t, dataPlane.URL, "dp-secret-token")
	client := newAuthenticatedClient(t, controlPlane.URL, cfg.SessionSecret)

	cases := []struct {
		path    string
		needles []string
	}{
		{path: "/sessions", needles: []string{"/api/v2/sessions", "/api/v2/sessions/bulk-kill", "/api/v2/sessions/' + encodeURIComponent(id) + '/recording/download", "/ws/sessions", "/ws/sessions/", "filter-ip", "filter-target", "asciinema-player.min.js"}},
		{path: "/users", needles: []string{"/api/v2/users", "/api/v2/users/", "/api/v2/users/' + encodeURIComponent(username) + '/mfa/qrcode", "/api/v2/audit/events?user=", "deleteUser(", "qrious@4.0.2"}},
		{path: "/servers", needles: []string{"/api/v2/servers", "/api/v2/servers/", "/api/v2/servers/health", "server-summary-total", "deleteServer("}},
		{path: "/automation", needles: []string{"/api/v2/automation/scripts", "/api/v2/automation/jobs", "/api/v2/automation/runs", "/api/v2/servers", "createAutomationScript", "createAutomationJob", "runAutomationJob"}},
		{path: "/audit", needles: []string{"/api/v2/audit/events", "/api/v2/audit/search", "/api/v2/audit/export"}},
		{path: "/webhooks", needles: []string{"/api/v2/webhooks/deliveries", "/api/v2/webhooks/deliveries/retry", "retryWebhookDeliveries", "webhook-deliveries-table"}},
		{path: "/terminal", needles: []string{"/api/v2/servers", "/ws/terminal", "xterm@5.3.0", "zmodem.js@0.1.7", "navigator.clipboard", "copyTerminalSelection", "pasteClipboard", "chooseTerminalUpload", "terminal-drop-overlay", "terminal-recording-download"}},
		{path: "/settings", needles: []string{"/api/v2/config", "/api/v2/config/templates", "/api/v2/config/export", "/api/v2/config/import", "/api/v2/config/versions", "/api/v2/config/rollback"}},
	}

	for _, tc := range cases {
		resp := mustRequest(t, client, http.MethodGet, controlPlane.URL+tc.path, nil, nil)
		if resp.StatusCode != http.StatusOK {
			body := string(mustReadBody(t, resp))
			t.Fatalf("GET %s status = %d body = %s", tc.path, resp.StatusCode, body)
		}
		_ = mustReadBody(t, resp)

		body := mustReadEmbeddedTemplate(t, "templates/pages"+tc.path+".html")
		for _, needle := range tc.needles {
			if !strings.Contains(body, needle) {
				t.Fatalf("%s page missing %q", tc.path, needle)
			}
		}
	}
}

func mustReadEmbeddedTemplate(t *testing.T, path string) string {
	t.Helper()

	data, err := fs.ReadFile(web.EmbeddedFS, path)
	if err != nil {
		t.Fatalf("fs.ReadFile(%q) error = %v", path, err)
	}
	return string(data)
}
