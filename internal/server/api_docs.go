package server

import (
	"net/http"

	"github.com/ssh-proxy-core/ssh-proxy-core/internal/openapi"
)

const swaggerHTML = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>SSH Proxy Core API Docs</title>
  <link rel="stylesheet" href="https://unpkg.com/swagger-ui-dist@5/swagger-ui.css">
  <style>
    body { margin: 0; background: #fafafa; }
    .topbar { display: none; }
    .info-banner {
      font-family: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      margin: 0;
      padding: 12px 20px;
      background: #111827;
      color: #f9fafb;
      font-size: 14px;
    }
    .info-banner code { color: #93c5fd; }
  </style>
</head>
<body>
  <p class="info-banner">
    Log in to the web UI first. Swagger UI uses the current <code>session</code> cookie automatically and copies the <code>csrf_token</code> cookie into <code>X-CSRF-Token</code> for POST/PUT/DELETE requests.
  </p>
  <div id="swagger-ui"></div>
  <script src="https://unpkg.com/swagger-ui-dist@5/swagger-ui-bundle.js"></script>
  <script src="https://unpkg.com/swagger-ui-dist@5/swagger-ui-standalone-preset.js"></script>
  <script>
    function readCookie(name) {
      const prefix = name + "=";
      for (const part of document.cookie.split(";")) {
        const cookie = part.trim();
        if (cookie.startsWith(prefix)) {
          return decodeURIComponent(cookie.substring(prefix.length));
        }
      }
      return "";
    }

    window.onload = function() {
      SwaggerUIBundle({
        url: "/api/openapi.json",
        dom_id: "#swagger-ui",
        deepLinking: true,
        presets: [SwaggerUIBundle.presets.apis, SwaggerUIStandalonePreset],
        layout: "BaseLayout",
        requestInterceptor: function(req) {
          req.credentials = "same-origin";
          const method = (req.method || "get").toLowerCase();
          if (method === "post" || method === "put" || method === "delete" || method === "patch") {
            const token = readCookie("csrf_token");
            if (token) {
              req.headers["X-CSRF-Token"] = token;
            }
          }
          return req;
        }
      });
    };
  </script>
</body>
</html>`

func (s *Server) handleOpenAPIJSON(w http.ResponseWriter, r *http.Request) {
	specJSON, err := openapi.JSON()
	if err != nil {
		http.Error(w, "failed to generate OpenAPI document", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(specJSON)
}

func (s *Server) handleAPIDocs(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(swaggerHTML))
}
