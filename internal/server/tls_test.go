package server

import (
	"crypto/tls"
	"crypto/x509"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/ssh-proxy-core/ssh-proxy-core/internal/config"
	"golang.org/x/crypto/acme"
)

func TestBuildRuntimeTLSConfigSelfSignedDefaults(t *testing.T) {
	cfg := &config.Config{
		ListenAddr:    "127.0.0.1:8443",
		TLSSelfSigned: true,
		SessionSecret: "secret",
	}

	tlsCfg, err := buildRuntimeTLSConfig(cfg)
	if err != nil {
		t.Fatalf("buildRuntimeTLSConfig(self-signed defaults) error = %v", err)
	}
	if tlsCfg == nil {
		t.Fatal("buildRuntimeTLSConfig(self-signed defaults) returned nil config")
	}
	if tlsCfg.MinVersion != tls.VersionTLS12 {
		t.Fatalf("MinVersion = %v, want TLS 1.2", tlsCfg.MinVersion)
	}
	if len(tlsCfg.Certificates) != 1 {
		t.Fatalf("Certificates = %d, want 1", len(tlsCfg.Certificates))
	}

	leaf, err := x509.ParseCertificate(tlsCfg.Certificates[0].Certificate[0])
	if err != nil {
		t.Fatalf("ParseCertificate = %v", err)
	}
	if !containsIP(leaf.IPAddresses, net.ParseIP("127.0.0.1")) {
		t.Fatalf("self-signed cert missing 127.0.0.1 SAN: %+v", leaf.IPAddresses)
	}
	if !containsString(leaf.DNSNames, "localhost") {
		t.Fatalf("self-signed cert missing localhost SAN: %+v", leaf.DNSNames)
	}
}

func TestBuildRuntimeTLSConfigSelfSignedHosts(t *testing.T) {
	cfg := &config.Config{
		ListenAddr:         ":8443",
		TLSSelfSigned:      true,
		TLSSelfSignedHosts: "proxy.example.com,192.0.2.10",
		SessionSecret:      "secret",
	}

	tlsCfg, err := buildRuntimeTLSConfig(cfg)
	if err != nil {
		t.Fatalf("buildRuntimeTLSConfig(self-signed hosts) error = %v", err)
	}

	leaf, err := x509.ParseCertificate(tlsCfg.Certificates[0].Certificate[0])
	if err != nil {
		t.Fatalf("ParseCertificate = %v", err)
	}
	if !containsString(leaf.DNSNames, "proxy.example.com") {
		t.Fatalf("self-signed cert missing proxy.example.com SAN: %+v", leaf.DNSNames)
	}
	if !containsIP(leaf.IPAddresses, net.ParseIP("192.0.2.10")) {
		t.Fatalf("self-signed cert missing 192.0.2.10 SAN: %+v", leaf.IPAddresses)
	}
}

func TestBuildRuntimeTLSConfigLetsEncrypt(t *testing.T) {
	cfg := &config.Config{
		DataDir:                t.TempDir(),
		TLSLetsEncrypt:         true,
		TLSLetsEncryptHosts:    "proxy.example.com",
		TLSLetsEncryptCacheDir: filepath.Join(t.TempDir(), "acme"),
		SessionSecret:          "secret",
	}

	tlsCfg, err := buildRuntimeTLSConfig(cfg)
	if err != nil {
		t.Fatalf("buildRuntimeTLSConfig(lets encrypt) error = %v", err)
	}
	if tlsCfg == nil {
		t.Fatal("buildRuntimeTLSConfig(lets encrypt) returned nil config")
	}
	if tlsCfg.MinVersion != tls.VersionTLS12 {
		t.Fatalf("MinVersion = %v, want TLS 1.2", tlsCfg.MinVersion)
	}
	if tlsCfg.GetCertificate == nil {
		t.Fatal("GetCertificate is nil for Let's Encrypt config")
	}
	if !containsString(tlsCfg.NextProtos, acme.ALPNProto) {
		t.Fatalf("NextProtos missing %q: %+v", acme.ALPNProto, tlsCfg.NextProtos)
	}
}

func TestServerAddsHSTSHeaderWhenEnabled(t *testing.T) {
	dataPlane := httptest.NewServer(http.NotFoundHandler())
	t.Cleanup(dataPlane.Close)

	cfg := &config.Config{
		ListenAddr:            "127.0.0.1:0",
		DataPlaneAddr:         dataPlane.URL,
		DataPlaneToken:        "token",
		SessionSecret:         "secret",
		AdminUser:             "admin",
		AdminPassHash:         "$2a$10$7EqJtq98hPqEX7fNZaFWoOHi4uA0sC0Bpvy.buk..qS0w6Y8G9M8K",
		AuditLogDir:           t.TempDir(),
		RecordingDir:          t.TempDir(),
		DataDir:               t.TempDir(),
		HSTSEnabled:           true,
		HSTSIncludeSubdomains: true,
		HSTSPreload:           true,
	}

	srv, err := New(cfg)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "https://proxy.example.com/login", nil)
	req.TLS = &tls.ConnectionState{}
	rr := httptest.NewRecorder()
	srv.srv.Handler.ServeHTTP(rr, req)

	if got := rr.Header().Get("Strict-Transport-Security"); got != "max-age=31536000; includeSubDomains; preload" {
		t.Fatalf("Strict-Transport-Security = %q", got)
	}
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func containsIP(values []net.IP, want net.IP) bool {
	for _, value := range values {
		if value.Equal(want) {
			return true
		}
	}
	return false
}
