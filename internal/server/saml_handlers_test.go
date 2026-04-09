package server

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"encoding/xml"
	"math/big"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	crewsaml "github.com/crewjam/saml"
	dsig "github.com/russellhaering/goxmldsig"
	"github.com/ssh-proxy-core/ssh-proxy-core/internal/config"
)

func TestLoginPageShowsSAMLButtonWhenConfigured(t *testing.T) {
	dataPlane := httptest.NewServer(http.NotFoundHandler())
	t.Cleanup(dataPlane.Close)

	controlTS, setControlHandler := newDeferredServer(t)
	idp := newTestSAMLIdentityProvider(t, controlTS.URL+"/auth/saml/metadata")
	newTestSAMLControlPlaneServer(t, controlTS, setControlHandler, dataPlane.URL, idp.metadataURL())

	resp := mustRequest(t, http.DefaultClient, http.MethodGet, controlTS.URL+"/login", nil, nil)
	if resp.StatusCode != http.StatusOK {
		body := string(mustReadBody(t, resp))
		t.Fatalf("GET /login status = %d body = %s", resp.StatusCode, body)
	}
	body := string(mustReadBody(t, resp))
	if !strings.Contains(body, "/auth/saml/login") {
		t.Fatalf("login page missing SAML login action: %s", body)
	}
}

func TestSAMLSPInitiatedLoginCreatesMappedSession(t *testing.T) {
	dataPlane := httptest.NewServer(http.NotFoundHandler())
	t.Cleanup(dataPlane.Close)

	controlTS, setControlHandler := newDeferredServer(t)
	idp := newTestSAMLIdentityProvider(t, controlTS.URL+"/auth/saml/metadata")
	cfg := newTestSAMLControlPlaneServer(t, controlTS, setControlHandler, dataPlane.URL, idp.metadataURL())

	jar := newCookieJar(t)
	noRedirectClient := newHTTPClient(jar, false)
	browserClient := newHTTPClient(jar, true)

	resp := mustRequest(t, noRedirectClient, http.MethodGet, controlTS.URL+"/auth/saml/login?return_to=%2Fservers", nil, nil)
	if resp.StatusCode != http.StatusFound {
		body := string(mustReadBody(t, resp))
		t.Fatalf("GET /auth/saml/login status = %d body = %s", resp.StatusCode, body)
	}
	location := resp.Header.Get("Location")
	if location == "" {
		t.Fatal("missing IdP redirect location")
	}

	acsAction, acsForm := idp.buildSPInitiatedForm(t, location)
	resp = submitHTMLForm(t, browserClient, acsAction, acsForm)
	if resp.StatusCode != http.StatusOK {
		body := string(mustReadBody(t, resp))
		t.Fatalf("final SP-initiated response status = %d body = %s", resp.StatusCode, body)
	}
	if resp.Request.URL.Path != "/servers" {
		t.Fatalf("final redirect path = %q, want /servers", resp.Request.URL.Path)
	}

	assertAuthenticatedRole(t, browserClient, controlTS.URL, "alice@example.com", "operator")
	if !cfg.SAMLAllowIDPInitiated {
		t.Fatal("expected SAML allow IDP initiated to be enabled in test config")
	}
}

func TestSAMLIDPInitiatedLoginHonorsRelayState(t *testing.T) {
	dataPlane := httptest.NewServer(http.NotFoundHandler())
	t.Cleanup(dataPlane.Close)

	controlTS, setControlHandler := newDeferredServer(t)
	idp := newTestSAMLIdentityProvider(t, controlTS.URL+"/auth/saml/metadata")
	newTestSAMLControlPlaneServer(t, controlTS, setControlHandler, dataPlane.URL, idp.metadataURL())

	client := newHTTPClient(newCookieJar(t), true)
	acsAction, acsForm := idp.buildIDPInitiatedForm(t, "/settings")
	resp := submitHTMLForm(t, client, acsAction, acsForm)
	if resp.StatusCode != http.StatusOK {
		body := string(mustReadBody(t, resp))
		t.Fatalf("final IdP-initiated response status = %d body = %s", resp.StatusCode, body)
	}
	if resp.Request.URL.Path != "/settings" {
		t.Fatalf("final redirect path = %q, want /settings", resp.Request.URL.Path)
	}

	assertAuthenticatedRole(t, client, controlTS.URL, "alice@example.com", "operator")
}

func TestSAMLACSRejectsTamperedAssertion(t *testing.T) {
	dataPlane := httptest.NewServer(http.NotFoundHandler())
	t.Cleanup(dataPlane.Close)

	controlTS, setControlHandler := newDeferredServer(t)
	idp := newTestSAMLIdentityProvider(t, controlTS.URL+"/auth/saml/metadata")
	newTestSAMLControlPlaneServer(t, controlTS, setControlHandler, dataPlane.URL, idp.metadataURL())

	jar := newCookieJar(t)
	noRedirectClient := newHTTPClient(jar, false)
	browserClient := newHTTPClient(jar, true)

	resp := mustRequest(t, noRedirectClient, http.MethodGet, controlTS.URL+"/auth/saml/login", nil, nil)
	if resp.StatusCode != http.StatusFound {
		body := string(mustReadBody(t, resp))
		t.Fatalf("GET /auth/saml/login status = %d body = %s", resp.StatusCode, body)
	}
	acsAction, acsForm := idp.buildSPInitiatedForm(t, resp.Header.Get("Location"))

	encodedResponse := acsForm.Get("SAMLResponse")
	rawResponse, err := base64.StdEncoding.DecodeString(encodedResponse)
	if err != nil {
		t.Fatalf("DecodeString(SAMLResponse): %v", err)
	}
	rawResponse[len(rawResponse)-8] ^= 0x01
	acsForm.Set("SAMLResponse", base64.StdEncoding.EncodeToString(rawResponse))

	resp = submitHTMLForm(t, browserClient, acsAction, acsForm)
	if resp.StatusCode != http.StatusUnauthorized {
		body := string(mustReadBody(t, resp))
		t.Fatalf("tampered SAML ACS status = %d body = %s", resp.StatusCode, body)
	}
	body := string(mustReadBody(t, resp))
	if !strings.Contains(body, "SAML authentication failed") {
		t.Fatalf("tampered SAML ACS body missing error message: %s", body)
	}

	resp = mustRequest(t, browserClient, http.MethodGet, controlTS.URL+"/api/v1/auth/me", nil, nil)
	if resp.StatusCode != http.StatusUnauthorized {
		body := string(mustReadBody(t, resp))
		t.Fatalf("expected no authenticated session after tampered assertion, got %d body = %s", resp.StatusCode, body)
	}
}

type testSAMLIdentityProvider struct {
	server           *httptest.Server
	serviceMetadata  string
	identityProvider *crewsaml.IdentityProvider
	session          *crewsaml.Session
}

func newTestSAMLIdentityProvider(t *testing.T, serviceMetadataURL string) *testSAMLIdentityProvider {
	t.Helper()

	idpKey, idpCert := generateTestCertificate(t, "idp.local")
	idp := &testSAMLIdentityProvider{
		serviceMetadata: serviceMetadataURL,
		session: &crewsaml.Session{
			ID:             "sess-1",
			CreateTime:     time.Now().Add(-time.Minute),
			ExpireTime:     time.Now().Add(time.Hour),
			Index:          "sess-idx-1",
			NameID:         "alice@example.com",
			UserName:       "alice",
			UserEmail:      "alice@example.com",
			UserCommonName: "Alice Example",
			Groups:         []string{"Operators"},
		},
	}

	mux := http.NewServeMux()
	idp.server = httptest.NewServer(mux)
	t.Cleanup(idp.server.Close)

	idp.identityProvider = &crewsaml.IdentityProvider{
		Key:             idpKey,
		Signer:          idpKey,
		Certificate:     idpCert,
		MetadataURL:     mustParseURL(t, idp.server.URL+"/metadata"),
		SSOURL:          mustParseURL(t, idp.server.URL+"/sso"),
		SignatureMethod: dsig.RSASHA256SignatureMethod,
		ServiceProviderProvider: serviceProviderProviderFunc(func(r *http.Request, serviceProviderID string) (*crewsaml.EntityDescriptor, error) {
			metadata := fetchServiceProviderMetadata(t, serviceMetadataURL)
			if metadata.EntityID != serviceProviderID {
				return nil, os.ErrNotExist
			}
			return metadata, nil
		}),
		SessionProvider: staticSAMLSessionProvider{session: idp.session},
	}

	mux.HandleFunc("/metadata", func(w http.ResponseWriter, r *http.Request) {
		buf, err := xml.MarshalIndent(idp.identityProvider.Metadata(), "", "  ")
		if err != nil {
			t.Fatalf("xml.MarshalIndent(idp.Metadata): %v", err)
		}
		w.Header().Set("Content-Type", "application/samlmetadata+xml")
		_, _ = w.Write(buf)
	})

	return idp
}

func (i *testSAMLIdentityProvider) metadataURL() string {
	return i.server.URL + "/metadata"
}

func (i *testSAMLIdentityProvider) buildSPInitiatedForm(t *testing.T, redirectURL string) (string, url.Values) {
	t.Helper()

	req, err := http.NewRequest(http.MethodGet, redirectURL, nil)
	if err != nil {
		t.Fatalf("http.NewRequest(GET redirectURL): %v", err)
	}
	req.RemoteAddr = "127.0.0.1:12345"

	idpReq, err := crewsaml.NewIdpAuthnRequest(i.identityProvider, req)
	if err != nil {
		t.Fatalf("NewIdpAuthnRequest(): %v", err)
	}
	if err := idpReq.Validate(); err != nil {
		t.Fatalf("Validate() SP-initiated request: %v", err)
	}
	if err := (crewsaml.DefaultAssertionMaker{}).MakeAssertion(idpReq, i.session); err != nil {
		t.Fatalf("MakeAssertion() SP-initiated: %v", err)
	}
	form, err := idpReq.PostBinding()
	if err != nil {
		t.Fatalf("PostBinding() SP-initiated: %v", err)
	}
	return form.URL, url.Values{
		"SAMLResponse": {form.SAMLResponse},
		"RelayState":   {form.RelayState},
	}
}

func (i *testSAMLIdentityProvider) buildIDPInitiatedForm(t *testing.T, relayState string) (string, url.Values) {
	t.Helper()

	metadata := fetchServiceProviderMetadata(t, i.serviceMetadata)
	req, err := http.NewRequest(http.MethodGet, i.identityProvider.SSOURL.String(), nil)
	if err != nil {
		t.Fatalf("http.NewRequest(GET idp sso): %v", err)
	}
	req.RemoteAddr = "127.0.0.1:12345"

	idpReq := &crewsaml.IdpAuthnRequest{
		IDP:                     i.identityProvider,
		HTTPRequest:             req,
		RelayState:              relayState,
		Now:                     crewsaml.TimeNow(),
		ServiceProviderMetadata: metadata,
	}
	for _, descriptor := range metadata.SPSSODescriptors {
		for _, endpoint := range descriptor.AssertionConsumerServices {
			if endpoint.Binding != crewsaml.HTTPPostBinding {
				continue
			}
			descriptorCopy := descriptor
			endpointCopy := endpoint
			idpReq.SPSSODescriptor = &descriptorCopy
			idpReq.ACSEndpoint = &endpointCopy
			break
		}
		if idpReq.ACSEndpoint != nil {
			break
		}
	}
	if idpReq.ACSEndpoint == nil {
		t.Fatal("SP metadata did not expose an HTTP POST ACS endpoint")
	}
	if err := (crewsaml.DefaultAssertionMaker{}).MakeAssertion(idpReq, i.session); err != nil {
		t.Fatalf("MakeAssertion() IdP-initiated: %v", err)
	}
	form, err := idpReq.PostBinding()
	if err != nil {
		t.Fatalf("PostBinding() IdP-initiated: %v", err)
	}
	return form.URL, url.Values{
		"SAMLResponse": {form.SAMLResponse},
		"RelayState":   {form.RelayState},
	}
}

type serviceProviderProviderFunc func(r *http.Request, serviceProviderID string) (*crewsaml.EntityDescriptor, error)

func (f serviceProviderProviderFunc) GetServiceProvider(r *http.Request, serviceProviderID string) (*crewsaml.EntityDescriptor, error) {
	return f(r, serviceProviderID)
}

type staticSAMLSessionProvider struct {
	session *crewsaml.Session
}

func (s staticSAMLSessionProvider) GetSession(w http.ResponseWriter, r *http.Request, req *crewsaml.IdpAuthnRequest) *crewsaml.Session {
	return s.session
}

func newTestSAMLControlPlaneServer(t *testing.T, controlTS *httptest.Server, setControlHandler func(http.Handler), dataPlaneURL, metadataURL string) *config.Config {
	t.Helper()

	certPath, keyPath := writeTestKeyPairFiles(t)
	cfg := &config.Config{
		ListenAddr:            "127.0.0.1:0",
		DataPlaneAddr:         dataPlaneURL,
		DataPlaneToken:        "dp-secret-token",
		SessionSecret:         "saml-session-secret",
		AdminUser:             "admin",
		AuditLogDir:           t.TempDir(),
		RecordingDir:          t.TempDir(),
		DataDir:               t.TempDir(),
		SAMLEnabled:           true,
		SAMLRootURL:           controlTS.URL,
		SAMLIDPMetadataURL:    metadataURL,
		SAMLSPCert:            certPath,
		SAMLSPKey:             keyPath,
		SAMLRoleMappings:      map[string]string{"Operators": "operator"},
		SAMLAllowIDPInitiated: true,
	}

	srv, err := New(cfg)
	if err != nil {
		t.Fatalf("New() with SAML error = %v", err)
	}
	setControlHandler(srv.srv.Handler)
	t.Cleanup(func() {
		_ = srv.Shutdown(context.Background())
	})
	return cfg
}

func fetchServiceProviderMetadata(t *testing.T, metadataURL string) *crewsaml.EntityDescriptor {
	t.Helper()

	resp, err := http.Get(metadataURL)
	if err != nil {
		t.Fatalf("GET SP metadata: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body := string(mustReadBody(t, resp))
		t.Fatalf("GET SP metadata status = %d body = %s", resp.StatusCode, body)
	}

	var metadata crewsaml.EntityDescriptor
	if err := xml.NewDecoder(resp.Body).Decode(&metadata); err != nil {
		t.Fatalf("decode SP metadata: %v", err)
	}
	return &metadata
}

func assertAuthenticatedRole(t *testing.T, client *http.Client, baseURL, wantUser, wantRole string) {
	t.Helper()

	resp := mustRequest(t, client, http.MethodGet, baseURL+"/api/v1/auth/me", nil, nil)
	if resp.StatusCode != http.StatusOK {
		body := string(mustReadBody(t, resp))
		t.Fatalf("GET /api/v1/auth/me status = %d body = %s", resp.StatusCode, body)
	}
	body := string(mustReadBody(t, resp))
	if !strings.Contains(body, `"username":"`+wantUser+`"`) {
		t.Fatalf("auth/me body missing username %q: %s", wantUser, body)
	}
	if !strings.Contains(body, `"role":"`+wantRole+`"`) {
		t.Fatalf("auth/me body missing role %q: %s", wantRole, body)
	}
}

func newCookieJar(t *testing.T) http.CookieJar {
	t.Helper()

	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("cookiejar.New(): %v", err)
	}
	return jar
}

func newHTTPClient(jar http.CookieJar, followRedirects bool) *http.Client {
	client := &http.Client{Jar: jar}
	if !followRedirects {
		client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}
	}
	return client
}

func newDeferredServer(t *testing.T) (*httptest.Server, func(http.Handler)) {
	t.Helper()

	var (
		mu      sync.RWMutex
		handler http.Handler = http.NotFoundHandler()
	)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.RLock()
		h := handler
		mu.RUnlock()
		h.ServeHTTP(w, r)
	}))
	t.Cleanup(ts.Close)

	return ts, func(next http.Handler) {
		mu.Lock()
		handler = next
		mu.Unlock()
	}
}

func submitHTMLForm(t *testing.T, client *http.Client, action string, values url.Values) *http.Response {
	t.Helper()

	return mustRequest(t, client, http.MethodPost, action, strings.NewReader(values.Encode()), map[string]string{
		"Content-Type": "application/x-www-form-urlencoded",
	})
}

func writeTestKeyPairFiles(t *testing.T) (string, string) {
	t.Helper()

	key, cert := generateTestCertificate(t, "proxy.local")
	certPath := filepath.Join(t.TempDir(), "saml_sp.pem")
	keyPath := filepath.Join(t.TempDir(), "saml_sp.key")

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})

	if err := os.WriteFile(certPath, certPEM, 0o600); err != nil {
		t.Fatalf("write cert: %v", err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}
	return certPath, keyPath
}

func mustParseURL(t *testing.T, raw string) url.URL {
	t.Helper()

	parsed, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("url.Parse(%q): %v", raw, err)
	}
	return *parsed
}

func generateTestCertificate(t *testing.T, commonName string) (*rsa.PrivateKey, *x509.Certificate) {
	t.Helper()

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey(): %v", err)
	}
	template := &x509.Certificate{
		SerialNumber:          newSerial(t),
		Subject:               pkix.Name{CommonName: commonName},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{commonName, "localhost"},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("x509.CreateCertificate(): %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("x509.ParseCertificate(): %v", err)
	}
	return priv, cert
}

func newSerial(t *testing.T) *big.Int {
	t.Helper()

	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		t.Fatalf("rand.Int(): %v", err)
	}
	return serial
}
