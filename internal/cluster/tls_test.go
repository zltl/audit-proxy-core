package cluster

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestNewManagerRejectsPartialMTLSConfig(t *testing.T) {
	_, err := NewManager(&ClusterConfig{
		NodeID:   "node-1",
		BindAddr: "127.0.0.1:0",
		TLSCert:  "/tmp/cert.pem",
	})
	if err == nil || !strings.Contains(err.Error(), "tls_cert, tls_key, and tls_ca") {
		t.Fatalf("NewManager(partial mTLS) = %v, want cluster tls error", err)
	}
}

func TestClusterMTLSJoinAndStatus(t *testing.T) {
	artifacts := writeClusterTLSArtifacts(t)

	cfg1 := testConfig("node-1", "Node 1", "127.0.0.1:0")
	cfg1.TLSCert = artifacts.certPath
	cfg1.TLSKey = artifacts.keyPath
	cfg1.TLSCA = artifacts.caPath
	m1 := startManager(t, cfg1)

	cfg2 := testConfig("node-2", "Node 2", "127.0.0.1:0")
	cfg2.Seeds = []string{m1.Self().Address}
	cfg2.TLSCert = artifacts.certPath
	cfg2.TLSKey = artifacts.keyPath
	cfg2.TLSCA = artifacts.caPath
	m2 := startManager(t, cfg2)

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if m1.NodeCount() == 2 && m2.NodeCount() == 2 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if m1.NodeCount() != 2 || m2.NodeCount() != 2 {
		t.Fatalf("expected both managers to see 2 nodes, got %d and %d", m1.NodeCount(), m2.NodeCount())
	}

	clientCert, err := tls.LoadX509KeyPair(artifacts.certPath, artifacts.keyPath)
	if err != nil {
		t.Fatalf("LoadX509KeyPair() error = %v", err)
	}
	caPEM, err := os.ReadFile(artifacts.caPath)
	if err != nil {
		t.Fatalf("ReadFile(ca) error = %v", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		t.Fatal("AppendCertsFromPEM() failed")
	}

	statusClient := &http.Client{
		Timeout: 2 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				MinVersion:   tls.VersionTLS12,
				RootCAs:      pool,
				Certificates: []tls.Certificate{clientCert},
			},
		},
	}
	resp, err := statusClient.Get(clusterBaseURL(cfg1, m1.Self().Address) + "/cluster/status")
	if err != nil {
		t.Fatalf("GET /cluster/status over mTLS: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /cluster/status status = %d, want 200", resp.StatusCode)
	}
}

func TestClusterMTLSRequiresClientCertificate(t *testing.T) {
	artifacts := writeClusterTLSArtifacts(t)

	cfg := testConfig("node-1", "Node 1", "127.0.0.1:0")
	cfg.TLSCert = artifacts.certPath
	cfg.TLSKey = artifacts.keyPath
	cfg.TLSCA = artifacts.caPath
	m := startManager(t, cfg)

	caPEM, err := os.ReadFile(artifacts.caPath)
	if err != nil {
		t.Fatalf("ReadFile(ca) error = %v", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		t.Fatal("AppendCertsFromPEM() failed")
	}

	client := &http.Client{
		Timeout: 2 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				MinVersion: tls.VersionTLS12,
				RootCAs:    pool,
			},
		},
	}
	if _, err := client.Get(clusterBaseURL(cfg, m.Self().Address) + "/cluster/status"); err == nil {
		t.Fatal("GET /cluster/status without client certificate unexpectedly succeeded")
	}
}

type clusterTLSArtifacts struct {
	caPath   string
	certPath string
	keyPath  string
}

func writeClusterTLSArtifacts(t *testing.T) clusterTLSArtifacts {
	t.Helper()

	caCertPEM, caKey, caCert := generateClusterCA(t)
	certPEM, keyPEM := generateClusterLeaf(t, caKey, caCert)

	dir := t.TempDir()
	artifacts := clusterTLSArtifacts{
		caPath:   filepath.Join(dir, "cluster-ca.pem"),
		certPath: filepath.Join(dir, "cluster-cert.pem"),
		keyPath:  filepath.Join(dir, "cluster-key.pem"),
	}
	if err := os.WriteFile(artifacts.caPath, caCertPEM, 0o600); err != nil {
		t.Fatalf("WriteFile(ca) error = %v", err)
	}
	if err := os.WriteFile(artifacts.certPath, certPEM, 0o600); err != nil {
		t.Fatalf("WriteFile(cert) error = %v", err)
	}
	if err := os.WriteFile(artifacts.keyPath, keyPEM, 0o600); err != nil {
		t.Fatalf("WriteFile(key) error = %v", err)
	}
	return artifacts
}

func generateClusterCA(t *testing.T) ([]byte, *ecdsa.PrivateKey, *x509.Certificate) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey(ca) error = %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "ssh-proxy-cluster-test-ca",
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("CreateCertificate(ca) error = %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("ParseCertificate(ca) error = %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), key, cert
}

func generateClusterLeaf(t *testing.T, caKey *ecdsa.PrivateKey, caCert *x509.Certificate) ([]byte, []byte) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey(leaf) error = %v", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 62))
	if err != nil {
		t.Fatalf("rand.Int(leaf) error = %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName: "127.0.0.1",
		},
		NotBefore:   time.Now().Add(-time.Hour),
		NotAfter:    time.Now().Add(24 * time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
		DNSNames:    []string{"localhost"},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, caCert, &key.PublicKey, caKey)
	if err != nil {
		t.Fatalf("CreateCertificate(leaf) error = %v", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("MarshalECPrivateKey(leaf) error = %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
}

func TestClusterBaseURLUsesHTTPSForMTLS(t *testing.T) {
	cfg := &ClusterConfig{TLSCert: "cert.pem", TLSKey: "key.pem", TLSCA: "ca.pem"}
	if got := clusterBaseURL(cfg, "127.0.0.1:9444"); got != "https://127.0.0.1:9444" {
		t.Fatalf("clusterBaseURL() = %q", got)
	}
}
