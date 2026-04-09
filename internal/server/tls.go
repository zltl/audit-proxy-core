package server

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"path/filepath"
	"strings"
	"time"

	"github.com/ssh-proxy-core/ssh-proxy-core/internal/config"
	"golang.org/x/crypto/acme/autocert"
)

func buildRuntimeTLSConfig(cfg *config.Config) (*tls.Config, error) {
	if cfg == nil {
		return nil, nil
	}
	if cfg.TLSSelfSigned {
		return buildSelfSignedTLSConfig(cfg)
	}
	if cfg.TLSLetsEncrypt {
		return buildLetsEncryptTLSConfig(cfg)
	}
	return nil, nil
}

func buildSelfSignedTLSConfig(cfg *config.Config) (*tls.Config, error) {
	cert, err := generateSelfSignedCertificate(resolveSelfSignedHosts(cfg))
	if err != nil {
		return nil, fmt.Errorf("server: self-signed tls: %w", err)
	}
	return &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{cert},
	}, nil
}

func buildLetsEncryptTLSConfig(cfg *config.Config) (*tls.Config, error) {
	hosts := splitCSV(cfg.TLSLetsEncryptHosts)
	if len(hosts) == 0 {
		return nil, fmt.Errorf("server: tls_lets_encrypt_hosts is required")
	}

	cacheDir := cfg.TLSLetsEncryptCacheDir
	if cacheDir == "" {
		cacheDir = filepath.Join(cfg.DataDir, "acme-cache")
	}

	manager := &autocert.Manager{
		Prompt:     autocert.AcceptTOS,
		HostPolicy: autocert.HostWhitelist(hosts...),
		Cache:      autocert.DirCache(cacheDir),
	}
	tlsCfg := manager.TLSConfig()
	tlsCfg.MinVersion = tls.VersionTLS12
	return tlsCfg, nil
}

func resolveSelfSignedHosts(cfg *config.Config) []string {
	hosts := splitCSV(cfg.TLSSelfSignedHosts)
	if len(hosts) > 0 {
		return hosts
	}

	host := cfg.ListenAddr
	if parsedHost, _, err := net.SplitHostPort(cfg.ListenAddr); err == nil {
		host = parsedHost
	}
	if host != "" && host != "0.0.0.0" && host != "::" && host != "[::]" {
		hosts = append(hosts, strings.Trim(host, "[]"))
	}
	hosts = append(hosts, "localhost", "127.0.0.1", "::1")
	return uniqueStrings(hosts)
}

func splitCSV(value string) []string {
	if strings.TrimSpace(value) == "" {
		return nil
	}

	parts := strings.Split(value, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(strings.Trim(part, "[]"))
		if part == "" {
			continue
		}
		out = append(out, part)
	}
	return uniqueStrings(out)
}

func uniqueStrings(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, value := range values {
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	return out
}

func generateSelfSignedCertificate(hosts []string) (tls.Certificate, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("generate key: %w", err)
	}

	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("generate serial: %w", err)
	}

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   firstHost(hosts),
			Organization: []string{"SSH Proxy Core Self-Signed"},
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(90 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	for _, host := range hosts {
		if ip := net.ParseIP(host); ip != nil {
			template.IPAddresses = append(template.IPAddresses, ip)
			continue
		}
		template.DNSNames = append(template.DNSNames, host)
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("create certificate: %w", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("marshal key: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("load key pair: %w", err)
	}
	return cert, nil
}

func firstHost(hosts []string) string {
	if len(hosts) == 0 {
		return "localhost"
	}
	return hosts[0]
}
