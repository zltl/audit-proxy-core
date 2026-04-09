package cluster

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
)

func validateTLSConfig(cfg *ClusterConfig) error {
	if cfg == nil || !cfg.mtlsEnabled() {
		return nil
	}
	if cfg.TLSCert == "" || cfg.TLSKey == "" || cfg.TLSCA == "" {
		return fmt.Errorf("cluster: tls_cert, tls_key, and tls_ca must all be set for mTLS")
	}
	return nil
}

func buildServerTLSConfig(cfg *ClusterConfig) (*tls.Config, error) {
	if cfg == nil || !cfg.mtlsEnabled() {
		return nil, nil
	}

	cert, pool, err := loadClusterTLSMaterial(cfg)
	if err != nil {
		return nil, err
	}

	return &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    pool,
	}, nil
}

func buildClientTLSConfig(cfg *ClusterConfig) (*tls.Config, error) {
	if cfg == nil || !cfg.mtlsEnabled() {
		return nil, nil
	}

	cert, pool, err := loadClusterTLSMaterial(cfg)
	if err != nil {
		return nil, err
	}

	return &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{cert},
		RootCAs:      pool,
	}, nil
}

func loadClusterTLSMaterial(cfg *ClusterConfig) (tls.Certificate, *x509.CertPool, error) {
	cert, err := tls.LoadX509KeyPair(cfg.TLSCert, cfg.TLSKey)
	if err != nil {
		return tls.Certificate{}, nil, fmt.Errorf("cluster: load tls key pair: %w", err)
	}

	caPEM, err := os.ReadFile(cfg.TLSCA)
	if err != nil {
		return tls.Certificate{}, nil, fmt.Errorf("cluster: read tls ca: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return tls.Certificate{}, nil, fmt.Errorf("cluster: parse tls ca bundle")
	}

	return cert, pool, nil
}

func clusterBaseURL(cfg *ClusterConfig, addr string) string {
	scheme := "http"
	if cfg != nil && cfg.mtlsEnabled() {
		scheme = "https"
	}
	return scheme + "://" + addr
}
