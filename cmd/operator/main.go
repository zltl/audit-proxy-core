package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/ssh-proxy-core/ssh-proxy-core/internal/operator"
)

const (
	defaultSATokenPath = "/var/run/secrets/kubernetes.io/serviceaccount/token"
	defaultSANamespace = "/var/run/secrets/kubernetes.io/serviceaccount/namespace"
	defaultSACAPath    = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
)

func main() {
	namespace := flag.String("namespace", "", "namespace to watch for SSHProxyCluster resources")
	reconcileInterval := flag.Duration("reconcile-interval", 30*time.Second, "operator reconcile interval")
	apiServer := flag.String("api-server", "", "override Kubernetes API server base URL")
	tokenFile := flag.String("token-file", defaultSATokenPath, "service account token file")
	caFile := flag.String("ca-file", defaultSACAPath, "cluster CA file")
	insecure := flag.Bool("insecure-skip-tls-verify", false, "skip Kubernetes API TLS verification")
	flag.Parse()

	baseURL := strings.TrimSpace(*apiServer)
	if baseURL == "" {
		host := strings.TrimSpace(os.Getenv("KUBERNETES_SERVICE_HOST"))
		port := strings.TrimSpace(os.Getenv("KUBERNETES_SERVICE_PORT"))
		if host == "" || port == "" {
			log.Fatal("operator: kubernetes api server is not configured")
		}
		baseURL = fmt.Sprintf("https://%s:%s", host, port)
	}
	token, err := readOptionalFile(*tokenFile)
	if err != nil {
		log.Fatalf("operator: read token: %v", err)
	}
	if strings.TrimSpace(token) == "" {
		log.Fatal("operator: service account token is required")
	}

	watchNamespace := firstNonEmpty(*namespace, os.Getenv("POD_NAMESPACE"))
	if watchNamespace == "" {
		if ns, err := readOptionalFile(defaultSANamespace); err == nil {
			watchNamespace = strings.TrimSpace(ns)
		}
	}
	watchNamespace = firstNonEmpty(watchNamespace, operator.DefaultNamespace)

	httpClient, err := newKubernetesHTTPClient(strings.TrimSpace(*caFile), *insecure)
	if err != nil {
		log.Fatalf("operator: create kubernetes client: %v", err)
	}
	client := operator.NewHTTPClient(baseURL, token, httpClient)
	reconciler := &operator.Reconciler{
		Client:    client,
		Namespace: watchNamespace,
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	if err := reconciler.ReconcileAll(ctx); err != nil {
		log.Fatalf("operator: initial reconcile: %v", err)
	}
	ticker := time.NewTicker(*reconcileInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := reconciler.ReconcileAll(ctx); err != nil {
				log.Printf("operator: reconcile failed: %v", err)
			}
		}
	}
}

func newKubernetesHTTPClient(caPath string, insecure bool) (*http.Client, error) {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			MinVersion:         tls.VersionTLS12,
			InsecureSkipVerify: insecure,
		},
	}
	if !insecure && strings.TrimSpace(caPath) != "" {
		caData, err := os.ReadFile(filepath.Clean(caPath))
		if err != nil && !os.IsNotExist(err) {
			return nil, err
		}
		if len(caData) > 0 {
			pool := x509.NewCertPool()
			if !pool.AppendCertsFromPEM(caData) {
				return nil, fmt.Errorf("failed to parse ca file %s", caPath)
			}
			transport.TLSClientConfig.RootCAs = pool
		}
	}
	return &http.Client{
		Timeout:   30 * time.Second,
		Transport: transport,
	}, nil
}

func readOptionalFile(path string) (string, error) {
	if strings.TrimSpace(path) == "" {
		return "", nil
	}
	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		if os.IsNotExist(err) {
			return "", nil
		}
		return "", err
	}
	return string(data), nil
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			return trimmed
		}
	}
	return ""
}
