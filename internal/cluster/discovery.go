package cluster

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

type hostResolver interface {
	LookupHost(ctx context.Context, host string) ([]string, error)
}

type defaultHostResolver struct{}

func (defaultHostResolver) LookupHost(ctx context.Context, host string) ([]string, error) {
	return net.DefaultResolver.LookupHost(ctx, host)
}

// ValidateSeedReference validates a static seed address or a discovery URI.
func ValidateSeedReference(seed string) error {
	_, _, err := parseSeedReference(seed)
	return err
}

func resolveSeedReferences(ctx context.Context, seeds []string) ([]string, error) {
	return resolveSeedReferencesWith(ctx, seeds, defaultHostResolver{}, &http.Client{Timeout: 2 * time.Second})
}

func resolveSeedReferencesWith(ctx context.Context, seeds []string, resolver hostResolver,
	client *http.Client) ([]string, error) {
	if len(seeds) == 0 {
		return nil, nil
	}
	if resolver == nil {
		resolver = defaultHostResolver{}
	}
	if client == nil {
		client = &http.Client{Timeout: 2 * time.Second}
	}

	seen := make(map[string]struct{})
	resolved := make([]string, 0, len(seeds))
	errs := make([]string, 0)
	for _, seed := range seeds {
		addresses, err := resolveSeedReferenceWith(ctx, seed, resolver, client)
		if err != nil {
			errs = append(errs, fmt.Sprintf("%s: %v", seed, err))
			continue
		}
		for _, addr := range addresses {
			if _, ok := seen[addr]; ok {
				continue
			}
			seen[addr] = struct{}{}
			resolved = append(resolved, addr)
		}
	}
	if len(resolved) > 0 {
		return resolved, nil
	}
	if len(errs) == 0 {
		return nil, fmt.Errorf("cluster: no seed addresses configured")
	}
	return nil, fmt.Errorf("cluster: could not resolve any seed: %s", strings.Join(errs, "; "))
}

func resolveSeedReferenceWith(ctx context.Context, seed string, resolver hostResolver,
	client *http.Client) ([]string, error) {
	ref, parsed, err := parseSeedReference(seed)
	if err != nil {
		return nil, err
	}

	switch ref.kind {
	case "static":
		return []string{ref.address}, nil
	case "dns":
		return resolveHostLookup(ctx, resolver, ref.host, ref.port)
	case "k8s":
		host := normalizeKubernetesHost(ref.host, parsed.Query().Get("cluster_domain"))
		return resolveHostLookup(ctx, resolver, host, ref.port)
	case "consul", "consuls":
		return resolveConsulSeed(ctx, client, ref, parsed)
	default:
		return nil, fmt.Errorf("unsupported seed kind %q", ref.kind)
	}
}

type seedReference struct {
	kind    string
	address string
	host    string
	port    string
	service string
}

func parseSeedReference(seed string) (*seedReference, *url.URL, error) {
	trimmed := strings.TrimSpace(seed)
	if trimmed == "" {
		return nil, nil, fmt.Errorf("seed reference is empty")
	}
	if !strings.Contains(trimmed, "://") {
		if _, _, err := net.SplitHostPort(trimmed); err != nil {
			return nil, nil, fmt.Errorf("static seed must be host:port: %w", err)
		}
		return &seedReference{kind: "static", address: trimmed}, nil, nil
	}

	parsed, err := url.Parse(trimmed)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid seed URI: %w", err)
	}
	ref := &seedReference{kind: parsed.Scheme, host: parsed.Hostname(), port: parsed.Port()}
	switch parsed.Scheme {
	case "dns", "k8s":
		if ref.host == "" || ref.port == "" {
			return nil, nil, fmt.Errorf("%s seed must include host and port", parsed.Scheme)
		}
	case "consul", "consuls":
		if parsed.Host == "" {
			return nil, nil, fmt.Errorf("%s seed must include the Consul host", parsed.Scheme)
		}
		ref.service = strings.Trim(strings.TrimPrefix(parsed.Path, "/"), " ")
		if ref.service == "" {
			return nil, nil, fmt.Errorf("%s seed must include /<service-name>", parsed.Scheme)
		}
	default:
		return nil, nil, fmt.Errorf("unsupported seed scheme %q", parsed.Scheme)
	}
	return ref, parsed, nil
}

func resolveHostLookup(ctx context.Context, resolver hostResolver, host, port string) ([]string, error) {
	addresses, err := resolver.LookupHost(ctx, host)
	if err != nil {
		return nil, fmt.Errorf("lookup host %s: %w", host, err)
	}
	if len(addresses) == 0 {
		return nil, fmt.Errorf("lookup host %s: no addresses found", host)
	}

	resolved := make([]string, 0, len(addresses))
	for _, addr := range addresses {
		resolved = append(resolved, net.JoinHostPort(addr, port))
	}
	return resolved, nil
}

func normalizeKubernetesHost(host, clusterDomain string) string {
	host = strings.TrimSpace(host)
	if host == "" {
		return ""
	}
	if clusterDomain == "" {
		clusterDomain = "cluster.local"
	}
	if strings.Contains(host, ".svc.") {
		return host
	}
	if strings.HasSuffix(host, ".svc") {
		return host + "." + clusterDomain
	}
	if strings.Count(host, ".") == 1 {
		return host + ".svc." + clusterDomain
	}
	return host
}

func resolveConsulSeed(ctx context.Context, client *http.Client, ref *seedReference,
	parsed *url.URL) ([]string, error) {
	query := parsed.Query()
	passing := strings.TrimSpace(query.Get("passing"))
	includePassing := passing == "" || passing == "1" || strings.EqualFold(passing, "true")
	if passing != "" && !includePassing && passing != "0" && !strings.EqualFold(passing, "false") {
		return nil, fmt.Errorf("invalid passing=%q", passing)
	}

	apiScheme := "http"
	if ref.kind == "consuls" {
		apiScheme = "https"
	}

	reqURL := &url.URL{
		Scheme: apiScheme,
		Host:   parsed.Host,
		Path:   "/v1/health/service/" + url.PathEscape(ref.service),
	}
	reqQuery := url.Values{}
	if includePassing {
		reqQuery.Set("passing", "1")
	}
	if tag := strings.TrimSpace(query.Get("tag")); tag != "" {
		reqQuery.Set("tag", tag)
	}
	reqURL.RawQuery = reqQuery.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("build Consul request: %w", err)
	}
	if token := strings.TrimSpace(query.Get("token")); token != "" {
		req.Header.Set("X-Consul-Token", token)
	} else if envToken := strings.TrimSpace(os.Getenv("CONSUL_HTTP_TOKEN")); envToken != "" {
		req.Header.Set("X-Consul-Token", envToken)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("query Consul service %s: %w", ref.service, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= http.StatusMultipleChoices {
		return nil, fmt.Errorf("query Consul service %s: status %d", ref.service, resp.StatusCode)
	}

	var entries []struct {
		Node struct {
			Address string `json:"Address"`
		} `json:"Node"`
		Service struct {
			Address string `json:"Address"`
			Port    int    `json:"Port"`
		} `json:"Service"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&entries); err != nil {
		return nil, fmt.Errorf("decode Consul response: %w", err)
	}

	overridePort := 0
	if rawPort := strings.TrimSpace(query.Get("port")); rawPort != "" {
		value, err := strconv.Atoi(rawPort)
		if err != nil || value <= 0 {
			return nil, fmt.Errorf("invalid port=%q", rawPort)
		}
		overridePort = value
	}

	addresses := make([]string, 0, len(entries))
	for _, entry := range entries {
		host := strings.TrimSpace(entry.Service.Address)
		if host == "" {
			host = strings.TrimSpace(entry.Node.Address)
		}
		port := entry.Service.Port
		if port == 0 {
			port = overridePort
		}
		if host == "" || port <= 0 {
			continue
		}
		addresses = append(addresses, net.JoinHostPort(host, strconv.Itoa(port)))
	}
	if len(addresses) == 0 {
		return nil, fmt.Errorf("query Consul service %s: no instances returned", ref.service)
	}
	return addresses, nil
}
