package operator

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type HTTPClient struct {
	BaseURL    string
	Token      string
	HTTPClient *http.Client
}

func NewHTTPClient(baseURL, token string, client *http.Client) *HTTPClient {
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	return &HTTPClient{
		BaseURL:    strings.TrimRight(baseURL, "/"),
		Token:      strings.TrimSpace(token),
		HTTPClient: client,
	}
}

func (c *HTTPClient) EnsureCRD(ctx context.Context) error {
	return c.Apply(ctx, CRDObject())
}

func (c *HTTPClient) ListClusters(ctx context.Context, namespace string) ([]SSHProxyCluster, error) {
	var list SSHProxyClusterList
	path := fmt.Sprintf("/apis/%s/%s/namespaces/%s/%s", Group, Version, namespace, Plural)
	if err := c.doJSON(ctx, http.MethodGet, path, "application/json", nil, &list); err != nil {
		return nil, err
	}
	return list.Items, nil
}

func (c *HTTPClient) Apply(ctx context.Context, obj map[string]interface{}) error {
	path, err := resourcePathForObject(obj)
	if err != nil {
		return err
	}
	query := url.Values{}
	query.Set("fieldManager", FieldManager)
	query.Set("force", "true")
	if strings.Contains(path, "?") {
		path += "&" + query.Encode()
	} else {
		path += "?" + query.Encode()
	}
	return c.doJSON(ctx, http.MethodPatch, path, "application/apply-patch+yaml", obj, nil)
}

func (c *HTTPClient) UpdateStatus(ctx context.Context, namespace, name string, status SSHProxyClusterStatus) error {
	body := map[string]interface{}{
		"status": status,
	}
	path := fmt.Sprintf("/apis/%s/%s/namespaces/%s/%s/%s/status", Group, Version, namespace, Plural, name)
	return c.doJSON(ctx, http.MethodPatch, path, "application/merge-patch+json", body, nil)
}

func (c *HTTPClient) doJSON(ctx context.Context, method, path, contentType string, body interface{}, out interface{}) error {
	if c == nil || c.HTTPClient == nil {
		return fmt.Errorf("http client is required")
	}
	var reader io.Reader
	if body != nil {
		payload, err := json.Marshal(body)
		if err != nil {
			return err
		}
		reader = bytes.NewReader(payload)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.BaseURL+path, reader)
	if err != nil {
		return err
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	req.Header.Set("Accept", "application/json")
	if c.Token != "" {
		req.Header.Set("Authorization", "Bearer "+c.Token)
	}
	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("kubernetes api %s %s: HTTP %d: %s", method, path, resp.StatusCode, strings.TrimSpace(string(data)))
	}
	if out != nil && len(data) > 0 {
		if err := json.Unmarshal(data, out); err != nil {
			return err
		}
	}
	return nil
}

func resourcePathForObject(obj map[string]interface{}) (string, error) {
	apiVersion, _ := obj["apiVersion"].(string)
	kind, _ := obj["kind"].(string)
	meta, _ := obj["metadata"].(map[string]interface{})
	name, _ := meta["name"].(string)
	namespace, _ := meta["namespace"].(string)
	if apiVersion == "" || kind == "" || name == "" {
		return "", fmt.Errorf("apiVersion, kind, and metadata.name are required")
	}
	switch {
	case apiVersion == "apiextensions.k8s.io/v1" && kind == "CustomResourceDefinition":
		return "/apis/apiextensions.k8s.io/v1/customresourcedefinitions/" + name, nil
	case apiVersion == "v1" && kind == "ServiceAccount":
		return fmt.Sprintf("/api/v1/namespaces/%s/serviceaccounts/%s", namespace, name), nil
	case apiVersion == "v1" && kind == "ConfigMap":
		return fmt.Sprintf("/api/v1/namespaces/%s/configmaps/%s", namespace, name), nil
	case apiVersion == "v1" && kind == "Secret":
		return fmt.Sprintf("/api/v1/namespaces/%s/secrets/%s", namespace, name), nil
	case apiVersion == "v1" && kind == "Service":
		return fmt.Sprintf("/api/v1/namespaces/%s/services/%s", namespace, name), nil
	case apiVersion == "v1" && kind == "PersistentVolumeClaim":
		return fmt.Sprintf("/api/v1/namespaces/%s/persistentvolumeclaims/%s", namespace, name), nil
	case apiVersion == "apps/v1" && kind == "Deployment":
		return fmt.Sprintf("/apis/apps/v1/namespaces/%s/deployments/%s", namespace, name), nil
	default:
		return "", fmt.Errorf("unsupported object %s %s", apiVersion, kind)
	}
}
