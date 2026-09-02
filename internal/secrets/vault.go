package secrets

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

// VaultProvider reads a key-encryption key from HashiCorp Vault KV v2.
type VaultProvider struct {
	cfg    VaultConfig
	client *http.Client

	mu     sync.RWMutex
	keys   map[string][]byte
	active string
}

// NewVaultProvider builds a provider that fetches key material from Vault.
func NewVaultProvider(cfg VaultConfig) (*VaultProvider, error) {
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	if cfg.KeyField == "" {
		cfg.KeyField = "kek"
	}
	p := &VaultProvider{
		cfg:    cfg,
		client: &http.Client{Timeout: 10 * time.Second},
		keys:   make(map[string][]byte),
	}
	if err := p.reload(); err != nil {
		return nil, err
	}
	return p, nil
}

func (p *VaultProvider) reload() error {
	token := strings.TrimSpace(p.cfg.Token)
	if token == "" {
		token = strings.TrimSpace(os.Getenv("VAULT_TOKEN"))
	}
	if token == "" {
		return fmt.Errorf("secrets: vault token is required (spec or VAULT_TOKEN)")
	}

	path := strings.TrimPrefix(strings.TrimSpace(p.cfg.Path), "/")
	url := strings.TrimRight(p.cfg.Addr, "/") + "/v1/" + path
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("X-Vault-Token", token)

	resp, err := p.client.Do(req)
	if err != nil {
		return fmt.Errorf("secrets: vault request: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("secrets: vault returned %s: %s", resp.Status, strings.TrimSpace(string(body)))
	}

	var envelope struct {
		Data struct {
			Data map[string]string `json:"data"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &envelope); err != nil {
		return fmt.Errorf("secrets: parse vault response: %w", err)
	}

	raw := strings.TrimSpace(envelope.Data.Data[p.cfg.KeyField])
	if raw == "" {
		return fmt.Errorf("secrets: vault path %q has no %q field", p.cfg.Path, p.cfg.KeyField)
	}
	key, err := decodeKeyMaterial(raw)
	if err != nil {
		return err
	}
	id := KeyIDFor(key)
	p.mu.Lock()
	p.keys[id] = key
	p.active = id
	p.mu.Unlock()
	return nil
}

func decodeKeyMaterial(raw string) ([]byte, error) {
	if key, err := hex.DecodeString(raw); err == nil && len(key) == 32 {
		return key, nil
	}
	if key, err := base64.StdEncoding.DecodeString(raw); err == nil && len(key) == 32 {
		return key, nil
	}
	return nil, fmt.Errorf("secrets: vault key must be 32 bytes as hex or base64")
}

func (p *VaultProvider) ActiveKeyID() string {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.active
}

func (p *VaultProvider) Key(keyID string) ([]byte, error) {
	p.mu.RLock()
	key, ok := p.keys[keyID]
	p.mu.RUnlock()
	if ok {
		return key, nil
	}
	if err := p.reload(); err != nil {
		return nil, err
	}
	p.mu.RLock()
	defer p.mu.RUnlock()
	key, ok = p.keys[keyID]
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrUnknownKeyID, keyID)
	}
	return key, nil
}

func (p *VaultProvider) KeyIDs() []string {
	p.mu.RLock()
	defer p.mu.RUnlock()
	ids := make([]string, 0, len(p.keys))
	for id := range p.keys {
		ids = append(ids, id)
	}
	return ids
}
