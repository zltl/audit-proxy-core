package secrets

import (
	"fmt"
	"strings"
)

// LoadProvider resolves key material from a specification string.
//
// Supported forms:
//   - 64-char hex literal
//   - file:/path/to/key
//   - vault:path=secret/data/audit-proxy;addr=https://vault:8200;key=kek (token from VAULT_TOKEN)
func LoadProvider(spec string) (Provider, error) {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return nil, ErrNoKey
	}
	if strings.HasPrefix(spec, "vault:") {
		return NewVaultProvider(parseVaultSpec(spec[len("vault:"):]))
	}
	return LoadStaticProvider(spec)
}

func parseVaultSpec(spec string) VaultConfig {
	cfg := VaultConfig{}
	for _, part := range strings.Split(spec, ";") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		key, value, ok := strings.Cut(part, "=")
		if !ok {
			continue
		}
		switch strings.ToLower(strings.TrimSpace(key)) {
		case "addr", "address":
			cfg.Addr = strings.TrimSpace(value)
		case "path":
			cfg.Path = strings.TrimSpace(value)
		case "key", "field", "keyid":
			cfg.KeyField = strings.TrimSpace(value)
		case "token":
			cfg.Token = strings.TrimSpace(value)
		}
	}
	return cfg
}

// VaultConfig configures a HashiCorp Vault KV provider.
type VaultConfig struct {
	Addr     string
	Path     string
	KeyField string
	Token    string
}

func (c VaultConfig) validate() error {
	if strings.TrimSpace(c.Addr) == "" {
		return fmt.Errorf("secrets: vault addr is required")
	}
	if strings.TrimSpace(c.Path) == "" {
		return fmt.Errorf("secrets: vault path is required")
	}
	return nil
}
