package discovery

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// Asset represents a discovered network host that may be an SSH server.
type Asset struct {
	ID           string            `json:"id"`
	Host         string            `json:"host"`
	Port         int               `json:"port"`
	Name         string            `json:"name"`
	SSHVersion   string            `json:"ssh_version"`
	HostKey      string            `json:"host_key"`
	OS           string            `json:"os"`
	Tags         map[string]string `json:"tags"`
	Status       string            `json:"status"` // "discovered", "registered", "offline"
	FirstSeen    time.Time         `json:"first_seen"`
	LastSeen     time.Time         `json:"last_seen"`
	AutoRegister bool              `json:"auto_register"`
}

// AssetFilter specifies optional filters when listing assets.
type AssetFilter struct {
	Status string
	Host   string
	OS     string
	Tag    string // "key=value"
}

// AssetUpdate holds the mutable fields that can be changed on an asset.
type AssetUpdate struct {
	Name         *string           `json:"name,omitempty"`
	Tags         map[string]string `json:"tags,omitempty"`
	AutoRegister *bool             `json:"auto_register,omitempty"`
	Status       *string           `json:"status,omitempty"`
}

// Inventory manages a set of discovered assets, backed by a JSON file in
// dataDir.
type Inventory struct {
	assets  map[string]*Asset
	mu      sync.RWMutex
	dataDir string
}

// NewInventory creates or loads an inventory persisted in dataDir.
func NewInventory(dataDir string) *Inventory {
	inv := &Inventory{
		assets:  make(map[string]*Asset),
		dataDir: dataDir,
	}
	_ = os.MkdirAll(dataDir, 0755)
	inv.load()
	return inv
}

// assetKey returns a deterministic identifier for a host:port pair.
func assetKey(host string, port int) string {
	return fmt.Sprintf("%s:%d", host, port)
}

// AddFromScan merges scan results into the inventory, adding new assets and
// updating existing ones. It returns the number of newly added assets.
func (inv *Inventory) AddFromScan(results []ScanResult) int {
	inv.mu.Lock()
	defer inv.mu.Unlock()

	newCount := 0
	for _, r := range results {
		if r.Status != "open" {
			continue
		}

		key := assetKey(r.Host, r.Port)
		now := time.Now().UTC()

		if existing, ok := inv.assets[key]; ok {
			// Update existing asset.
			existing.LastSeen = now
			if r.SSHVersion != "" {
				existing.SSHVersion = r.SSHVersion
			}
			if r.HostKey != "" {
				existing.HostKey = r.HostKey
			}
			if r.OS != "" {
				existing.OS = r.OS
			}
			if existing.Status == "offline" {
				existing.Status = "discovered"
			}
			continue
		}

		// New asset.
		a := &Asset{
			ID:        key,
			Host:      r.Host,
			Port:      r.Port,
			Name:      fmt.Sprintf("%s:%d", r.Host, r.Port),
			SSHVersion: r.SSHVersion,
			HostKey:   r.HostKey,
			OS:        r.OS,
			Tags:      make(map[string]string),
			Status:    "discovered",
			FirstSeen: now,
			LastSeen:  now,
		}
		inv.assets[key] = a
		newCount++
	}
	return newCount
}

// List returns assets matching the given filter, sorted by ID.
func (inv *Inventory) List(filter AssetFilter) []*Asset {
	inv.mu.RLock()
	defer inv.mu.RUnlock()

	var result []*Asset
	for _, a := range inv.assets {
		if filter.Status != "" && a.Status != filter.Status {
			continue
		}
		if filter.Host != "" && !strings.Contains(a.Host, filter.Host) {
			continue
		}
		if filter.OS != "" && !strings.EqualFold(a.OS, filter.OS) {
			continue
		}
		if filter.Tag != "" {
			parts := strings.SplitN(filter.Tag, "=", 2)
			if len(parts) == 2 {
				if v, ok := a.Tags[parts[0]]; !ok || v != parts[1] {
					continue
				}
			}
		}
		// Return a copy to avoid races.
		cp := *a
		result = append(result, &cp)
	}

	sort.Slice(result, func(i, j int) bool { return result[i].ID < result[j].ID })
	return result
}

// Get returns a single asset by ID.
func (inv *Inventory) Get(id string) (*Asset, error) {
	inv.mu.RLock()
	defer inv.mu.RUnlock()

	a, ok := inv.assets[id]
	if !ok {
		return nil, fmt.Errorf("asset %q not found", id)
	}
	cp := *a
	return &cp, nil
}

// Update applies partial updates to the asset identified by id.
func (inv *Inventory) Update(id string, update AssetUpdate) error {
	inv.mu.Lock()
	defer inv.mu.Unlock()

	a, ok := inv.assets[id]
	if !ok {
		return fmt.Errorf("asset %q not found", id)
	}

	if update.Name != nil {
		a.Name = *update.Name
	}
	if update.Tags != nil {
		a.Tags = update.Tags
	}
	if update.AutoRegister != nil {
		a.AutoRegister = *update.AutoRegister
	}
	if update.Status != nil {
		a.Status = *update.Status
	}
	return nil
}

// Delete removes an asset from the inventory.
func (inv *Inventory) Delete(id string) error {
	inv.mu.Lock()
	defer inv.mu.Unlock()

	if _, ok := inv.assets[id]; !ok {
		return fmt.Errorf("asset %q not found", id)
	}
	delete(inv.assets, id)
	return nil
}

// Count returns the total number of assets.
func (inv *Inventory) Count() int {
	inv.mu.RLock()
	defer inv.mu.RUnlock()
	return len(inv.assets)
}

// AutoRegister marks all "discovered" assets with AutoRegister==true as
// "registered". The dpClient parameter is accepted as interface{} for
// loose coupling with the data-plane client. Returns the number of assets
// registered.
func (inv *Inventory) AutoRegister(dpClient interface{}) (int, error) {
	inv.mu.Lock()
	defer inv.mu.Unlock()

	registered := 0
	for _, a := range inv.assets {
		if a.Status == "discovered" && a.AutoRegister {
			a.Status = "registered"
			registered++
		}
	}
	return registered, nil
}

// MarkOffline sets all assets whose LastSeen is before cutoff to "offline".
func (inv *Inventory) MarkOffline(cutoff time.Time) int {
	inv.mu.Lock()
	defer inv.mu.Unlock()

	count := 0
	for _, a := range inv.assets {
		if a.LastSeen.Before(cutoff) && a.Status != "offline" {
			a.Status = "offline"
			count++
		}
	}
	return count
}

// Save persists the inventory to disk.
func (inv *Inventory) Save() error {
	inv.mu.RLock()
	defer inv.mu.RUnlock()

	assets := make([]*Asset, 0, len(inv.assets))
	for _, a := range inv.assets {
		assets = append(assets, a)
	}
	sort.Slice(assets, func(i, j int) bool { return assets[i].ID < assets[j].ID })

	data, err := json.MarshalIndent(assets, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal inventory: %w", err)
	}
	return os.WriteFile(inv.filePath(), data, 0644)
}

// load reads the inventory from disk. Errors are silently ignored (the
// inventory starts empty).
func (inv *Inventory) load() {
	data, err := os.ReadFile(inv.filePath())
	if err != nil {
		return
	}
	var assets []*Asset
	if err := json.Unmarshal(data, &assets); err != nil {
		return
	}
	for _, a := range assets {
		if a.Tags == nil {
			a.Tags = make(map[string]string)
		}
		inv.assets[a.ID] = a
	}
}

func (inv *Inventory) filePath() string {
	return filepath.Join(inv.dataDir, "inventory.json")
}
