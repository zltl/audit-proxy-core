package api

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

// ConfigChangeStatus represents the lifecycle state of a pending config change.
type ConfigChangeStatus string

const (
	ConfigChangePending  ConfigChangeStatus = "pending"
	ConfigChangeApproved ConfigChangeStatus = "approved"
	ConfigChangeApplied  ConfigChangeStatus = "applied"
	ConfigChangeDenied   ConfigChangeStatus = "denied"
	ConfigChangeFailed   ConfigChangeStatus = "failed"
	ConfigChangeExpired  ConfigChangeStatus = "expired"
)

// ConfigChangeRequest represents a requested configuration change that may
// require explicit approval before it is applied to the data plane.
type ConfigChangeRequest struct {
	ID            string                 `json:"id"`
	Requester     string                 `json:"requester"`
	Payload       map[string]interface{} `json:"payload"`
	BaseVersion   string                 `json:"base_version,omitempty"`
	Status        ConfigChangeStatus     `json:"status"`
	Approver      string                 `json:"approver,omitempty"`
	CreatedAt     time.Time              `json:"created_at"`
	ExpiresAt     time.Time              `json:"expires_at,omitempty"`
	ApprovedAt    time.Time              `json:"approved_at,omitempty"`
	AppliedAt     time.Time              `json:"applied_at,omitempty"`
	DeniedAt      time.Time              `json:"denied_at,omitempty"`
	FailedAt      time.Time              `json:"failed_at,omitempty"`
	DenyReason    string                 `json:"deny_reason,omitempty"`
	FailureReason string                 `json:"failure_reason,omitempty"`
}

// ConfigChangeFilter limits config change listing results.
type ConfigChangeFilter struct {
	Status    ConfigChangeStatus
	Requester string
	Approver  string
	Since     time.Time
	Until     time.Time
}

type persistedConfigChanges struct {
	Changes []*ConfigChangeRequest `json:"changes"`
}

// ConfigChangeStore persists config change requests.
type ConfigChangeStore struct {
	mu      sync.RWMutex
	path    string
	timeout time.Duration
	changes map[string]*ConfigChangeRequest
	now     func() time.Time
}

func newConfigChangeStore(path string, timeout time.Duration) *ConfigChangeStore {
	if timeout <= 0 {
		timeout = 24 * time.Hour
	}
	s := &ConfigChangeStore{
		path:    path,
		timeout: timeout,
		changes: make(map[string]*ConfigChangeRequest),
		now:     time.Now,
	}
	s.load()
	return s
}

func generateConfigChangeID() (string, error) {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("failed to generate change id: %w", err)
	}
	return hex.EncodeToString(b), nil
}

// CreateChange validates and stores a new config change request.
func (s *ConfigChangeStore) CreateChange(requester string, payload map[string]interface{}, baseVersion string) (*ConfigChangeRequest, error) {
	if requester == "" {
		return nil, errors.New("requester is required")
	}
	if len(payload) == 0 {
		return nil, errors.New("config payload is required")
	}
	id, err := generateConfigChangeID()
	if err != nil {
		return nil, err
	}

	now := s.now().UTC()
	req := &ConfigChangeRequest{
		ID:          id,
		Requester:   requester,
		Payload:     cloneConfigPayload(payload),
		BaseVersion: baseVersion,
		Status:      ConfigChangePending,
		CreatedAt:   now,
		ExpiresAt:   now.Add(s.timeout),
	}

	s.mu.Lock()
	s.changes[req.ID] = req
	if err := s.saveLocked(); err != nil {
		delete(s.changes, req.ID)
		s.mu.Unlock()
		return nil, err
	}
	clone := cloneConfigChange(req)
	s.mu.Unlock()
	return clone, nil
}

// GetChange returns a single change request by ID.
func (s *ConfigChangeStore) GetChange(id string) (*ConfigChangeRequest, error) {
	s.mu.Lock()
	req, ok := s.changes[id]
	if !ok {
		s.mu.Unlock()
		return nil, fmt.Errorf("config change %s not found", id)
	}
	if s.expireLocked(req) {
		_ = s.saveLocked()
	}
	clone := cloneConfigChange(req)
	s.mu.Unlock()
	return clone, nil
}

// ListChanges returns all matching change requests, newest first.
func (s *ConfigChangeStore) ListChanges(filter ConfigChangeFilter) []*ConfigChangeRequest {
	s.mu.Lock()
	changed := false
	results := make([]*ConfigChangeRequest, 0, len(s.changes))
	for _, req := range s.changes {
		if s.expireLocked(req) {
			changed = true
		}
		if filter.Status != "" && req.Status != filter.Status {
			continue
		}
		if filter.Requester != "" && req.Requester != filter.Requester {
			continue
		}
		if filter.Approver != "" && req.Approver != filter.Approver {
			continue
		}
		if !filter.Since.IsZero() && req.CreatedAt.Before(filter.Since) {
			continue
		}
		if !filter.Until.IsZero() && req.CreatedAt.After(filter.Until) {
			continue
		}
		results = append(results, cloneConfigChange(req))
	}
	if changed {
		_ = s.saveLocked()
	}
	s.mu.Unlock()

	sort.Slice(results, func(i, j int) bool {
		return results[i].CreatedAt.After(results[j].CreatedAt)
	})
	return results
}

// ApproveChange marks a pending change as approved before apply.
func (s *ConfigChangeStore) ApproveChange(id, approver string) (*ConfigChangeRequest, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	req, ok := s.changes[id]
	if !ok {
		return nil, fmt.Errorf("config change %s not found", id)
	}
	if s.expireLocked(req) {
		_ = s.saveLocked()
		return nil, fmt.Errorf("config change %s has expired", id)
	}
	if req.Status != ConfigChangePending {
		return nil, fmt.Errorf("config change %s is not pending (status: %s)", id, req.Status)
	}

	prev := cloneConfigChange(req)
	now := s.now().UTC()
	req.Status = ConfigChangeApproved
	req.Approver = approver
	req.ApprovedAt = now
	req.DenyReason = ""
	req.FailureReason = ""
	req.DeniedAt = time.Time{}
	req.FailedAt = time.Time{}
	req.AppliedAt = time.Time{}
	if err := s.saveLocked(); err != nil {
		*req = *prev
		return nil, err
	}
	return cloneConfigChange(req), nil
}

// MarkApplied marks an approved change as successfully applied.
func (s *ConfigChangeStore) MarkApplied(id string) (*ConfigChangeRequest, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	req, ok := s.changes[id]
	if !ok {
		return nil, fmt.Errorf("config change %s not found", id)
	}
	if req.Status != ConfigChangeApproved {
		return nil, fmt.Errorf("config change %s is not approved (status: %s)", id, req.Status)
	}

	prev := cloneConfigChange(req)
	req.Status = ConfigChangeApplied
	req.AppliedAt = s.now().UTC()
	req.FailureReason = ""
	req.FailedAt = time.Time{}
	if err := s.saveLocked(); err != nil {
		*req = *prev
		return nil, err
	}
	return cloneConfigChange(req), nil
}

// MarkFailed marks an approved change as failed after apply.
func (s *ConfigChangeStore) MarkFailed(id, failureReason string) (*ConfigChangeRequest, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	req, ok := s.changes[id]
	if !ok {
		return nil, fmt.Errorf("config change %s not found", id)
	}
	if req.Status != ConfigChangeApproved {
		return nil, fmt.Errorf("config change %s is not approved (status: %s)", id, req.Status)
	}

	prev := cloneConfigChange(req)
	req.Status = ConfigChangeFailed
	req.FailedAt = s.now().UTC()
	req.FailureReason = failureReason
	req.AppliedAt = time.Time{}
	if err := s.saveLocked(); err != nil {
		*req = *prev
		return nil, err
	}
	return cloneConfigChange(req), nil
}

// DenyChange marks a pending change as denied.
func (s *ConfigChangeStore) DenyChange(id, approver, reason string) (*ConfigChangeRequest, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	req, ok := s.changes[id]
	if !ok {
		return nil, fmt.Errorf("config change %s not found", id)
	}
	if s.expireLocked(req) {
		_ = s.saveLocked()
		return nil, fmt.Errorf("config change %s has expired", id)
	}
	if req.Status != ConfigChangePending {
		return nil, fmt.Errorf("config change %s is not pending (status: %s)", id, req.Status)
	}

	prev := cloneConfigChange(req)
	req.Status = ConfigChangeDenied
	req.Approver = approver
	req.DeniedAt = s.now().UTC()
	req.DenyReason = reason
	if err := s.saveLocked(); err != nil {
		*req = *prev
		return nil, err
	}
	return cloneConfigChange(req), nil
}

func (s *ConfigChangeStore) expireLocked(req *ConfigChangeRequest) bool {
	if req == nil || req.Status != ConfigChangePending {
		return false
	}
	if s.now().UTC().After(req.ExpiresAt) {
		req.Status = ConfigChangeExpired
		return true
	}
	return false
}

func (s *ConfigChangeStore) saveLocked() error {
	if s.path == "" {
		return nil
	}

	data := persistedConfigChanges{
		Changes: make([]*ConfigChangeRequest, 0, len(s.changes)),
	}
	for _, req := range s.changes {
		data.Changes = append(data.Changes, cloneConfigChange(req))
	}

	raw, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(s.path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(s.path, raw, 0o600)
}

func (s *ConfigChangeStore) load() {
	if s.path == "" {
		return
	}
	raw, err := os.ReadFile(s.path)
	if err != nil {
		return
	}

	var data persistedConfigChanges
	if err := json.Unmarshal(raw, &data); err != nil {
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	for _, req := range data.Changes {
		s.changes[req.ID] = req
	}
}

func cloneConfigChange(req *ConfigChangeRequest) *ConfigChangeRequest {
	if req == nil {
		return nil
	}
	cloned := *req
	cloned.Payload = cloneConfigPayload(req.Payload)
	return &cloned
}

func cloneConfigPayload(payload map[string]interface{}) map[string]interface{} {
	if payload == nil {
		return nil
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return nil
	}
	var cloned map[string]interface{}
	if err := json.Unmarshal(raw, &cloned); err != nil {
		return nil
	}
	return cloned
}

func sanitizeConfigPayload(payload map[string]interface{}) map[string]interface{} {
	cloned := cloneConfigPayload(payload)
	if cloned == nil {
		return map[string]interface{}{}
	}
	sanitizeConfig(cloned)
	return cloned
}

func serializeConfigChange(req *ConfigChangeRequest) map[string]interface{} {
	resp := map[string]interface{}{
		"id":           req.ID,
		"requester":    req.Requester,
		"payload":      sanitizeConfigPayload(req.Payload),
		"base_version": req.BaseVersion,
		"status":       req.Status,
		"created_at":   req.CreatedAt,
		"expires_at":   req.ExpiresAt,
	}
	if req.Approver != "" {
		resp["approver"] = req.Approver
	}
	if !req.ApprovedAt.IsZero() {
		resp["approved_at"] = req.ApprovedAt
	}
	if !req.AppliedAt.IsZero() {
		resp["applied_at"] = req.AppliedAt
	}
	if !req.DeniedAt.IsZero() {
		resp["denied_at"] = req.DeniedAt
	}
	if !req.FailedAt.IsZero() {
		resp["failed_at"] = req.FailedAt
	}
	if req.DenyReason != "" {
		resp["deny_reason"] = req.DenyReason
	}
	if req.FailureReason != "" {
		resp["failure_reason"] = req.FailureReason
	}
	return resp
}

func (a *API) handleCreateConfigChange(w http.ResponseWriter, r *http.Request) {
	if !a.requireConfigLeader(w) {
		return
	}

	requester := r.Header.Get("X-User")
	if requester == "" {
		writeError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	var newConfig map[string]interface{}
	if err := readJSON(r, &newConfig); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	change, err := a.createConfigChange(requester, newConfig)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	writeJSON(w, http.StatusCreated, APIResponse{
		Success: true,
		Data:    serializeConfigChange(change),
	})
}

func (a *API) handleListConfigChanges(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	filter := ConfigChangeFilter{
		Status:    ConfigChangeStatus(q.Get("status")),
		Requester: q.Get("requester"),
		Approver:  q.Get("approver"),
	}
	if v := q.Get("since"); v != "" {
		if parsed, err := time.Parse(time.RFC3339, v); err == nil {
			filter.Since = parsed
		}
	}
	if v := q.Get("until"); v != "" {
		if parsed, err := time.Parse(time.RFC3339, v); err == nil {
			filter.Until = parsed
		}
	}

	changes := a.configChanges.ListChanges(filter)
	page, perPage := parsePagination(r)
	total := len(changes)
	start, end := paginate(total, page, perPage)

	items := make([]map[string]interface{}, 0, end-start)
	for _, change := range changes[start:end] {
		items = append(items, serializeConfigChange(change))
	}

	writeJSON(w, http.StatusOK, APIResponse{
		Success: true,
		Data:    items,
		Total:   total,
		Page:    page,
		PerPage: perPage,
	})
}

func (a *API) handleGetConfigChange(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" {
		writeError(w, http.StatusBadRequest, "missing config change id")
		return
	}

	change, err := a.configChanges.GetChange(id)
	if err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}

	diffData, err := a.buildConfigChangeDiff(change)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to build config diff: "+err.Error())
		return
	}

	writeJSON(w, http.StatusOK, APIResponse{
		Success: true,
		Data: map[string]interface{}{
			"change":       serializeConfigChange(change),
			"from_version": diffData["from_version"],
			"to_version":   diffData["to_version"],
			"changed":      diffData["changed"],
			"diff":         diffData["diff"],
		},
	})
}

func (a *API) handleApproveConfigChange(w http.ResponseWriter, r *http.Request) {
	if !a.requireConfigLeader(w) {
		return
	}

	approver := r.Header.Get("X-User")
	role := r.Header.Get("X-Role")
	if approver == "" {
		writeError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if role != "admin" {
		writeError(w, http.StatusForbidden, "admin role required")
		return
	}

	id := r.PathValue("id")
	if id == "" {
		writeError(w, http.StatusBadRequest, "missing config change id")
		return
	}

	change, err := a.configChanges.ApproveChange(id, approver)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	if err := a.applyConfigDocument(change.Payload); err != nil {
		if _, markErr := a.configChanges.MarkFailed(id, err.Error()); markErr != nil {
			writeError(w, http.StatusBadGateway, "failed to apply approved config: "+err.Error()+" (and failed to persist request failure: "+markErr.Error()+")")
			return
		}
		writeError(w, http.StatusBadGateway, "failed to apply approved config: "+err.Error())
		return
	}

	change, err = a.configChanges.MarkApplied(id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "config applied but failed to persist request state: "+err.Error())
		return
	}
	if err := a.publishCurrentConfigClusterWide(change.ID, change.Requester); err != nil {
		writeError(w, http.StatusInternalServerError, "config applied locally but failed to publish cluster sync: "+err.Error())
		return
	}

	writeJSON(w, http.StatusOK, APIResponse{
		Success: true,
		Data: map[string]interface{}{
			"change":      serializeConfigChange(change),
			"sync_status": a.clusterConfigSyncStatus(),
		},
	})
}

func (a *API) handleDenyConfigChange(w http.ResponseWriter, r *http.Request) {
	if !a.requireConfigLeader(w) {
		return
	}

	approver := r.Header.Get("X-User")
	role := r.Header.Get("X-Role")
	if approver == "" {
		writeError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if role != "admin" {
		writeError(w, http.StatusForbidden, "admin role required")
		return
	}

	id := r.PathValue("id")
	if id == "" {
		writeError(w, http.StatusBadRequest, "missing config change id")
		return
	}

	var body struct {
		Reason string `json:"reason"`
	}
	_ = readJSON(r, &body)

	change, err := a.configChanges.DenyChange(id, approver, body.Reason)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, APIResponse{
		Success: true,
		Data:    serializeConfigChange(change),
	})
}

func (a *API) createConfigChange(requester string, newConfig map[string]interface{}) (*ConfigChangeRequest, error) {
	newConfig = a.prepareConfigDocument(newConfig)
	currentSnapshot, err := a.loadCurrentConfigSnapshot()
	if err != nil {
		return nil, fmt.Errorf("failed to load current config: %w", err)
	}

	baseVersion, err := a.saveConfigVersionSnapshot(currentSnapshot)
	if err != nil {
		return nil, fmt.Errorf("failed to save config version: %w", err)
	}

	change, err := a.configChanges.CreateChange(requester, newConfig, baseVersion)
	if err != nil {
		return nil, fmt.Errorf("failed to persist config change: %w", err)
	}
	return change, nil
}

func (a *API) buildConfigChangeDiff(change *ConfigChangeRequest) (map[string]interface{}, error) {
	fromVersion := change.BaseVersion
	if fromVersion == "" {
		fromVersion = "current"
	}
	fromLabel, fromContent, err := a.loadConfigDiffSource(fromVersion)
	if err != nil {
		return nil, err
	}
	toLabel := "change:" + change.ID
	toContent, err := sanitizedNormalizedConfigValue(change.Payload)
	if err != nil {
		return nil, err
	}
	diff := buildUnifiedConfigDiff(fromLabel, toLabel, fromContent, toContent)
	return map[string]interface{}{
		"from_version": fromLabel,
		"to_version":   toLabel,
		"changed":      diff != noConfigDiffMessage,
		"diff":         diff,
	}, nil
}

func (a *API) clusterConfigSyncStatus() interface{} {
	if a.cluster == nil {
		return nil
	}
	return a.cluster.GetConfigSyncStatus()
}
