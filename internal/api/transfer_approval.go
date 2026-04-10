package api

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/ssh-proxy-core/ssh-proxy-core/internal/jit"
)

// TransferApprovalStatus represents the lifecycle state of a DLP transfer approval request.
type TransferApprovalStatus string

const (
	TransferApprovalPending  TransferApprovalStatus = "pending"
	TransferApprovalApproved TransferApprovalStatus = "approved"
	TransferApprovalDenied   TransferApprovalStatus = "denied"
	TransferApprovalExpired  TransferApprovalStatus = "expired"
)

// ErrTransferApproverRoleNotAllowed indicates the caller's role cannot approve or deny requests.
var ErrTransferApproverRoleNotAllowed = errors.New("approver role not allowed for transfer approval")

// TransferApprovalRequest represents one transfer approval workflow request.
type TransferApprovalRequest struct {
	ID            string                 `json:"id"`
	Requester     string                 `json:"requester"`
	RequesterRole string                 `json:"requester_role,omitempty"`
	Target        string                 `json:"target"`
	Direction     string                 `json:"direction"`
	Name          string                 `json:"name"`
	Path          string                 `json:"path,omitempty"`
	Size          int64                  `json:"size,omitempty"`
	Reason        string                 `json:"reason"`
	Status        TransferApprovalStatus `json:"status"`
	Approver      string                 `json:"approver,omitempty"`
	ApproverRole  string                 `json:"approver_role,omitempty"`
	CreatedAt     time.Time              `json:"created_at"`
	ExpiresAt     time.Time              `json:"expires_at,omitempty"`
	DecidedAt     time.Time              `json:"decided_at,omitempty"`
	DenyReason    string                 `json:"deny_reason,omitempty"`
}

// TransferApprovalFilter limits approval listing results.
type TransferApprovalFilter struct {
	Status    TransferApprovalStatus
	Requester string
	Approver  string
	Target    string
	Direction string
}

type persistedTransferApprovals struct {
	Requests []*TransferApprovalRequest `json:"requests"`
}

// TransferApprovalStore persists transfer approval workflows to disk.
type TransferApprovalStore struct {
	mu            sync.RWMutex
	path          string
	timeout       time.Duration
	approverRoles []string
	requests      map[string]*TransferApprovalRequest
	notifier      *jit.Notifier
	now           func() time.Time
}

// ParseTransferApprovalRoles splits a comma-separated role list.
func ParseTransferApprovalRoles(raw string) []string {
	parts := strings.Split(raw, ",")
	roles := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.ToLower(strings.TrimSpace(part))
		if part == "" {
			continue
		}
		roles = append(roles, part)
	}
	return roles
}

// NewTransferApprovalStore creates a persisted transfer approval store.
func NewTransferApprovalStore(path string, approverRoles []string, timeout time.Duration) *TransferApprovalStore {
	if timeout <= 0 {
		timeout = 30 * time.Minute
	}
	store := &TransferApprovalStore{
		path:          path,
		timeout:       timeout,
		approverRoles: normalizeTransferApprovalRoles(approverRoles),
		requests:      make(map[string]*TransferApprovalRequest),
		now:           time.Now,
	}
	store.load()
	return store
}

// SetNotifier attaches the shared notifier used for approval request fan-out.
func (s *TransferApprovalStore) SetNotifier(n *jit.Notifier) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.notifier = n
}

// IsApproverRole reports whether a role can approve or deny transfer requests.
func (s *TransferApprovalStore) IsApproverRole(role string) bool {
	role = strings.ToLower(strings.TrimSpace(role))
	if role == "" {
		return false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, allowed := range s.approverRoles {
		if role == allowed {
			return true
		}
	}
	return false
}

// CreateOrReuseRequest creates a new pending request or reuses a matching pending/approved one.
func (s *TransferApprovalStore) CreateOrReuseRequest(req *TransferApprovalRequest) (*TransferApprovalRequest, bool, error) {
	if req == nil {
		return nil, false, errors.New("transfer approval request is required")
	}
	if strings.TrimSpace(req.Requester) == "" {
		return nil, false, errors.New("requester is required")
	}
	if strings.TrimSpace(req.Target) == "" {
		return nil, false, errors.New("target is required")
	}
	if strings.TrimSpace(req.Direction) == "" {
		return nil, false, errors.New("direction is required")
	}
	if strings.TrimSpace(req.Name) == "" {
		return nil, false, errors.New("name is required")
	}
	if strings.TrimSpace(req.Reason) == "" {
		return nil, false, errors.New("reason is required")
	}

	req.Requester = strings.TrimSpace(req.Requester)
	req.RequesterRole = strings.ToLower(strings.TrimSpace(req.RequesterRole))
	req.Target = strings.TrimSpace(req.Target)
	req.Direction = strings.ToLower(strings.TrimSpace(req.Direction))
	req.Name = strings.TrimSpace(req.Name)
	req.Path = strings.TrimSpace(req.Path)
	req.Reason = strings.TrimSpace(req.Reason)

	id, err := generateTransferApprovalID()
	if err != nil {
		return nil, false, err
	}

	now := s.now().UTC()
	persisted := &TransferApprovalRequest{
		ID:            id,
		Requester:     req.Requester,
		RequesterRole: req.RequesterRole,
		Target:        req.Target,
		Direction:     req.Direction,
		Name:          req.Name,
		Path:          req.Path,
		Size:          req.Size,
		Reason:        req.Reason,
		Status:        TransferApprovalPending,
		CreatedAt:     now,
		ExpiresAt:     now.Add(s.timeout),
	}

	var (
		created  bool
		result   *TransferApprovalRequest
		notifier *jit.Notifier
	)

	s.mu.Lock()
	changed := false
	for _, existing := range s.requests {
		if s.expireLocked(existing) {
			changed = true
		}
		if !sameTransferApproval(existing, persisted) {
			continue
		}
		if existing.Status == TransferApprovalPending || existing.Status == TransferApprovalApproved {
			result = cloneTransferApproval(existing)
			if changed {
				_ = s.saveLocked()
			}
			s.mu.Unlock()
			return result, false, nil
		}
	}
	s.requests[persisted.ID] = persisted
	if err := s.saveLocked(); err != nil {
		delete(s.requests, persisted.ID)
		s.mu.Unlock()
		return nil, false, err
	}
	result = cloneTransferApproval(persisted)
	created = true
	notifier = s.notifier
	s.mu.Unlock()

	if notifier != nil {
		s.notifyPendingRequest(notifier, result)
	}
	return result, created, nil
}

// GetRequest returns a single approval request by ID.
func (s *TransferApprovalStore) GetRequest(id string) (*TransferApprovalRequest, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	req, ok := s.requests[id]
	if !ok {
		return nil, fmt.Errorf("transfer approval %s not found", id)
	}
	if s.expireLocked(req) {
		_ = s.saveLocked()
	}
	return cloneTransferApproval(req), nil
}

// ListRequests returns matching approval requests, newest first.
func (s *TransferApprovalStore) ListRequests(filter TransferApprovalFilter) []*TransferApprovalRequest {
	s.mu.Lock()
	changed := false
	results := make([]*TransferApprovalRequest, 0, len(s.requests))
	for _, req := range s.requests {
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
		if filter.Target != "" && req.Target != filter.Target {
			continue
		}
		if filter.Direction != "" && req.Direction != filter.Direction {
			continue
		}
		results = append(results, cloneTransferApproval(req))
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

// ApproveRequest marks a pending transfer request as approved.
func (s *TransferApprovalStore) ApproveRequest(id, approver, role string) (*TransferApprovalRequest, error) {
	if !s.IsApproverRole(role) {
		return nil, ErrTransferApproverRoleNotAllowed
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	req, ok := s.requests[id]
	if !ok {
		return nil, fmt.Errorf("transfer approval %s not found", id)
	}
	if s.expireLocked(req) {
		_ = s.saveLocked()
		return nil, fmt.Errorf("transfer approval %s has expired", id)
	}
	if req.Status != TransferApprovalPending {
		return nil, fmt.Errorf("transfer approval %s is not pending (status: %s)", id, req.Status)
	}

	prev := cloneTransferApproval(req)
	now := s.now().UTC()
	req.Status = TransferApprovalApproved
	req.Approver = strings.TrimSpace(approver)
	req.ApproverRole = strings.ToLower(strings.TrimSpace(role))
	req.DecidedAt = now
	req.ExpiresAt = now.Add(s.timeout)
	req.DenyReason = ""
	if err := s.saveLocked(); err != nil {
		*req = *prev
		return nil, err
	}
	return cloneTransferApproval(req), nil
}

// DenyRequest marks a pending transfer request as denied.
func (s *TransferApprovalStore) DenyRequest(id, approver, role, reason string) (*TransferApprovalRequest, error) {
	if !s.IsApproverRole(role) {
		return nil, ErrTransferApproverRoleNotAllowed
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	req, ok := s.requests[id]
	if !ok {
		return nil, fmt.Errorf("transfer approval %s not found", id)
	}
	if s.expireLocked(req) {
		_ = s.saveLocked()
		return nil, fmt.Errorf("transfer approval %s has expired", id)
	}
	if req.Status != TransferApprovalPending {
		return nil, fmt.Errorf("transfer approval %s is not pending (status: %s)", id, req.Status)
	}

	prev := cloneTransferApproval(req)
	req.Status = TransferApprovalDenied
	req.Approver = strings.TrimSpace(approver)
	req.ApproverRole = strings.ToLower(strings.TrimSpace(role))
	req.DecidedAt = s.now().UTC()
	req.DenyReason = strings.TrimSpace(reason)
	if err := s.saveLocked(); err != nil {
		*req = *prev
		return nil, err
	}
	return cloneTransferApproval(req), nil
}

func generateTransferApprovalID() (string, error) {
	buf := make([]byte, 8)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("failed to generate transfer approval id: %w", err)
	}
	return hex.EncodeToString(buf), nil
}

func normalizeTransferApprovalRoles(roles []string) []string {
	if len(roles) == 0 {
		return []string{"admin"}
	}
	seen := make(map[string]struct{}, len(roles))
	out := make([]string, 0, len(roles))
	for _, role := range roles {
		role = strings.ToLower(strings.TrimSpace(role))
		if role == "" {
			continue
		}
		if _, ok := seen[role]; ok {
			continue
		}
		seen[role] = struct{}{}
		out = append(out, role)
	}
	if len(out) == 0 {
		return []string{"admin"}
	}
	return out
}

func sameTransferApproval(a, b *TransferApprovalRequest) bool {
	if a == nil || b == nil {
		return false
	}
	return a.Requester == b.Requester &&
		a.Target == b.Target &&
		a.Direction == b.Direction &&
		a.Name == b.Name &&
		a.Path == b.Path &&
		a.Size == b.Size &&
		a.Reason == b.Reason
}

func cloneTransferApproval(req *TransferApprovalRequest) *TransferApprovalRequest {
	if req == nil {
		return nil
	}
	clone := *req
	return &clone
}

func (s *TransferApprovalStore) expireLocked(req *TransferApprovalRequest) bool {
	if req == nil || req.ExpiresAt.IsZero() || s.now().Before(req.ExpiresAt) {
		return false
	}
	switch req.Status {
	case TransferApprovalPending, TransferApprovalApproved:
		req.Status = TransferApprovalExpired
		if req.DecidedAt.IsZero() {
			req.DecidedAt = s.now().UTC()
		}
		return true
	default:
		return false
	}
}

func (s *TransferApprovalStore) load() {
	if strings.TrimSpace(s.path) == "" {
		return
	}
	data, err := os.ReadFile(s.path)
	if err != nil {
		return
	}
	var persisted persistedTransferApprovals
	if err := json.Unmarshal(data, &persisted); err != nil {
		return
	}
	for _, req := range persisted.Requests {
		if req == nil || strings.TrimSpace(req.ID) == "" {
			continue
		}
		s.requests[req.ID] = req
	}
}

func (s *TransferApprovalStore) saveLocked() error {
	if strings.TrimSpace(s.path) == "" {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(s.path), 0o755); err != nil {
		return err
	}
	requests := make([]*TransferApprovalRequest, 0, len(s.requests))
	for _, req := range s.requests {
		requests = append(requests, cloneTransferApproval(req))
	}
	sort.Slice(requests, func(i, j int) bool {
		return requests[i].CreatedAt.Before(requests[j].CreatedAt)
	})
	payload, err := json.MarshalIndent(persistedTransferApprovals{Requests: requests}, "", "  ")
	if err != nil {
		return err
	}
	tempPath := s.path + ".tmp"
	if err := os.WriteFile(tempPath, payload, 0o600); err != nil {
		return err
	}
	return os.Rename(tempPath, s.path)
}

func (s *TransferApprovalStore) notifyPendingRequest(notifier *jit.Notifier, req *TransferApprovalRequest) {
	body := fmt.Sprintf("Requester: %s\nRequester role: %s\nTarget: %s\nDirection: %s\nName: %s\nPath: %s\nSize: %d bytes\nReason: %s\nRequest ID: %s",
		req.Requester,
		emptyIfBlank(req.RequesterRole, "<unknown>"),
		req.Target,
		req.Direction,
		req.Name,
		emptyIfBlank(req.Path, req.Name),
		req.Size,
		req.Reason,
		req.ID,
	)
	if err := notifier.NotifyMessage(context.Background(), "[SSH Proxy] Transfer approval requested", body); err != nil {
		log.Printf("transfer approval notify: %v", err)
	}
}

func emptyIfBlank(value, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return value
}

// SetTransferApprovals attaches a transfer approval store to the API.
func (a *API) SetTransferApprovals(store *TransferApprovalStore) {
	a.transferApprovals = store
}

// RegisterTransferApprovalRoutes registers DLP transfer approval endpoints.
func (a *API) RegisterTransferApprovalRoutes(mux *http.ServeMux) {
	mux.HandleFunc("POST /api/v2/terminal/transfer-approvals", a.handleCreateTransferApproval)
	mux.HandleFunc("GET /api/v2/terminal/transfer-approvals", a.handleListTransferApprovals)
	mux.HandleFunc("GET /api/v2/terminal/transfer-approvals/{id}", a.handleGetTransferApproval)
	mux.HandleFunc("POST /api/v2/terminal/transfer-approvals/{id}/approve", a.handleApproveTransferApproval)
	mux.HandleFunc("POST /api/v2/terminal/transfer-approvals/{id}/deny", a.handleDenyTransferApproval)
}

func (a *API) requireTransferApprovals(w http.ResponseWriter) bool {
	if a.transferApprovals == nil {
		writeError(w, http.StatusServiceUnavailable, "transfer approvals are not enabled")
		return false
	}
	return true
}

func (a *API) handleCreateTransferApproval(w http.ResponseWriter, r *http.Request) {
	if !a.requireTransferApprovals(w) {
		return
	}
	requester := strings.TrimSpace(r.Header.Get("X-User"))
	if requester == "" {
		writeError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	var body struct {
		Target    string `json:"target"`
		Direction string `json:"direction"`
		Name      string `json:"name"`
		Path      string `json:"path"`
		Size      int64  `json:"size"`
		Reason    string `json:"reason"`
	}
	if err := readJSON(r, &body); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	req, created, err := a.transferApprovals.CreateOrReuseRequest(&TransferApprovalRequest{
		Requester:     requester,
		RequesterRole: r.Header.Get("X-Role"),
		Target:        body.Target,
		Direction:     body.Direction,
		Name:          body.Name,
		Path:          body.Path,
		Size:          body.Size,
		Reason:        body.Reason,
	})
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	status := http.StatusOK
	if req.Status == TransferApprovalPending {
		status = http.StatusAccepted
	}
	if created {
		status = http.StatusAccepted
	}
	writeJSON(w, status, APIResponse{
		Success: true,
		Data:    req,
	})
}

func (a *API) handleListTransferApprovals(w http.ResponseWriter, r *http.Request) {
	if !a.requireTransferApprovals(w) {
		return
	}
	user := strings.TrimSpace(r.Header.Get("X-User"))
	if user == "" {
		writeError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	role := r.Header.Get("X-Role")
	filter := TransferApprovalFilter{
		Status:    TransferApprovalStatus(r.URL.Query().Get("status")),
		Requester: r.URL.Query().Get("requester"),
		Approver:  r.URL.Query().Get("approver"),
		Target:    r.URL.Query().Get("target"),
		Direction: strings.ToLower(strings.TrimSpace(r.URL.Query().Get("direction"))),
	}
	if !a.transferApprovals.IsApproverRole(role) {
		filter.Requester = user
	}
	requests := a.transferApprovals.ListRequests(filter)
	page, perPage := parsePagination(r)
	total := len(requests)
	start, end := paginate(total, page, perPage)
	writeJSON(w, http.StatusOK, APIResponse{
		Success: true,
		Data:    requests[start:end],
		Total:   total,
		Page:    page,
		PerPage: perPage,
	})
}

func (a *API) handleGetTransferApproval(w http.ResponseWriter, r *http.Request) {
	if !a.requireTransferApprovals(w) {
		return
	}
	user := strings.TrimSpace(r.Header.Get("X-User"))
	if user == "" {
		writeError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	role := r.Header.Get("X-Role")
	req, err := a.transferApprovals.GetRequest(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	if !a.transferApprovals.IsApproverRole(role) && req.Requester != user {
		writeError(w, http.StatusForbidden, "not allowed to view this transfer approval")
		return
	}
	writeJSON(w, http.StatusOK, APIResponse{
		Success: true,
		Data:    req,
	})
}

func (a *API) handleApproveTransferApproval(w http.ResponseWriter, r *http.Request) {
	if !a.requireTransferApprovals(w) {
		return
	}
	approver := strings.TrimSpace(r.Header.Get("X-User"))
	role := r.Header.Get("X-Role")
	if approver == "" {
		writeError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if strings.TrimSpace(role) == "" {
		writeError(w, http.StatusForbidden, "approver role required")
		return
	}
	req, err := a.transferApprovals.ApproveRequest(r.PathValue("id"), approver, role)
	if err != nil {
		if errors.Is(err, ErrTransferApproverRoleNotAllowed) {
			writeError(w, http.StatusForbidden, err.Error())
			return
		}
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, APIResponse{
		Success: true,
		Data:    req,
	})
}

func (a *API) handleDenyTransferApproval(w http.ResponseWriter, r *http.Request) {
	if !a.requireTransferApprovals(w) {
		return
	}
	approver := strings.TrimSpace(r.Header.Get("X-User"))
	role := r.Header.Get("X-Role")
	if approver == "" {
		writeError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if strings.TrimSpace(role) == "" {
		writeError(w, http.StatusForbidden, "approver role required")
		return
	}
	var body struct {
		Reason string `json:"reason"`
	}
	_ = readJSON(r, &body)
	req, err := a.transferApprovals.DenyRequest(r.PathValue("id"), approver, role, body.Reason)
	if err != nil {
		if errors.Is(err, ErrTransferApproverRoleNotAllowed) {
			writeError(w, http.StatusForbidden, err.Error())
			return
		}
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, APIResponse{
		Success: true,
		Data:    req,
	})
}
