package api

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/ssh-proxy-core/ssh-proxy-core/internal/jit"
)

// SetJIT attaches a JIT store to the API and registers the JIT routes.
// Call this after RegisterRoutes if JIT is enabled.
func (a *API) SetJIT(store *jit.Store) {
	a.jitStore = store
}

// RegisterJITRoutes registers all JIT access routes on the given mux.
func (a *API) RegisterJITRoutes(mux *http.ServeMux) {
	mux.HandleFunc("POST /api/v2/jit/requests", a.handleCreateJITRequest)
	mux.HandleFunc("GET /api/v2/jit/requests", a.handleListJITRequests)
	mux.HandleFunc("GET /api/v2/jit/requests/{id}", a.handleGetJITRequest)
	mux.HandleFunc("POST /api/v2/jit/requests/{id}/approve", a.handleApproveJITRequest)
	mux.HandleFunc("POST /api/v2/jit/requests/{id}/deny", a.handleDenyJITRequest)
	mux.HandleFunc("POST /api/v2/jit/requests/{id}/revoke", a.handleRevokeJITRequest)
	mux.HandleFunc("GET /api/v2/jit/grants", a.handleListJITGrants)
	mux.HandleFunc("GET /api/v2/jit/check", a.handleCheckJITAccess)
	mux.HandleFunc("GET /api/v2/jit/policy", a.handleGetJITPolicy)
	mux.HandleFunc("PUT /api/v2/jit/policy", a.handleUpdateJITPolicy)
}

func (a *API) requireJIT(w http.ResponseWriter) bool {
	if a.jitStore == nil {
		writeError(w, http.StatusServiceUnavailable, "JIT access is not enabled")
		return false
	}
	return true
}

// handleCreateJITRequest creates a new JIT access request.
func (a *API) handleCreateJITRequest(w http.ResponseWriter, r *http.Request) {
	if !a.requireJIT(w) {
		return
	}

	var req struct {
		Target   string `json:"target"`
		Role     string `json:"role"`
		Reason   string `json:"reason"`
		Duration string `json:"duration"`
	}
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	if req.Target == "" {
		writeError(w, http.StatusBadRequest, "target is required")
		return
	}
	if req.Role == "" {
		writeError(w, http.StatusBadRequest, "role is required")
		return
	}
	if req.Duration == "" {
		writeError(w, http.StatusBadRequest, "duration is required")
		return
	}

	dur, err := time.ParseDuration(req.Duration)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid duration: "+err.Error())
		return
	}

	// Extract requester from X-User header (set by auth middleware)
	requester := r.Header.Get("X-User")
	if requester == "" {
		writeError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	accessReq := &jit.AccessRequest{
		Requester: requester,
		Target:    req.Target,
		Role:      req.Role,
		Reason:    req.Reason,
		Duration:  dur,
	}

	if err := a.jitStore.CreateRequest(accessReq); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	writeJSON(w, http.StatusCreated, APIResponse{
		Success: true,
		Data:    accessReq,
	})
}

// handleListJITRequests lists JIT requests with optional filters.
func (a *API) handleListJITRequests(w http.ResponseWriter, r *http.Request) {
	if !a.requireJIT(w) {
		return
	}

	q := r.URL.Query()
	filter := jit.RequestFilter{
		Status:    jit.RequestStatus(q.Get("status")),
		Requester: q.Get("requester"),
		Target:    q.Get("target"),
	}
	if v := q.Get("since"); v != "" {
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			filter.Since = t
		}
	}
	if v := q.Get("until"); v != "" {
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			filter.Until = t
		}
	}

	requests := a.jitStore.ListRequests(filter)
	if requests == nil {
		requests = []*jit.AccessRequest{}
	}

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

// handleGetJITRequest returns details for a specific request.
func (a *API) handleGetJITRequest(w http.ResponseWriter, r *http.Request) {
	if !a.requireJIT(w) {
		return
	}

	id := r.PathValue("id")
	if id == "" {
		writeError(w, http.StatusBadRequest, "missing request id")
		return
	}

	req, err := a.jitStore.GetRequest(id)
	if err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, APIResponse{
		Success: true,
		Data:    req,
	})
}

// handleApproveJITRequest approves a pending JIT request (admin only).
func (a *API) handleApproveJITRequest(w http.ResponseWriter, r *http.Request) {
	if !a.requireJIT(w) {
		return
	}

	approver := r.Header.Get("X-User")
	role := r.Header.Get("X-Role")
	if approver == "" {
		writeError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if !a.isApproverRole(role) {
		writeError(w, http.StatusForbidden, "admin role required")
		return
	}

	id := r.PathValue("id")
	if id == "" {
		writeError(w, http.StatusBadRequest, "missing request id")
		return
	}

	if err := a.jitStore.ApproveRequest(id, approver); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	req, _ := a.jitStore.GetRequest(id)
	writeJSON(w, http.StatusOK, APIResponse{
		Success: true,
		Data:    req,
	})
}

// handleDenyJITRequest denies a pending JIT request (admin only).
func (a *API) handleDenyJITRequest(w http.ResponseWriter, r *http.Request) {
	if !a.requireJIT(w) {
		return
	}

	approver := r.Header.Get("X-User")
	role := r.Header.Get("X-Role")
	if approver == "" {
		writeError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if !a.isApproverRole(role) {
		writeError(w, http.StatusForbidden, "admin role required")
		return
	}

	id := r.PathValue("id")
	if id == "" {
		writeError(w, http.StatusBadRequest, "missing request id")
		return
	}

	var body struct {
		Reason string `json:"reason"`
	}
	readJSON(r, &body)

	if err := a.jitStore.DenyRequest(id, approver, body.Reason); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	req, _ := a.jitStore.GetRequest(id)
	writeJSON(w, http.StatusOK, APIResponse{
		Success: true,
		Data:    req,
	})
}

// handleRevokeJITRequest revokes an approved JIT request.
func (a *API) handleRevokeJITRequest(w http.ResponseWriter, r *http.Request) {
	if !a.requireJIT(w) {
		return
	}

	revoker := r.Header.Get("X-User")
	if revoker == "" {
		writeError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	id := r.PathValue("id")
	if id == "" {
		writeError(w, http.StatusBadRequest, "missing request id")
		return
	}

	if err := a.jitStore.RevokeRequest(id, revoker); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	req, _ := a.jitStore.GetRequest(id)
	writeJSON(w, http.StatusOK, APIResponse{
		Success: true,
		Data:    req,
	})
}

// handleListJITGrants lists all active access grants.
func (a *API) handleListJITGrants(w http.ResponseWriter, r *http.Request) {
	if !a.requireJIT(w) {
		return
	}

	grants := a.jitStore.ListGrants()
	if grants == nil {
		grants = []*jit.AccessGrant{}
	}

	writeJSON(w, http.StatusOK, APIResponse{
		Success: true,
		Data:    grants,
		Total:   len(grants),
	})
}

// handleCheckJITAccess checks whether a user has active JIT access.
func (a *API) handleCheckJITAccess(w http.ResponseWriter, r *http.Request) {
	if !a.requireJIT(w) {
		return
	}

	user := r.URL.Query().Get("user")
	target := r.URL.Query().Get("target")
	if user == "" || target == "" {
		writeError(w, http.StatusBadRequest, "user and target query parameters are required")
		return
	}

	grant, ok := a.jitStore.CheckAccess(user, target)
	resp := map[string]interface{}{
		"has_access": ok,
		"user":       user,
		"target":     target,
	}
	if ok {
		resp["grant"] = grant
	}

	writeJSON(w, http.StatusOK, APIResponse{
		Success: true,
		Data:    resp,
	})
}

// handleGetJITPolicy returns the current JIT policy.
func (a *API) handleGetJITPolicy(w http.ResponseWriter, r *http.Request) {
	if !a.requireJIT(w) {
		return
	}

	policy := a.jitStore.GetPolicy()
	writeJSON(w, http.StatusOK, APIResponse{
		Success: true,
		Data:    policy,
	})
}

// handleUpdateJITPolicy updates the JIT policy (admin only).
func (a *API) handleUpdateJITPolicy(w http.ResponseWriter, r *http.Request) {
	if !a.requireJIT(w) {
		return
	}

	user := r.Header.Get("X-User")
	role := r.Header.Get("X-Role")
	if user == "" {
		writeError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if role != "admin" {
		writeError(w, http.StatusForbidden, "admin role required")
		return
	}

	var raw struct {
		MaxDuration     string   `json:"max_duration"`
		AutoApprove     bool     `json:"auto_approve"`
		AutoApproveFor  []string `json:"auto_approve_for"`
		RequireReason   bool     `json:"require_reason"`
		ApproverRoles   []string `json:"approver_roles"`
		NotifyOnRequest bool     `json:"notify_on_request"`
		NotifyOnApprove bool     `json:"notify_on_approve"`
	}
	if err := readJSON(r, &raw); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	policy := &jit.Policy{
		AutoApprove:     raw.AutoApprove,
		AutoApproveFor:  raw.AutoApproveFor,
		RequireReason:   raw.RequireReason,
		ApproverRoles:   raw.ApproverRoles,
		NotifyOnRequest: raw.NotifyOnRequest,
		NotifyOnApprove: raw.NotifyOnApprove,
	}

	if raw.MaxDuration != "" {
		dur, err := time.ParseDuration(raw.MaxDuration)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid max_duration: "+err.Error())
			return
		}
		policy.MaxDuration = dur
	}

	if err := a.jitStore.SetPolicy(policy); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to save policy: "+err.Error())
		return
	}

	writeJSON(w, http.StatusOK, APIResponse{
		Success: true,
		Data:    policy,
	})
}

// isApproverRole checks if the given role is in the policy's approver list.
func (a *API) isApproverRole(role string) bool {
	policy := a.jitStore.GetPolicy()
	roles := policy.ApproverRoles
	if len(roles) == 0 {
		roles = []string{"admin"}
	}
	for _, r := range roles {
		if r == role {
			return true
		}
	}
	return false
}

// jitPolicyJSON is used for JSON serialization of the policy with string durations.
type jitPolicyJSON struct {
	MaxDuration     string   `json:"max_duration"`
	AutoApprove     bool     `json:"auto_approve"`
	AutoApproveFor  []string `json:"auto_approve_for"`
	RequireReason   bool     `json:"require_reason"`
	ApproverRoles   []string `json:"approver_roles"`
	NotifyOnRequest bool     `json:"notify_on_request"`
	NotifyOnApprove bool     `json:"notify_on_approve"`
}

func policyToJSON(p jit.Policy) jitPolicyJSON {
	return jitPolicyJSON{
		MaxDuration:     p.MaxDuration.String(),
		AutoApprove:     p.AutoApprove,
		AutoApproveFor:  p.AutoApproveFor,
		RequireReason:   p.RequireReason,
		ApproverRoles:   p.ApproverRoles,
		NotifyOnRequest: p.NotifyOnRequest,
		NotifyOnApprove: p.NotifyOnApprove,
	}
}

// marshalAccessRequest serializes an AccessRequest with duration as string.
func marshalAccessRequest(req *jit.AccessRequest) json.RawMessage {
	type alias jit.AccessRequest
	raw, _ := json.Marshal(&struct {
		*alias
		Duration string `json:"duration"`
	}{
		alias:    (*alias)(req),
		Duration: req.Duration.String(),
	})
	return raw
}
