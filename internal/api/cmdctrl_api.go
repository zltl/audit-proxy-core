package api

import (
	"net/http"
	"sync"

	"github.com/ssh-proxy-core/ssh-proxy-core/internal/cmdctrl"
)

type cmdCtrlState struct {
	engine    *cmdctrl.PolicyEngine
	approvals *cmdctrl.ApprovalManager
	mu        sync.RWMutex
	stats     cmdCtrlStats
}

type cmdCtrlStats struct {
	TotalEvaluations int64 `json:"total_evaluations"`
	Allowed          int64 `json:"allowed"`
	Denied           int64 `json:"denied"`
	Audited          int64 `json:"audited"`
	Rewritten        int64 `json:"rewritten"`
	ApprovalRequired int64 `json:"approval_required"`
}

// SetCmdCtrl attaches a command control policy engine and approval manager to the API.
func (a *API) SetCmdCtrl(engine *cmdctrl.PolicyEngine, approvals *cmdctrl.ApprovalManager) {
	a.cmdCtrl = &cmdCtrlState{
		engine:    engine,
		approvals: approvals,
	}
}

// RegisterCmdCtrlRoutes registers all command control routes on the given mux.
func (a *API) RegisterCmdCtrlRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v2/commands/rules", a.handleListCmdRules)
	mux.HandleFunc("POST /api/v2/commands/rules", a.handleCreateCmdRule)
	mux.HandleFunc("GET /api/v2/commands/rules/{id}", a.handleGetCmdRule)
	mux.HandleFunc("PUT /api/v2/commands/rules/{id}", a.handleUpdateCmdRule)
	mux.HandleFunc("DELETE /api/v2/commands/rules/{id}", a.handleDeleteCmdRule)
	mux.HandleFunc("POST /api/v2/commands/evaluate", a.handleEvaluateCommand)
	mux.HandleFunc("GET /api/v2/commands/approvals", a.handleListApprovals)
	mux.HandleFunc("POST /api/v2/commands/approvals/{id}/approve", a.handleApproveCommand)
	mux.HandleFunc("POST /api/v2/commands/approvals/{id}/deny", a.handleDenyCommand)
	mux.HandleFunc("GET /api/v2/commands/stats", a.handleCmdCtrlStats)
}

func (a *API) requireCmdCtrl(w http.ResponseWriter) bool {
	if a.cmdCtrl == nil {
		writeError(w, http.StatusServiceUnavailable, "command control is not enabled")
		return false
	}
	return true
}

func (a *API) handleListCmdRules(w http.ResponseWriter, r *http.Request) {
	if !a.requireCmdCtrl(w) {
		return
	}

	rules := a.cmdCtrl.engine.ListRules()
	if rules == nil {
		rules = []*cmdctrl.CommandRule{}
	}

	page, perPage := parsePagination(r)
	total := len(rules)
	start, end := paginate(total, page, perPage)

	writeJSON(w, http.StatusOK, APIResponse{
		Success: true,
		Data:    rules[start:end],
		Total:   total,
		Page:    page,
		PerPage: perPage,
	})
}

func (a *API) handleCreateCmdRule(w http.ResponseWriter, r *http.Request) {
	if !a.requireCmdCtrl(w) {
		return
	}

	var rule cmdctrl.CommandRule
	if err := readJSON(r, &rule); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	if err := a.cmdCtrl.engine.AddRule(&rule); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	if err := a.cmdCtrl.engine.SaveRules(); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to persist rules: "+err.Error())
		return
	}

	writeJSON(w, http.StatusCreated, APIResponse{
		Success: true,
		Data:    &rule,
	})
}

func (a *API) handleGetCmdRule(w http.ResponseWriter, r *http.Request) {
	if !a.requireCmdCtrl(w) {
		return
	}

	id := r.PathValue("id")
	rule, err := a.cmdCtrl.engine.GetRule(id)
	if err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, APIResponse{
		Success: true,
		Data:    rule,
	})
}

func (a *API) handleUpdateCmdRule(w http.ResponseWriter, r *http.Request) {
	if !a.requireCmdCtrl(w) {
		return
	}

	id := r.PathValue("id")

	var rule cmdctrl.CommandRule
	if err := readJSON(r, &rule); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	if err := a.cmdCtrl.engine.UpdateRule(id, &rule); err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}

	if err := a.cmdCtrl.engine.SaveRules(); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to persist rules: "+err.Error())
		return
	}

	updated, _ := a.cmdCtrl.engine.GetRule(id)
	writeJSON(w, http.StatusOK, APIResponse{
		Success: true,
		Data:    updated,
	})
}

func (a *API) handleDeleteCmdRule(w http.ResponseWriter, r *http.Request) {
	if !a.requireCmdCtrl(w) {
		return
	}

	id := r.PathValue("id")
	if err := a.cmdCtrl.engine.DeleteRule(id); err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}

	if err := a.cmdCtrl.engine.SaveRules(); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to persist rules: "+err.Error())
		return
	}

	writeJSON(w, http.StatusOK, APIResponse{
		Success: true,
		Data:    "rule deleted",
	})
}

func (a *API) handleEvaluateCommand(w http.ResponseWriter, r *http.Request) {
	if !a.requireCmdCtrl(w) {
		return
	}

	var body struct {
		Command  string `json:"command"`
		Username string `json:"username"`
		Role     string `json:"role"`
		Target   string `json:"target"`
	}
	if err := readJSON(r, &body); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if body.Command == "" {
		writeError(w, http.StatusBadRequest, "command is required")
		return
	}

	decision := a.cmdCtrl.engine.Evaluate(body.Command, body.Username, body.Role, body.Target)

	a.cmdCtrl.mu.Lock()
	a.cmdCtrl.stats.TotalEvaluations++
	switch decision.Action {
	case cmdctrl.ActionAllow:
		a.cmdCtrl.stats.Allowed++
	case cmdctrl.ActionDeny:
		a.cmdCtrl.stats.Denied++
	case cmdctrl.ActionAudit:
		a.cmdCtrl.stats.Audited++
	case cmdctrl.ActionRewrite:
		a.cmdCtrl.stats.Rewritten++
	case cmdctrl.ActionApprove:
		a.cmdCtrl.stats.ApprovalRequired++
	}
	a.cmdCtrl.mu.Unlock()

	writeJSON(w, http.StatusOK, APIResponse{
		Success: true,
		Data:    decision,
	})
}

func (a *API) handleListApprovals(w http.ResponseWriter, r *http.Request) {
	if !a.requireCmdCtrl(w) {
		return
	}

	pending := a.cmdCtrl.approvals.GetPending()
	if pending == nil {
		pending = []*cmdctrl.ApprovalRequest{}
	}

	writeJSON(w, http.StatusOK, APIResponse{
		Success: true,
		Data:    pending,
		Total:   len(pending),
	})
}

func (a *API) handleApproveCommand(w http.ResponseWriter, r *http.Request) {
	if !a.requireCmdCtrl(w) {
		return
	}

	id := r.PathValue("id")
	approver := r.Header.Get("X-User")
	if approver == "" {
		writeError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	if err := a.cmdCtrl.approvals.Approve(id, approver); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, APIResponse{
		Success: true,
		Data:    "command approved",
	})
}

func (a *API) handleDenyCommand(w http.ResponseWriter, r *http.Request) {
	if !a.requireCmdCtrl(w) {
		return
	}

	id := r.PathValue("id")
	approver := r.Header.Get("X-User")
	if approver == "" {
		writeError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	if err := a.cmdCtrl.approvals.Deny(id, approver); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, APIResponse{
		Success: true,
		Data:    "command denied",
	})
}

func (a *API) handleCmdCtrlStats(w http.ResponseWriter, r *http.Request) {
	if !a.requireCmdCtrl(w) {
		return
	}

	a.cmdCtrl.mu.RLock()
	stats := a.cmdCtrl.stats
	a.cmdCtrl.mu.RUnlock()

	ruleCount := len(a.cmdCtrl.engine.ListRules())
	pendingCount := len(a.cmdCtrl.approvals.GetPending())

	result := struct {
		cmdCtrlStats
		RuleCount    int `json:"rule_count"`
		PendingCount int `json:"pending_approvals"`
	}{
		cmdCtrlStats: stats,
		RuleCount:    ruleCount,
		PendingCount: pendingCount,
	}

	writeJSON(w, http.StatusOK, APIResponse{
		Success: true,
		Data:    result,
	})
}
