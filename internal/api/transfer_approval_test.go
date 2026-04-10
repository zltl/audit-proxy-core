package api

import (
	"net/http"
	"path/filepath"
	"testing"
	"time"
)

func TestTransferApprovalCreateApproveAndReuse(t *testing.T) {
	api, mux, _ := setupTestAPI(t)
	store := NewTransferApprovalStore(filepath.Join(api.config.DataDir, "transfer_approvals.json"), []string{"admin"}, 30*time.Minute)
	api.SetTransferApprovals(store)
	api.RegisterTransferApprovalRoutes(mux)

	createRR := doRequestWithHeaders(mux, http.MethodPost, "/api/v2/terminal/transfer-approvals", map[string]interface{}{
		"target":    "srv1.local:22",
		"direction": "upload",
		"name":      "secrets.txt",
		"path":      "uploads/secrets.txt",
		"size":      128,
		"reason":    "content matches API key detector",
	}, map[string]string{
		"X-User": "alice",
		"X-Role": "operator",
	})
	if createRR.Code != http.StatusAccepted {
		t.Fatalf("expected 202, got %d: %s", createRR.Code, createRR.Body.String())
	}
	createResp := parseResponse(t, createRR)
	created := createResp.Data.(map[string]interface{})
	id := created["id"].(string)
	if created["status"] != string(TransferApprovalPending) {
		t.Fatalf("status = %#v, want pending", created["status"])
	}

	approveRR := doRequestWithHeaders(mux, http.MethodPost, "/api/v2/terminal/transfer-approvals/"+id+"/approve", nil, map[string]string{
		"X-User": "admin",
		"X-Role": "admin",
	})
	if approveRR.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", approveRR.Code, approveRR.Body.String())
	}
	approveResp := parseResponse(t, approveRR)
	approved := approveResp.Data.(map[string]interface{})
	if approved["status"] != string(TransferApprovalApproved) {
		t.Fatalf("status = %#v, want approved", approved["status"])
	}

	reuseRR := doRequestWithHeaders(mux, http.MethodPost, "/api/v2/terminal/transfer-approvals", map[string]interface{}{
		"target":    "srv1.local:22",
		"direction": "upload",
		"name":      "secrets.txt",
		"path":      "uploads/secrets.txt",
		"size":      128,
		"reason":    "content matches API key detector",
	}, map[string]string{
		"X-User": "alice",
		"X-Role": "operator",
	})
	if reuseRR.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", reuseRR.Code, reuseRR.Body.String())
	}
	reuseResp := parseResponse(t, reuseRR)
	reused := reuseResp.Data.(map[string]interface{})
	if reused["id"] != id {
		t.Fatalf("reused id = %#v, want %q", reused["id"], id)
	}
	if reused["status"] != string(TransferApprovalApproved) {
		t.Fatalf("reused status = %#v, want approved", reused["status"])
	}
}

func TestTransferApprovalVisibilityAndRoleChecks(t *testing.T) {
	api, mux, _ := setupTestAPI(t)
	store := NewTransferApprovalStore(filepath.Join(api.config.DataDir, "transfer_approvals.json"), []string{"admin"}, 30*time.Minute)
	api.SetTransferApprovals(store)
	api.RegisterTransferApprovalRoutes(mux)

	createRR := doRequestWithHeaders(mux, http.MethodPost, "/api/v2/terminal/transfer-approvals", map[string]interface{}{
		"target":    "srv1.local:22",
		"direction": "download",
		"name":      "report.txt",
		"path":      "downloads/report.txt",
		"size":      256,
		"reason":    "content matches credit card detector",
	}, map[string]string{
		"X-User": "alice",
		"X-Role": "operator",
	})
	createResp := parseResponse(t, createRR)
	id := createResp.Data.(map[string]interface{})["id"].(string)

	getForbidden := doRequestWithHeaders(mux, http.MethodGet, "/api/v2/terminal/transfer-approvals/"+id, nil, map[string]string{
		"X-User": "bob",
		"X-Role": "operator",
	})
	if getForbidden.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d: %s", getForbidden.Code, getForbidden.Body.String())
	}

	listOwn := doRequestWithHeaders(mux, http.MethodGet, "/api/v2/terminal/transfer-approvals", nil, map[string]string{
		"X-User": "alice",
		"X-Role": "operator",
	})
	if listOwn.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", listOwn.Code, listOwn.Body.String())
	}
	listOwnResp := parseResponse(t, listOwn)
	if listOwnResp.Total != 1 {
		t.Fatalf("own list total = %d, want 1", listOwnResp.Total)
	}

	approveForbidden := doRequestWithHeaders(mux, http.MethodPost, "/api/v2/terminal/transfer-approvals/"+id+"/approve", nil, map[string]string{
		"X-User": "bob",
		"X-Role": "operator",
	})
	if approveForbidden.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d: %s", approveForbidden.Code, approveForbidden.Body.String())
	}

	denyRR := doRequestWithHeaders(mux, http.MethodPost, "/api/v2/terminal/transfer-approvals/"+id+"/deny", map[string]interface{}{
		"reason": "contains payment data",
	}, map[string]string{
		"X-User": "admin",
		"X-Role": "admin",
	})
	if denyRR.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", denyRR.Code, denyRR.Body.String())
	}
	denyResp := parseResponse(t, denyRR)
	denied := denyResp.Data.(map[string]interface{})
	if denied["status"] != string(TransferApprovalDenied) {
		t.Fatalf("status = %#v, want denied", denied["status"])
	}
	if denied["deny_reason"] != "contains payment data" {
		t.Fatalf("deny_reason = %#v, want contains payment data", denied["deny_reason"])
	}
}
