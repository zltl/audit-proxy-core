package api

import (
	"net/http"
	"testing"

	"github.com/ssh-proxy-core/ssh-proxy-core/internal/collab"
)

func TestCollabFourEyesGrantControlFlow(t *testing.T) {
	api, mux, _ := setupTestAPI(t)
	api.SetCollab(collab.NewManager())
	api.RegisterCollabRoutes(mux)

	createRR := doRequestWithHeaders(mux, http.MethodPost, "/api/v2/collab/sessions", map[string]interface{}{
		"session_id":         "sess-1",
		"target":             "db.internal",
		"max_viewers":        5,
		"allow_control":      true,
		"four_eyes_required": true,
	}, map[string]string{
		"X-User": "alice",
	})
	if createRR.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", createRR.Code, createRR.Body.String())
	}
	createResp := parseResponse(t, createRR)
	session := createResp.Data.(map[string]interface{})
	id := session["id"].(string)
	if session["four_eyes_required"] != true {
		t.Fatalf("expected four_eyes_required=true, got %#v", session["four_eyes_required"])
	}

	joinRR := doRequestWithHeaders(mux, http.MethodPost, "/api/v2/collab/sessions/"+id+"/join", map[string]interface{}{
		"role": "viewer",
	}, map[string]string{
		"X-User": "bob",
	})
	if joinRR.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", joinRR.Code, joinRR.Body.String())
	}

	grantRR := doRequestWithHeaders(mux, http.MethodPost, "/api/v2/collab/sessions/"+id+"/grant-control", map[string]interface{}{
		"username": "bob",
	}, map[string]string{
		"X-User": "alice",
	})
	if grantRR.Code != http.StatusAccepted {
		t.Fatalf("expected 202, got %d: %s", grantRR.Code, grantRR.Body.String())
	}
	grantResp := parseResponse(t, grantRR)
	grantData := grantResp.Data.(map[string]interface{})
	if grantData["status"] != "pending_approval" {
		t.Fatalf("expected pending approval status, got %#v", grantData["status"])
	}
	approval := grantData["approval"].(map[string]interface{})
	approvalID := approval["id"].(string)
	if approval["action"] != string(collab.SessionActionGrantControl) {
		t.Fatalf("unexpected approval action: %#v", approval["action"])
	}

	listRR := doRequestWithHeaders(mux, http.MethodGet, "/api/v2/collab/sessions/"+id+"/approvals", nil, map[string]string{
		"X-User": "bob",
	})
	if listRR.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", listRR.Code, listRR.Body.String())
	}
	listResp := parseResponse(t, listRR)
	approvals := listResp.Data.([]interface{})
	if len(approvals) != 1 {
		t.Fatalf("expected 1 approval, got %d", len(approvals))
	}

	approveRR := doRequestWithHeaders(mux, http.MethodPost, "/api/v2/collab/sessions/"+id+"/approvals/"+approvalID+"/approve", nil, map[string]string{
		"X-User": "bob",
	})
	if approveRR.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", approveRR.Code, approveRR.Body.String())
	}
	approveResp := parseResponse(t, approveRR)
	approved := approveResp.Data.(map[string]interface{})["approval"].(map[string]interface{})
	if approved["status"] != "approved" || approved["approver"] != "bob" {
		t.Fatalf("unexpected approval payload: %#v", approved)
	}

	getRR := doRequest(mux, http.MethodGet, "/api/v2/collab/sessions/"+id, nil)
	if getRR.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", getRR.Code, getRR.Body.String())
	}
	getResp := parseResponse(t, getRR)
	participants := getResp.Data.(map[string]interface{})["participants"].([]interface{})
	var bobRole string
	for _, raw := range participants {
		participant := raw.(map[string]interface{})
		if participant["username"] == "bob" {
			bobRole = participant["role"].(string)
			break
		}
	}
	if bobRole != string(collab.RoleOperator) {
		t.Fatalf("expected bob role operator, got %q", bobRole)
	}
}
