package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

type fakeAutomationExecutor struct {
	mu      sync.Mutex
	results map[string]automationTargetResult
	calls   []automationExecutionRequest
	notify  chan string
}

func (f *fakeAutomationExecutor) Execute(_ context.Context, req automationExecutionRequest) automationTargetResult {
	f.mu.Lock()
	f.calls = append(f.calls, req)
	result := f.results[req.Target.Host]
	f.mu.Unlock()
	if f.notify != nil {
		select {
		case f.notify <- req.Target.Host:
		default:
		}
	}
	if result.Host == "" {
		result.Host = req.Target.Host
	}
	if result.Port == 0 {
		result.Port = req.Target.Port
	}
	if result.TargetName == "" {
		result.TargetName = req.Target.Name
	}
	if result.StartedAt.IsZero() {
		result.StartedAt = time.Now().UTC()
	}
	if result.FinishedAt.IsZero() {
		result.FinishedAt = result.StartedAt.Add(time.Second)
	}
	if result.Status == "" {
		result.Status = "completed"
	}
	return result
}

func doAutomationRequest(t *testing.T, mux *http.ServeMux, method, path string, body interface{}, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	var reader *bytes.Reader
	if body == nil {
		reader = bytes.NewReader(nil)
	} else {
		payload, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("json.Marshal() error = %v", err)
		}
		reader = bytes.NewReader(payload)
	}
	req := httptest.NewRequest(method, path, reader)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	for key, value := range headers {
		req.Header.Set(key, value)
	}
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	return rr
}

func TestAutomationScriptLifecycle(t *testing.T) {
	api, mux, _ := setupTestAPI(t)
	api.automation.executor = &fakeAutomationExecutor{}

	createResp := doAutomationRequest(t, mux, http.MethodPost, "/api/v2/automation/scripts", map[string]interface{}{
		"name":  "inventory",
		"shell": "/bin/sh",
		"body":  "hostname\n",
	}, map[string]string{"X-User": "admin"})
	if createResp.Code != http.StatusCreated {
		t.Fatalf("POST /api/v2/automation/scripts status = %d body = %s", createResp.Code, createResp.Body.String())
	}
	created := parseResponse(t, createResp)
	script := created.Data.(map[string]interface{})
	scriptID := script["id"].(string)

	listResp := doAutomationRequest(t, mux, http.MethodGet, "/api/v2/automation/scripts", nil, nil)
	if listResp.Code != http.StatusOK {
		t.Fatalf("GET /api/v2/automation/scripts status = %d body = %s", listResp.Code, listResp.Body.String())
	}
	listed := parseResponse(t, listResp)
	if listed.Total != 1 {
		t.Fatalf("list total = %d, want 1", listed.Total)
	}

	updateResp := doAutomationRequest(t, mux, http.MethodPut, "/api/v2/automation/scripts/"+scriptID, map[string]interface{}{
		"name":  "inventory-updated",
		"shell": "/bin/bash",
		"body":  "hostname && whoami\n",
	}, map[string]string{"X-User": "admin"})
	if updateResp.Code != http.StatusOK {
		t.Fatalf("PUT /api/v2/automation/scripts/{id} status = %d body = %s", updateResp.Code, updateResp.Body.String())
	}

	deleteResp := doAutomationRequest(t, mux, http.MethodDelete, "/api/v2/automation/scripts/"+scriptID, nil, nil)
	if deleteResp.Code != http.StatusOK {
		t.Fatalf("DELETE /api/v2/automation/scripts/{id} status = %d body = %s", deleteResp.Code, deleteResp.Body.String())
	}
}

func TestAutomationJobRunCollectsBatchResults(t *testing.T) {
	api, mux, _ := setupTestAPI(t)
	api.automation.executor = &fakeAutomationExecutor{
		results: map[string]automationTargetResult{
			"10.0.1.1": {Status: "completed", Summary: "ok", Stdout: "server1\n"},
			"10.0.1.2": {Status: "failed", ExitCode: 2, Summary: "exit 2", Error: "exit status 2", Stderr: "boom\n"},
		},
	}

	createJob := doAutomationRequest(t, mux, http.MethodPost, "/api/v2/automation/jobs", map[string]interface{}{
		"name":                           "batch-hostname",
		"command":                        "hostname",
		"server_ids":                     []string{"srv-1", "srv-2"},
		"username":                       "ops",
		"password":                       "secret",
		"insecure_skip_host_key_verify":  true,
		"enabled":                        true,
		"schedule":                       "1h",
		"trigger_providers":              []string{"github-actions", "jenkins"},
	}, map[string]string{"X-User": "admin"})
	if createJob.Code != http.StatusCreated {
		t.Fatalf("POST /api/v2/automation/jobs status = %d body = %s", createJob.Code, createJob.Body.String())
	}
	jobResp := parseResponse(t, createJob)
	jobID := jobResp.Data.(map[string]interface{})["id"].(string)

	runResp := doAutomationRequest(t, mux, http.MethodPost, "/api/v2/automation/jobs/"+jobID+"/run", map[string]interface{}{
		"trigger": "manual-ui",
	}, map[string]string{"X-User": "admin"})
	if runResp.Code != http.StatusOK {
		t.Fatalf("POST /api/v2/automation/jobs/{id}/run status = %d body = %s", runResp.Code, runResp.Body.String())
	}
	run := parseResponse(t, runResp).Data.(map[string]interface{})
	if run["status"] != "partial" {
		t.Fatalf("run status = %v, want partial", run["status"])
	}
	if run["summary"] != "1 target(s) succeeded, 1 target(s) failed" {
		t.Fatalf("run summary = %v", run["summary"])
	}

	runsResp := doAutomationRequest(t, mux, http.MethodGet, "/api/v2/automation/runs?job_id="+jobID, nil, nil)
	if runsResp.Code != http.StatusOK {
		t.Fatalf("GET /api/v2/automation/runs status = %d body = %s", runsResp.Code, runsResp.Body.String())
	}
	runs := parseResponse(t, runsResp)
	if runs.Total != 1 {
		t.Fatalf("run total = %d, want 1", runs.Total)
	}

	jobDetail := doAutomationRequest(t, mux, http.MethodGet, "/api/v2/automation/jobs/"+jobID, nil, nil)
	if jobDetail.Code != http.StatusOK {
		t.Fatalf("GET /api/v2/automation/jobs/{id} status = %d body = %s", jobDetail.Code, jobDetail.Body.String())
	}
	job := parseResponse(t, jobDetail).Data.(map[string]interface{})
	if job["last_status"] != "partial" {
		t.Fatalf("job last_status = %v, want partial", job["last_status"])
	}
}

func TestAutomationTriggerRestrictsProviders(t *testing.T) {
	api, mux, _ := setupTestAPI(t)
	api.automation.executor = &fakeAutomationExecutor{
		results: map[string]automationTargetResult{
			"10.0.1.1": {Status: "completed", Summary: "ok"},
		},
	}

	createJob := doAutomationRequest(t, mux, http.MethodPost, "/api/v2/automation/jobs", map[string]interface{}{
		"name":                           "deploy",
		"command":                        "echo deploy",
		"server_ids":                     []string{"srv-1"},
		"username":                       "ops",
		"password":                       "secret",
		"insecure_skip_host_key_verify":  true,
		"enabled":                        true,
		"trigger_providers":              []string{"github-actions"},
	}, map[string]string{"X-User": "admin"})
	if createJob.Code != http.StatusCreated {
		t.Fatalf("POST /api/v2/automation/jobs status = %d body = %s", createJob.Code, createJob.Body.String())
	}
	jobID := parseResponse(t, createJob).Data.(map[string]interface{})["id"].(string)

	forbidden := doAutomationRequest(t, mux, http.MethodPost, "/api/v2/automation/jobs/"+jobID+"/trigger", map[string]interface{}{
		"provider": "gitlab-ci",
	}, map[string]string{"X-User": "admin"})
	if forbidden.Code != http.StatusForbidden {
		t.Fatalf("POST /api/v2/automation/jobs/{id}/trigger status = %d body = %s", forbidden.Code, forbidden.Body.String())
	}

	accepted := doAutomationRequest(t, mux, http.MethodPost, "/api/v2/automation/jobs/"+jobID+"/trigger", map[string]interface{}{
		"provider":   "github-actions",
		"workflow":   "deploy.yml",
		"ref":        "refs/heads/main",
		"pipeline_id": "run-42",
	}, map[string]string{"X-User": "admin"})
	if accepted.Code != http.StatusAccepted {
		t.Fatalf("allowed trigger status = %d body = %s", accepted.Code, accepted.Body.String())
	}
}

func TestAutomationSchedulerRunsDueJob(t *testing.T) {
	api, mux, _ := setupTestAPI(t)
	executor := &fakeAutomationExecutor{
		results: map[string]automationTargetResult{
			"10.0.1.1": {Status: "completed", Summary: "ok"},
		},
		notify: make(chan string, 1),
	}
	api.automation.executor = executor

	createJob := doAutomationRequest(t, mux, http.MethodPost, "/api/v2/automation/jobs", map[string]interface{}{
		"name":                           "scheduled-check",
		"command":                        "echo ok",
		"server_ids":                     []string{"srv-1"},
		"username":                       "ops",
		"password":                       "secret",
		"insecure_skip_host_key_verify":  true,
		"enabled":                        true,
		"schedule":                       "1m",
	}, map[string]string{"X-User": "admin"})
	if createJob.Code != http.StatusCreated {
		t.Fatalf("POST /api/v2/automation/jobs status = %d body = %s", createJob.Code, createJob.Body.String())
	}
	jobID := parseResponse(t, createJob).Data.(map[string]interface{})["id"].(string)
	if _, err := api.automation.jobs.patch(jobID, func(item *automationJob) error {
		item.NextRunAt = time.Now().UTC().Add(-time.Second)
		return nil
	}); err != nil {
		t.Fatalf("patch scheduled job: %v", err)
	}

	api.runDueAutomationJobs(context.Background())
	select {
	case <-executor.notify:
	case <-time.After(2 * time.Second):
		t.Fatal("scheduler did not execute due job")
	}
}
