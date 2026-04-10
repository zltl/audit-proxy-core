package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestDiscoverySyncSourceRunOfflinesMissingAssets(t *testing.T) {
	api, _, _ := setupTestAPI(t)
	ds := api.initDiscovery()
	source, err := ds.syncSources.create(discoverySyncSource{
		ID:           "src-cloud",
		Name:         "aws-prod",
		Kind:         discoverySyncKindCloud,
		Provider:     "aws",
		Interval:     "1m",
		Enabled:      true,
		AutoRegister: true,
		Content: json.RawMessage(`{
			"Reservations": [{
				"Instances": [{
					"InstanceId": "i-123",
					"PrivateIpAddress": "10.80.0.10",
					"Tags": [{"Key": "Name", "Value": "bastion"}]
				}]
			}]
		}`),
		CreatedAt: time.Now().UTC(),
		UpdatedAt: time.Now().UTC(),
	})
	if err != nil {
		t.Fatalf("create source: %v", err)
	}

	updated, result, err := api.runDiscoverySyncSource(context.Background(), source.ID)
	if err != nil {
		t.Fatalf("run source: %v", err)
	}
	if result.Imported != 1 || result.Registered != 1 || updated.LastStatus != "success" {
		t.Fatalf("unexpected run result: %+v source=%+v", result, updated)
	}
	asset, err := ds.inventory.Get("aws-ec2:i-123")
	if err != nil {
		t.Fatalf("expected asset: %v", err)
	}
	if asset.Status != "registered" || asset.Tags[discoverySyncSourceTagKey] != source.ID {
		t.Fatalf("unexpected synced asset: %+v", asset)
	}
	if _, ok := api.servers.servers[discoveryManagedServerID(asset.ID)]; !ok {
		t.Fatalf("expected managed server for asset %s", asset.ID)
	}

	source.Content = json.RawMessage(`{"Reservations":[]}`)
	if _, err := ds.syncSources.update(source.ID, source); err != nil {
		t.Fatalf("update source: %v", err)
	}
	updated, result, err = api.runDiscoverySyncSource(context.Background(), source.ID)
	if err != nil {
		t.Fatalf("run empty source: %v", err)
	}
	if result.Offlined != 1 || updated.LastOfflined != 1 {
		t.Fatalf("expected 1 offlined asset, got result=%+v source=%+v", result, updated)
	}
	asset, err = ds.inventory.Get("aws-ec2:i-123")
	if err != nil {
		t.Fatalf("expected asset record: %v", err)
	}
	if asset.Status != "offline" {
		t.Fatalf("expected offline asset, got %+v", asset)
	}
	if _, ok := api.servers.servers[discoveryManagedServerID(asset.ID)]; ok {
		t.Fatalf("expected managed server removal for offline asset")
	}
}

func TestDiscoverySyncSourceAPIEndpoints(t *testing.T) {
	api, mux, _ := setupTestAPI(t)

	createReq := httptest.NewRequest(http.MethodPost, "/api/v2/discovery/sources", bytes.NewBufferString(`{
		"name": "ansible-prod",
		"kind": "ansible",
		"interval": "30m",
		"content_text": "[web]\nweb-1 ansible_host=10.81.0.10 ansible_port=2200 env=prod\n",
		"auto_register": true
	}`))
	createReq.Header.Set("Content-Type", "application/json")
	createRR := httptest.NewRecorder()
	mux.ServeHTTP(createRR, createReq)
	if createRR.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", createRR.Code, createRR.Body.String())
	}

	listReq := httptest.NewRequest(http.MethodGet, "/api/v2/discovery/sources", nil)
	listRR := httptest.NewRecorder()
	mux.ServeHTTP(listRR, listReq)
	if listRR.Code != http.StatusOK || !strings.Contains(listRR.Body.String(), "ansible-prod") {
		t.Fatalf("unexpected list response: %d %s", listRR.Code, listRR.Body.String())
	}

	var createResp APIResponse
	if err := json.Unmarshal(createRR.Body.Bytes(), &createResp); err != nil {
		t.Fatalf("decode create response: %v", err)
	}
	rawSource, err := json.Marshal(createResp.Data)
	if err != nil {
		t.Fatalf("re-marshal create data: %v", err)
	}
	var created discoverySyncSource
	if err := json.Unmarshal(rawSource, &created); err != nil {
		t.Fatalf("decode created source: %v", err)
	}

	runReq := httptest.NewRequest(http.MethodPost, "/api/v2/discovery/sources/"+created.ID+"/run", nil)
	runRR := httptest.NewRecorder()
	mux.ServeHTTP(runRR, runReq)
	if runRR.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", runRR.Code, runRR.Body.String())
	}
	if _, err := api.initDiscovery().inventory.Get("ansible:web-1"); err != nil {
		t.Fatalf("expected ansible asset: %v", err)
	}
}

func TestDiscoverySyncSchedulerRunsDueSources(t *testing.T) {
	api, _, _ := setupTestAPI(t)
	ds := api.initDiscovery()
	now := time.Now().UTC()
	source, err := ds.syncSources.create(discoverySyncSource{
		ID:        "src-cmdb",
		Name:      "servicenow-prod",
		Kind:      discoverySyncKindCMDB,
		Provider:  "servicenow",
		Interval:  "1m",
		Enabled:   true,
		Content:   json.RawMessage(`{"result":[{"sys_id":"cmdb-1","ip_address":"10.82.0.10","name":"cmdb-host"}]}`),
		NextRunAt: now.Add(-time.Minute),
		CreatedAt: now,
		UpdatedAt: now,
	})
	if err != nil {
		t.Fatalf("create source: %v", err)
	}
	ds.syncScheduler = newDiscoverySyncScheduler(api, ds.syncSources)
	ds.syncScheduler.now = func() time.Time { return now }
	ds.syncScheduler.runDueSourcesOnce(context.Background())

	updated, ok := ds.syncSources.get(source.ID)
	if !ok {
		t.Fatalf("expected source after scheduler run")
	}
	if updated.LastStatus != "success" || updated.LastImported != 1 || updated.NextRunAt.Before(now.Add(59*time.Second)) {
		t.Fatalf("unexpected scheduler-updated source: %+v", updated)
	}
}
