package operator

import (
	"context"
	"encoding/json"
	"testing"
	"time"
)

func TestRenderResourcesIncludesManagedObjects(t *testing.T) {
	cluster := SSHProxyCluster{
		Metadata: ObjectMeta{
			Name:      "example",
			Namespace: "ops",
			UID:       "uid-1",
		},
		Spec: SSHProxyClusterSpec{
			Config: ConfigSpec{
				ControlPlaneJSON: `{"listen_addr":":8443","session_secret":"secret","admin_user":"admin","admin_pass_hash":"hash","data_plane_addr":"http://127.0.0.1:9090"}`,
				DataPlaneINI:     "[server]\nport = 2222\n",
			},
			Secrets: map[string]string{
				"session_secret": "secret",
			},
			Persistence: PersistenceSpec{Enabled: true},
		},
	}

	rendered, err := RenderResources(cluster)
	if err != nil {
		t.Fatalf("RenderResources() error = %v", err)
	}
	if len(rendered.Objects) != 8 {
		t.Fatalf("RenderResources() object count = %d, want 8", len(rendered.Objects))
	}
	if rendered.ResourceNames["configMap"] != "example-config" {
		t.Fatalf("configMap name = %q", rendered.ResourceNames["configMap"])
	}
	configMap := rendered.Objects[1]
	data := configMap["data"].(map[string]interface{})
	if data["control-plane.json"] == "" || data["config.ini"] == "" {
		t.Fatalf("config map data = %#v", data)
	}
	controlDeployment := rendered.Objects[len(rendered.Objects)-2]
	spec := controlDeployment["spec"].(map[string]interface{})
	template := spec["template"].(map[string]interface{})
	podSpec := template["spec"].(map[string]interface{})
	if podSpec["serviceAccountName"] != "example-sa" {
		t.Fatalf("serviceAccountName = %#v", podSpec["serviceAccountName"])
	}
	containers := podSpec["containers"].([]map[string]interface{})
	env := containers[0]["env"].([]map[string]interface{})
	if len(env) != 1 || env[0]["name"] != "SSH_PROXY_CP_SESSION_SECRET" {
		t.Fatalf("control-plane env = %#v", env)
	}
}

func TestReconcilerAppliesResourcesAndUpdatesReadyStatus(t *testing.T) {
	fake := &fakeClient{}
	reconciler := &Reconciler{
		Client:    fake,
		Namespace: "ops",
		Now: func() time.Time {
			return time.Unix(1710000000, 0).UTC()
		},
	}
	cluster := SSHProxyCluster{
		Metadata: ObjectMeta{
			Name:       "example",
			Namespace:  "ops",
			UID:        "uid-1",
			Generation: 3,
		},
		Spec: SSHProxyClusterSpec{
			Config: ConfigSpec{
				ControlPlaneJSON: `{"listen_addr":":8443","session_secret":"secret","admin_user":"admin","admin_pass_hash":"hash","data_plane_addr":"http://127.0.0.1:9090"}`,
				DataPlaneINI:     "[server]\nport = 2222\n",
			},
		},
	}

	if err := reconciler.ReconcileCluster(context.Background(), cluster); err != nil {
		t.Fatalf("ReconcileCluster() error = %v", err)
	}
	if len(fake.applied) == 0 {
		t.Fatal("expected resources to be applied")
	}
	if fake.status.Phase != "Ready" || fake.status.ObservedGeneration != 3 {
		t.Fatalf("status = %+v", fake.status)
	}
	if fake.status.ResourceNames["dataPlaneDeployment"] != "example-data-plane" {
		t.Fatalf("resource names = %+v", fake.status.ResourceNames)
	}
}

func TestReconcilerWritesErrorStatusForInvalidSpec(t *testing.T) {
	fake := &fakeClient{}
	reconciler := &Reconciler{
		Client:    fake,
		Namespace: "ops",
	}
	cluster := SSHProxyCluster{
		Metadata: ObjectMeta{Name: "bad", Namespace: "ops", Generation: 1},
		Spec:     SSHProxyClusterSpec{},
	}
	if err := reconciler.ReconcileCluster(context.Background(), cluster); err == nil {
		t.Fatal("expected validation error")
	}
	if fake.status.Phase != "Error" {
		t.Fatalf("status = %+v", fake.status)
	}
}

type fakeClient struct {
	applied []map[string]interface{}
	status  SSHProxyClusterStatus
}

func (f *fakeClient) EnsureCRD(context.Context) error { return nil }

func (f *fakeClient) ListClusters(context.Context, string) ([]SSHProxyCluster, error) {
	return nil, nil
}

func (f *fakeClient) Apply(_ context.Context, obj map[string]interface{}) error {
	cloned := map[string]interface{}{}
	raw, _ := json.Marshal(obj)
	_ = json.Unmarshal(raw, &cloned)
	f.applied = append(f.applied, cloned)
	return nil
}

func (f *fakeClient) UpdateStatus(_ context.Context, _, _ string, status SSHProxyClusterStatus) error {
	f.status = status
	return nil
}
