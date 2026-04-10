package discovery

import "testing"

func TestImportCMDBAssetsServiceNow(t *testing.T) {
	assets, err := ImportCMDBAssets("servicenow", []byte(`{
		"result": [{
			"sys_id": "cmdb-123",
			"name": "bastion-01",
			"ip_address": "10.20.0.10",
			"os": "Ubuntu 22.04",
			"u_ssh_port": "2222",
			"sys_class_name": "cmdb_ci_linux_server",
			"u_environment": "prod"
		}]
	}`), CMDBImportConfig{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(assets) != 1 {
		t.Fatalf("expected 1 asset, got %d", len(assets))
	}
	if assets[0].ID != "servicenow:cmdb-123" || assets[0].Port != 2222 {
		t.Fatalf("unexpected asset: %+v", assets[0])
	}
	if assets[0].Tags["u_environment"] != "prod" || assets[0].Tags["sys_class_name"] != "cmdb_ci_linux_server" {
		t.Fatalf("unexpected tags: %+v", assets[0].Tags)
	}
}

func TestImportCMDBAssetsCustomAPI(t *testing.T) {
	assets, err := ImportCMDBAssets("custom-api", []byte(`{
		"items": [{
			"id": "srv-01",
			"displayName": "prod-app-01",
			"connection": {"host": "10.30.0.15", "port": 2200},
			"platform": {"os": "Debian 12"},
			"env": "prod",
			"owner": "ops"
		}]
	}`), CMDBImportConfig{
		ItemsPath:   "items",
		IDField:     "id",
		NameField:   "displayName",
		HostField:   "connection.host",
		PortField:   "connection.port",
		OSField:     "platform.os",
		TagFields:   []string{"env", "owner"},
		DefaultPort: 22,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(assets) != 1 {
		t.Fatalf("expected 1 asset, got %d", len(assets))
	}
	if assets[0].ID != "custom-api:srv-01" || assets[0].Host != "10.30.0.15" || assets[0].Port != 2200 {
		t.Fatalf("unexpected asset: %+v", assets[0])
	}
	if assets[0].Tags["env"] != "prod" || assets[0].Tags["owner"] != "ops" {
		t.Fatalf("unexpected tags: %+v", assets[0].Tags)
	}
}

func TestImportCMDBAssetsCustomAPIRequiresHostField(t *testing.T) {
	if _, err := ImportCMDBAssets("custom-api", []byte(`{"items":[]}`), CMDBImportConfig{}); err == nil {
		t.Fatal("expected host_field validation error")
	}
}
