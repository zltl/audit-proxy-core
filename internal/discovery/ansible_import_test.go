package discovery

import "testing"

func TestImportAnsibleAssetsJSON(t *testing.T) {
	assets, err := ImportAnsibleAssets("json", []byte(`{
		"_meta": {
			"hostvars": {
				"web-1": {
					"ansible_host": "10.50.0.10",
					"ansible_port": "2222",
					"ansible_distribution": "Ubuntu",
					"env": "prod"
				}
			}
		},
		"web": {
			"hosts": ["web-1"]
		},
		"prod": {
			"children": ["web"]
		}
	}`), AnsibleImportConfig{DefaultPort: 22})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(assets) != 1 {
		t.Fatalf("expected 1 asset, got %d", len(assets))
	}
	if assets[0].ID != "ansible:web-1" || assets[0].Host != "10.50.0.10" || assets[0].Port != 2222 {
		t.Fatalf("unexpected asset: %+v", assets[0])
	}
	if assets[0].Tags["ansible_groups"] != "prod,web" {
		t.Fatalf("unexpected ansible groups: %+v", assets[0].Tags)
	}
}

func TestImportAnsibleAssetsINI(t *testing.T) {
	assets, err := ImportAnsibleAssets("ini", []byte(`
[web]
web-1 ansible_host=10.60.0.10 ansible_port=2200 env=prod

[prod:children]
web
`), AnsibleImportConfig{DefaultPort: 22})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(assets) != 1 {
		t.Fatalf("expected 1 asset, got %d", len(assets))
	}
	if assets[0].Host != "10.60.0.10" || assets[0].Port != 2200 {
		t.Fatalf("unexpected asset: %+v", assets[0])
	}
	if assets[0].Tags["ansible_groups"] != "prod,web" || assets[0].Tags["env"] != "prod" {
		t.Fatalf("unexpected tags: %+v", assets[0].Tags)
	}
}
