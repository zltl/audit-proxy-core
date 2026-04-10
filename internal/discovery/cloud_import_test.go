package discovery

import "testing"

func TestImportCloudAssetsAWS(t *testing.T) {
	assets, err := ImportCloudAssets("aws", []byte(`{
		"Reservations": [{
			"Instances": [{
				"InstanceId": "i-123",
				"PrivateIpAddress": "10.0.0.10",
				"PlatformDetails": "Linux/UNIX",
				"State": {"Name": "running"},
				"Placement": {"AvailabilityZone": "us-east-1a"},
				"Tags": [{"Key": "Name", "Value": "bastion"}, {"Key": "env", "Value": "prod"}]
			}]
		}]
	}`), map[string]string{"env": "prod"}, 22)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(assets) != 1 {
		t.Fatalf("expected 1 asset, got %d", len(assets))
	}
	if assets[0].ID != "aws-ec2:i-123" || assets[0].Host != "10.0.0.10" {
		t.Fatalf("unexpected asset: %+v", assets[0])
	}
	if assets[0].Tags["availability_zone"] != "us-east-1a" {
		t.Fatalf("expected aws zone tag, got %+v", assets[0].Tags)
	}
}

func TestImportCloudAssetsAzure(t *testing.T) {
	assets, err := ImportCloudAssets("azure", []byte(`[
		{
			"vmId": "vm-123",
			"name": "jumpbox",
			"privateIps": "10.0.1.10",
			"resourceGroup": "rg-prod",
			"location": "eastus",
			"powerState": "VM running",
			"tags": {"env": "prod"},
			"storageProfile": {"imageReference": {"offer": "UbuntuServer"}}
		}
	]`), map[string]string{"env": "prod"}, 22)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(assets) != 1 || assets[0].ID != "azure-vm:vm-123" {
		t.Fatalf("unexpected assets: %+v", assets)
	}
	if assets[0].Tags["resource_group"] != "rg-prod" {
		t.Fatalf("expected resource group tag, got %+v", assets[0].Tags)
	}
}

func TestImportCloudAssetsGCP(t *testing.T) {
	assets, err := ImportCloudAssets("gcp", []byte(`[
		{
			"id": "123456",
			"name": "gce-1",
			"status": "RUNNING",
			"zone": "https://www.googleapis.com/compute/v1/projects/test/zones/us-central1-a",
			"labels": {"env": "prod"},
			"networkInterfaces": [{"networkIP": "10.0.2.10"}],
			"disks": [{"licenses": ["https://www.googleapis.com/compute/v1/projects/ubuntu-os-cloud/global/licenses/ubuntu-2204-lts"]}]
		}
	]`), map[string]string{"env": "prod"}, 22)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(assets) != 1 || assets[0].Tags["zone"] != "us-central1-a" {
		t.Fatalf("unexpected assets: %+v", assets)
	}
}

func TestImportCloudAssetsAliyun(t *testing.T) {
	assets, err := ImportCloudAssets("aliyun", []byte(`{
		"Instances": {
			"Instance": [{
				"InstanceId": "i-ecs1",
				"InstanceName": "ecs-1",
				"RegionId": "cn-hangzhou",
				"ZoneId": "cn-hangzhou-h",
				"Status": "Running",
				"OSName": "Alibaba Cloud Linux",
				"VpcAttributes": {"PrivateIpAddress": {"IpAddress": ["10.0.3.10"]}},
				"Tags": {"Tag": [{"TagKey": "env", "TagValue": "prod"}]}
			}]
		}
	}`), map[string]string{"env": "prod"}, 22)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(assets) != 1 || assets[0].ID != "aliyun-ecs:i-ecs1" {
		t.Fatalf("unexpected assets: %+v", assets)
	}
}

func TestImportCloudAssetsTencent(t *testing.T) {
	assets, err := ImportCloudAssets("tencent", []byte(`{
		"Response": {
			"InstanceSet": [{
				"InstanceId": "ins-123",
				"InstanceName": "cvm-1",
				"InstanceState": "RUNNING",
				"OperatingSystem": "TencentOS Server 3.1",
				"PrivateIpAddresses": ["10.0.4.10"],
				"Placement": {"Zone": "ap-shanghai-2"},
				"Tags": [{"Key": "env", "Value": "prod"}]
			}]
		}
	}`), map[string]string{"env": "prod"}, 22)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(assets) != 1 || assets[0].Tags["zone"] != "ap-shanghai-2" {
		t.Fatalf("unexpected assets: %+v", assets)
	}
}

func TestImportCloudAssetsUnsupportedProvider(t *testing.T) {
	if _, err := ImportCloudAssets("digitalocean", []byte(`[]`), nil, 22); err == nil {
		t.Fatal("expected unsupported provider error")
	}
}

func TestInventoryUpsertAssetsPreservesRegisteredStatus(t *testing.T) {
	inv := NewInventory(t.TempDir())
	if newCount := inv.UpsertAssets([]Asset{{
		ID:     "aws-ec2:i-123",
		Host:   "10.0.0.10",
		Port:   22,
		Name:   "bastion",
		Status: "registered",
		Tags:   map[string]string{"source": "cloud"},
	}}); newCount != 1 {
		t.Fatalf("expected first upsert to create asset, got %d", newCount)
	}

	if newCount := inv.UpsertAssets([]Asset{{
		ID:     "aws-ec2:i-123",
		Host:   "10.0.0.11",
		Port:   22,
		Name:   "bastion-updated",
		Status: "discovered",
		Tags:   map[string]string{"env": "prod"},
	}}); newCount != 0 {
		t.Fatalf("expected update to reuse existing asset, got %d", newCount)
	}

	asset, err := inv.Get("aws-ec2:i-123")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if asset.Status != "registered" || asset.Host != "10.0.0.11" || asset.Tags["env"] != "prod" {
		t.Fatalf("unexpected merged asset: %+v", asset)
	}
}
