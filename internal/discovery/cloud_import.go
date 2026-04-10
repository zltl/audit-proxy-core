package discovery

import (
	"encoding/json"
	"fmt"
	"strings"
)

// ImportCloudAssets normalizes provider-native instance inventory JSON into
// discovery assets that can be merged into the shared discovery inventory.
func ImportCloudAssets(provider string, payload []byte, tagFilters map[string]string, port int) ([]Asset, error) {
	provider = normalizeCloudProvider(provider)
	if port <= 0 {
		port = 22
	}

	switch provider {
	case "aws-ec2":
		return parseAWSAssets(payload, tagFilters, port)
	case "azure-vm":
		return parseAzureAssets(payload, tagFilters, port)
	case "gcp-compute":
		return parseGCPAssets(payload, tagFilters, port)
	case "aliyun-ecs":
		return parseAliyunAssets(payload, tagFilters, port)
	case "tencent-cvm":
		return parseTencentAssets(payload, tagFilters, port)
	default:
		return nil, fmt.Errorf("unsupported cloud provider %q", provider)
	}
}

func normalizeCloudProvider(provider string) string {
	provider = strings.ToLower(strings.TrimSpace(provider))
	provider = strings.NewReplacer("_", "-", " ", "-").Replace(provider)
	switch provider {
	case "aws", "ec2", "aws-ec2":
		return "aws-ec2"
	case "azure", "azure-vm", "azure-vms":
		return "azure-vm"
	case "gcp", "gce", "gcp-compute", "google-compute":
		return "gcp-compute"
	case "aliyun", "ecs", "aliyun-ecs":
		return "aliyun-ecs"
	case "tencent", "tencent-cvm", "cvm", "tencentcloud":
		return "tencent-cvm"
	default:
		return provider
	}
}

func parseAWSAssets(payload []byte, tagFilters map[string]string, port int) ([]Asset, error) {
	var doc struct {
		Reservations []struct {
			Instances []struct {
				InstanceID      string `json:"InstanceId"`
				PrivateIP       string `json:"PrivateIpAddress"`
				PublicIP        string `json:"PublicIpAddress"`
				Platform        string `json:"Platform"`
				PlatformDetails string `json:"PlatformDetails"`
				State           struct {
					Name string `json:"Name"`
				} `json:"State"`
				Placement struct {
					AvailabilityZone string `json:"AvailabilityZone"`
				} `json:"Placement"`
				Tags []struct{ Key, Value string } `json:"Tags"`
			} `json:"Instances"`
		} `json:"Reservations"`
	}
	if err := json.Unmarshal(payload, &doc); err != nil {
		return nil, fmt.Errorf("parse aws inventory: %w", err)
	}

	var assets []Asset
	for _, reservation := range doc.Reservations {
		for _, inst := range reservation.Instances {
			tags := make(map[string]string, len(inst.Tags)+4)
			for _, tag := range inst.Tags {
				tags[tag.Key] = tag.Value
			}
			if inst.Placement.AvailabilityZone != "" {
				tags["availability_zone"] = inst.Placement.AvailabilityZone
			}
			if !matchesTagFilters(tags, tagFilters) {
				continue
			}
			asset, ok := newCloudAsset("aws-ec2", inst.InstanceID, firstNonEmpty(tags["Name"], inst.InstanceID), firstNonEmpty(inst.PrivateIP, inst.PublicIP), port, firstNonEmpty(inst.PlatformDetails, inst.Platform), tags, inst.State.Name)
			if ok {
				assets = append(assets, asset)
			}
		}
	}
	return assets, nil
}

func parseAzureAssets(payload []byte, tagFilters map[string]string, port int) ([]Asset, error) {
	var doc []struct {
		ID             string            `json:"id"`
		VMID           string            `json:"vmId"`
		Name           string            `json:"name"`
		PrivateIPs     string            `json:"privateIps"`
		PublicIPs      string            `json:"publicIps"`
		ResourceGroup  string            `json:"resourceGroup"`
		Location       string            `json:"location"`
		PowerState     string            `json:"powerState"`
		Tags           map[string]string `json:"tags"`
		StorageProfile struct {
			ImageReference struct {
				Offer     string `json:"offer"`
				Publisher string `json:"publisher"`
				SKU       string `json:"sku"`
			} `json:"imageReference"`
		} `json:"storageProfile"`
	}
	if err := json.Unmarshal(payload, &doc); err != nil {
		return nil, fmt.Errorf("parse azure inventory: %w", err)
	}

	var assets []Asset
	for _, vm := range doc {
		tags := cloneTags(vm.Tags)
		if vm.ResourceGroup != "" {
			tags["resource_group"] = vm.ResourceGroup
		}
		if vm.Location != "" {
			tags["location"] = vm.Location
		}
		if !matchesTagFilters(tags, tagFilters) {
			continue
		}
		osName := firstNonEmpty(vm.StorageProfile.ImageReference.Offer, vm.StorageProfile.ImageReference.Publisher, vm.StorageProfile.ImageReference.SKU)
		asset, ok := newCloudAsset("azure-vm", firstNonEmpty(vm.VMID, pathTail(vm.ID), vm.Name), firstNonEmpty(vm.Name, vm.VMID), firstCSV(vm.PrivateIPs, vm.PublicIPs), port, osName, tags, vm.PowerState)
		if ok {
			assets = append(assets, asset)
		}
	}
	return assets, nil
}

func parseGCPAssets(payload []byte, tagFilters map[string]string, port int) ([]Asset, error) {
	var doc []struct {
		ID                string            `json:"id"`
		Name              string            `json:"name"`
		Status            string            `json:"status"`
		Zone              string            `json:"zone"`
		Labels            map[string]string `json:"labels"`
		NetworkInterfaces []struct {
			NetworkIP     string `json:"networkIP"`
			AccessConfigs []struct {
				NatIP string `json:"natIP"`
			} `json:"accessConfigs"`
		} `json:"networkInterfaces"`
		Disks []struct {
			Licenses []string `json:"licenses"`
		} `json:"disks"`
	}
	if err := json.Unmarshal(payload, &doc); err != nil {
		return nil, fmt.Errorf("parse gcp inventory: %w", err)
	}

	var assets []Asset
	for _, inst := range doc {
		tags := cloneTags(inst.Labels)
		if zone := pathTail(inst.Zone); zone != "" {
			tags["zone"] = zone
		}
		if !matchesTagFilters(tags, tagFilters) {
			continue
		}
		host := ""
		for _, nic := range inst.NetworkInterfaces {
			host = firstNonEmpty(nic.NetworkIP, host)
			if host == "" && len(nic.AccessConfigs) > 0 {
				host = nic.AccessConfigs[0].NatIP
			}
			if host != "" {
				break
			}
		}
		var licenses []string
		for _, disk := range inst.Disks {
			for _, license := range disk.Licenses {
				licenses = append(licenses, pathTail(license))
			}
		}
		asset, ok := newCloudAsset("gcp-compute", firstNonEmpty(inst.ID, inst.Name), inst.Name, host, port, strings.Join(licenses, ","), tags, inst.Status)
		if ok {
			assets = append(assets, asset)
		}
	}
	return assets, nil
}

func parseAliyunAssets(payload []byte, tagFilters map[string]string, port int) ([]Asset, error) {
	var doc struct {
		Instances struct {
			Instance []struct {
				InstanceID   string `json:"InstanceId"`
				InstanceName string `json:"InstanceName"`
				RegionID     string `json:"RegionId"`
				ZoneID       string `json:"ZoneId"`
				Status       string `json:"Status"`
				OSName       string `json:"OSName"`
				VPC          struct {
					PrivateIP struct {
						IPAddresses []string `json:"IpAddress"`
					} `json:"PrivateIpAddress"`
				} `json:"VpcAttributes"`
				PublicIP struct {
					IPAddresses []string `json:"IpAddress"`
				} `json:"PublicIpAddress"`
				Tags struct {
					Tag []struct {
						Key   string `json:"TagKey"`
						Value string `json:"TagValue"`
					} `json:"Tag"`
				} `json:"Tags"`
			} `json:"Instance"`
		} `json:"Instances"`
	}
	if err := json.Unmarshal(payload, &doc); err != nil {
		return nil, fmt.Errorf("parse aliyun inventory: %w", err)
	}

	var assets []Asset
	for _, inst := range doc.Instances.Instance {
		tags := make(map[string]string, len(inst.Tags.Tag)+4)
		for _, tag := range inst.Tags.Tag {
			tags[tag.Key] = tag.Value
		}
		if inst.RegionID != "" {
			tags["region"] = inst.RegionID
		}
		if inst.ZoneID != "" {
			tags["zone"] = inst.ZoneID
		}
		if !matchesTagFilters(tags, tagFilters) {
			continue
		}
		host := firstNonEmpty(firstString(inst.VPC.PrivateIP.IPAddresses), firstString(inst.PublicIP.IPAddresses))
		asset, ok := newCloudAsset("aliyun-ecs", inst.InstanceID, firstNonEmpty(inst.InstanceName, inst.InstanceID), host, port, inst.OSName, tags, inst.Status)
		if ok {
			assets = append(assets, asset)
		}
	}
	return assets, nil
}

func parseTencentAssets(payload []byte, tagFilters map[string]string, port int) ([]Asset, error) {
	var doc struct {
		Response struct {
			InstanceSet []struct {
				InstanceID      string   `json:"InstanceId"`
				InstanceName    string   `json:"InstanceName"`
				InstanceState   string   `json:"InstanceState"`
				OperatingSystem string   `json:"OperatingSystem"`
				PrivateIPs      []string `json:"PrivateIpAddresses"`
				PublicIPs       []string `json:"PublicIpAddresses"`
				Placement       struct {
					Zone string `json:"Zone"`
				} `json:"Placement"`
				Tags []struct{ Key, Value string } `json:"Tags"`
			} `json:"InstanceSet"`
		} `json:"Response"`
	}
	if err := json.Unmarshal(payload, &doc); err != nil {
		return nil, fmt.Errorf("parse tencent inventory: %w", err)
	}

	var assets []Asset
	for _, inst := range doc.Response.InstanceSet {
		tags := make(map[string]string, len(inst.Tags)+4)
		for _, tag := range inst.Tags {
			tags[tag.Key] = tag.Value
		}
		if inst.Placement.Zone != "" {
			tags["zone"] = inst.Placement.Zone
		}
		if !matchesTagFilters(tags, tagFilters) {
			continue
		}
		host := firstNonEmpty(firstString(inst.PrivateIPs), firstString(inst.PublicIPs))
		asset, ok := newCloudAsset("tencent-cvm", inst.InstanceID, firstNonEmpty(inst.InstanceName, inst.InstanceID), host, port, inst.OperatingSystem, tags, inst.InstanceState)
		if ok {
			assets = append(assets, asset)
		}
	}
	return assets, nil
}

func newCloudAsset(provider, instanceID, name, host string, port int, osName string, tags map[string]string, providerStatus string) (Asset, bool) {
	host = strings.TrimSpace(host)
	if host == "" {
		return Asset{}, false
	}
	instanceID = strings.TrimSpace(instanceID)
	if instanceID == "" {
		instanceID = host
	}
	if port <= 0 {
		port = 22
	}
	tags = cloneTags(tags)
	tags["source"] = "cloud"
	tags["cloud_provider"] = provider
	tags["instance_id"] = instanceID
	if providerStatus != "" {
		tags["provider_status"] = strings.ToLower(strings.TrimSpace(providerStatus))
	}
	asset := Asset{
		ID:     provider + ":" + instanceID,
		Host:   host,
		Port:   port,
		Name:   strings.TrimSpace(name),
		OS:     strings.TrimSpace(osName),
		Tags:   tags,
		Status: "discovered",
	}
	if asset.Name == "" {
		asset.Name = host
	}
	return asset, true
}

func matchesTagFilters(tags, filters map[string]string) bool {
	for key, value := range filters {
		if tags[key] != value {
			return false
		}
	}
	return true
}

func cloneTags(tags map[string]string) map[string]string {
	if len(tags) == 0 {
		return make(map[string]string)
	}
	cloned := make(map[string]string, len(tags))
	for k, v := range tags {
		cloned[k] = v
	}
	return cloned
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			return trimmed
		}
	}
	return ""
}

func firstString(values []string) string {
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			return trimmed
		}
	}
	return ""
}

func firstCSV(values ...string) string {
	for _, value := range values {
		for _, part := range strings.Split(value, ",") {
			if trimmed := strings.TrimSpace(part); trimmed != "" {
				return trimmed
			}
		}
	}
	return ""
}

func pathTail(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	parts := strings.Split(value, "/")
	return parts[len(parts)-1]
}
