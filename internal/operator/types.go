package operator

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

const (
	Group              = "proxy.sshproxy.io"
	Version            = "v1alpha1"
	Kind               = "SSHProxyCluster"
	Plural             = "sshproxyclusters"
	FullCRDName        = Plural + "." + Group
	FieldManager       = "ssh-proxy-operator"
	DefaultNamespace   = "default"
	DefaultBaseImage   = "ghcr.io/ssh-proxy-core/ssh-proxy-core"
	DefaultPullPolicy  = "IfNotPresent"
	DefaultServiceType = "LoadBalancer"
)

type SSHProxyCluster struct {
	APIVersion string                `json:"apiVersion"`
	Kind       string                `json:"kind"`
	Metadata   ObjectMeta            `json:"metadata"`
	Spec       SSHProxyClusterSpec   `json:"spec"`
	Status     SSHProxyClusterStatus `json:"status,omitempty"`
}

type ObjectMeta struct {
	Name       string            `json:"name"`
	Namespace  string            `json:"namespace,omitempty"`
	UID        string            `json:"uid,omitempty"`
	Generation int64             `json:"generation,omitempty"`
	Labels     map[string]string `json:"labels,omitempty"`
}

type SSHProxyClusterList struct {
	Items []SSHProxyCluster `json:"items"`
}

type SSHProxyClusterSpec struct {
	Image        ImageSpec         `json:"image,omitempty"`
	ControlPlane PlaneSpec         `json:"controlPlane,omitempty"`
	DataPlane    PlaneSpec         `json:"dataPlane,omitempty"`
	Service      ServiceSpec       `json:"service,omitempty"`
	Persistence  PersistenceSpec   `json:"persistence,omitempty"`
	Config       ConfigSpec        `json:"config"`
	Secrets      map[string]string `json:"secrets,omitempty"`
}

type ImageSpec struct {
	Repository string `json:"repository,omitempty"`
	Tag        string `json:"tag,omitempty"`
	PullPolicy string `json:"pullPolicy,omitempty"`
}

type PlaneSpec struct {
	Replicas int32 `json:"replicas,omitempty"`
	Port     int32 `json:"port,omitempty"`
}

type ServiceSpec struct {
	Type     string `json:"type,omitempty"`
	SSHPort  int32  `json:"sshPort,omitempty"`
	HTTPPort int32  `json:"httpPort,omitempty"`
}

type PersistenceSpec struct {
	Enabled          bool   `json:"enabled,omitempty"`
	Size             string `json:"size,omitempty"`
	AccessMode       string `json:"accessMode,omitempty"`
	StorageClassName string `json:"storageClassName,omitempty"`
}

type ConfigSpec struct {
	ControlPlaneJSON string `json:"controlPlaneJSON"`
	DataPlaneINI     string `json:"dataPlaneINI"`
}

type SSHProxyClusterStatus struct {
	ObservedGeneration int64             `json:"observedGeneration,omitempty"`
	Phase              string            `json:"phase,omitempty"`
	Message            string            `json:"message,omitempty"`
	ResourceNames      map[string]string `json:"resourceNames,omitempty"`
	LastReconciledAt   time.Time         `json:"lastReconciledAt,omitempty"`
}

func (c *SSHProxyCluster) Normalize(defaultNamespace string) {
	if c == nil {
		return
	}
	if strings.TrimSpace(c.APIVersion) == "" {
		c.APIVersion = Group + "/" + Version
	}
	if strings.TrimSpace(c.Kind) == "" {
		c.Kind = Kind
	}
	if strings.TrimSpace(c.Metadata.Namespace) == "" {
		c.Metadata.Namespace = firstNonEmpty(defaultNamespace, DefaultNamespace)
	}
	if strings.TrimSpace(c.Spec.Image.Repository) == "" {
		c.Spec.Image.Repository = DefaultBaseImage
	}
	if strings.TrimSpace(c.Spec.Image.PullPolicy) == "" {
		c.Spec.Image.PullPolicy = DefaultPullPolicy
	}
	if c.Spec.ControlPlane.Replicas <= 0 {
		c.Spec.ControlPlane.Replicas = 1
	}
	if c.Spec.DataPlane.Replicas <= 0 {
		c.Spec.DataPlane.Replicas = 1
	}
	if c.Spec.ControlPlane.Port <= 0 {
		c.Spec.ControlPlane.Port = 8443
	}
	if c.Spec.DataPlane.Port <= 0 {
		c.Spec.DataPlane.Port = 2222
	}
	if c.Spec.Service.SSHPort <= 0 {
		c.Spec.Service.SSHPort = c.Spec.DataPlane.Port
	}
	if c.Spec.Service.HTTPPort <= 0 {
		c.Spec.Service.HTTPPort = 443
	}
	if strings.TrimSpace(c.Spec.Service.Type) == "" {
		c.Spec.Service.Type = DefaultServiceType
	}
	if c.Spec.Persistence.Size == "" {
		c.Spec.Persistence.Size = "10Gi"
	}
	if c.Spec.Persistence.AccessMode == "" {
		c.Spec.Persistence.AccessMode = "ReadWriteOnce"
	}
}

func (c *SSHProxyCluster) Validate() error {
	if c == nil {
		return fmt.Errorf("cluster is required")
	}
	if strings.TrimSpace(c.Metadata.Name) == "" {
		return fmt.Errorf("metadata.name is required")
	}
	if strings.TrimSpace(c.Spec.Config.ControlPlaneJSON) == "" {
		return fmt.Errorf("spec.config.controlPlaneJSON is required")
	}
	if strings.TrimSpace(c.Spec.Config.DataPlaneINI) == "" {
		return fmt.Errorf("spec.config.dataPlaneINI is required")
	}
	var controlPlane map[string]interface{}
	if err := json.Unmarshal([]byte(c.Spec.Config.ControlPlaneJSON), &controlPlane); err != nil {
		return fmt.Errorf("spec.config.controlPlaneJSON must be valid JSON: %w", err)
	}
	if !strings.Contains(c.Spec.Config.DataPlaneINI, "[") {
		return fmt.Errorf("spec.config.dataPlaneINI must look like an INI document")
	}
	return nil
}

func (c SSHProxyCluster) Namespace() string {
	return firstNonEmpty(c.Metadata.Namespace, DefaultNamespace)
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			return trimmed
		}
	}
	return ""
}
