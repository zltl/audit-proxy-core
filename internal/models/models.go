// Package models defines the core data types used throughout the SSH Proxy
// control plane. All structs include JSON tags for API serialization and are
// designed to be passed between the server, data-plane client, and templates.
package models

import "time"

// User represents an authenticated control-plane user.
type User struct {
	Username    string    `json:"username"`
	DisplayName string    `json:"display_name"`
	Email       string    `json:"email"`
	Role        string    `json:"role"` // "admin", "operator", "viewer"
	MFASecret   string    `json:"-"`    // never serialised to clients
	PassHash    string    `json:"-"`    // bcrypt hash, never serialised
	Enabled     bool      `json:"enabled"`
	MFAEnabled  bool      `json:"mfa_enabled"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
	LastLogin   time.Time `json:"last_login"`
	AllowedIPs  []string  `json:"allowed_ips,omitempty"`
}

// Session describes an active or historical SSH proxy session.
type Session struct {
	ID                string    `json:"id"`
	Username          string    `json:"username"`
	SourceIP          string    `json:"source_ip"`
	ClientVersion     string    `json:"client_version,omitempty"`
	ClientOS          string    `json:"client_os,omitempty"`
	DeviceFingerprint string    `json:"device_fingerprint,omitempty"`
	InstanceID        string    `json:"instance_id,omitempty"`
	TargetHost        string    `json:"target_host"`
	TargetPort        int       `json:"target_port"`
	StartTime         time.Time `json:"start_time"`
	Duration          string    `json:"duration"`
	BytesIn           int64     `json:"bytes_in"`
	BytesOut          int64     `json:"bytes_out"`
	Status            string    `json:"status"` // "active", "closed", "terminated"
	RecordingFile     string    `json:"recording_file,omitempty"`
}

// Server represents an upstream SSH server managed by the proxy.
type Server struct {
	ID          string            `json:"id"`
	Host        string            `json:"host"`
	Port        int               `json:"port"`
	Name        string            `json:"name"`
	Group       string            `json:"group"`
	Status      string            `json:"status"` // "online", "offline", "draining"
	Healthy     bool              `json:"healthy"`
	Maintenance bool              `json:"maintenance"`
	Weight      int               `json:"weight"`
	MaxSessions int               `json:"max_sessions"`
	Sessions    int               `json:"sessions"`
	Tags        map[string]string `json:"tags,omitempty"`
	CheckedAt   time.Time         `json:"checked_at"`
}

// DrainStatus describes the local data-plane drain/upgrade state.
type DrainStatus struct {
	Status         string `json:"status,omitempty"`
	Draining       bool   `json:"draining"`
	ActiveSessions int    `json:"active_sessions"`
}

// AuditEvent records a security-relevant action in the system.
type AuditEvent struct {
	ID         string    `json:"id"`
	Timestamp  time.Time `json:"timestamp"`
	EventType  string    `json:"event_type"` // "login", "logout", "session_start", …
	Username   string    `json:"username"`
	SourceIP   string    `json:"source_ip"`
	TargetHost string    `json:"target_host,omitempty"`
	Details    string    `json:"details,omitempty"`
	SessionID  string    `json:"session_id,omitempty"`
}

// Route defines a traffic-routing rule in the proxy.
type Route struct {
	Name     string `json:"name"`
	Pattern  string `json:"pattern"`
	Backend  string `json:"backend"`
	Policy   string `json:"policy,omitempty"`
	Priority int    `json:"priority"`
	Enabled  bool   `json:"enabled"`
}

// PolicyRule expresses an authorisation policy.
type PolicyRule struct {
	Name       string            `json:"name"`
	Role       string            `json:"role"`
	Action     string            `json:"action"` // "allow" or "deny"
	Resources  []string          `json:"resources"`
	Operations []string          `json:"operations"`
	Conditions map[string]string `json:"conditions,omitempty"`
}

// DashboardStats is the aggregated payload returned for the main dashboard.
type DashboardStats struct {
	ActiveSessions  int               `json:"active_sessions"`
	TotalUsers      int               `json:"total_users"`
	TotalServers    int               `json:"total_servers"`
	HealthyServers  int               `json:"healthy_servers"`
	AuthSuccessRate float64           `json:"auth_success_rate"`
	RecentEvents    []AuditEvent      `json:"recent_events"`
	SessionTrend    []TimeSeriesPoint `json:"session_trend"`
}

// DashboardSnapshot is the realtime payload pushed to dashboard WebSocket clients.
type DashboardSnapshot struct {
	Stats    DashboardStats `json:"stats"`
	Sessions []Session      `json:"sessions"`
	Events   []AuditEvent   `json:"events"`
	Servers  []Server       `json:"servers"`
}

// TimeSeriesPoint is a single data-point on a time-series chart.
type TimeSeriesPoint struct {
	Time  time.Time `json:"time"`
	Value float64   `json:"value"`
}

// ConfigVersion tracks a versioned snapshot of the proxy configuration.
type ConfigVersion struct {
	Version   int       `json:"version"`
	Content   string    `json:"content"`
	Author    string    `json:"author"`
	Comment   string    `json:"comment"`
	Timestamp time.Time `json:"timestamp"`
}

// HealthStatus describes the health of the data-plane process.
type HealthStatus struct {
	Status  string `json:"status"` // "healthy", "degraded", "unhealthy"
	Version string `json:"version,omitempty"`
	Uptime  string `json:"uptime,omitempty"`
}

// DataPlaneConfig holds the running configuration of the C data plane.
type DataPlaneConfig struct {
	Raw map[string]interface{} `json:"raw"`
}
