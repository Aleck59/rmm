// Package protocol defines the wire types of the agent API, shared by the
// agent and the server. They mirror the schemas in docs/api/openapi.yaml
// (Agent API section); keep both in sync. Unknown JSON fields are ignored on
// decode so newer agents and servers stay compatible within a major version.
package protocol

import "time"

// APIVersionPath is the base path of the agent API.
const APIVersionPath = "/api/agent/v1"

// AgentConfig is the declarative collection configuration handed to agents.
// It is the only thing the server "tells" an agent in Stage 1.
type AgentConfig struct {
	ConfigVersion        int  `json:"config_version"`
	MetricsSendIntervalS int  `json:"metrics_send_interval_s"`
	CPUSampleIntervalS   int  `json:"cpu_sample_interval_s"`
	DiskIntervalS        int  `json:"disk_interval_s"`
	InventoryIntervalS   int  `json:"inventory_interval_s"`
	InventoryFullResendS int  `json:"inventory_full_resend_s"`
	CollectLoggedOnUser  bool `json:"collect_logged_on_user"`
}

// DefaultAgentConfig is used by agents until the server's config is fetched.
func DefaultAgentConfig() AgentConfig {
	return AgentConfig{
		ConfigVersion:        0,
		MetricsSendIntervalS: 60,
		CPUSampleIntervalS:   15,
		DiskIntervalS:        300,
		InventoryIntervalS:   3600,
		InventoryFullResendS: 86400,
		CollectLoggedOnUser:  false,
	}
}

// OSInfo describes the operating system.
type OSInfo struct {
	Name           string     `json:"name"`
	Version        string     `json:"version"`
	Build          int        `json:"build,omitempty"`
	UBR            int        `json:"ubr,omitempty"`
	DisplayVersion string     `json:"display_version,omitempty"`
	Arch           string     `json:"arch"`
	InstallDate    *time.Time `json:"install_date,omitempty"`
	LastBoot       *time.Time `json:"last_boot,omitempty"`
}

// HardwareIDs help detect duplicates and reinstalls; never used to authenticate.
type HardwareIDs struct {
	MachineGUID  string   `json:"machine_guid,omitempty"`
	SMBIOSUUID   *string  `json:"smbios_uuid,omitempty"`
	SerialNumber string   `json:"serial_number,omitempty"`
	MACs         []string `json:"macs,omitempty"`
}

// EnrollRequest is sent once, authenticated by an enrollment token.
type EnrollRequest struct {
	AgentUID     string      `json:"agent_uid"`
	AgentVersion string      `json:"agent_version"`
	Hostname     string      `json:"hostname"`
	Domain       string      `json:"domain,omitempty"`
	OS           OSInfo      `json:"os"`
	HardwareIDs  HardwareIDs `json:"hardware_ids"`
}

// EnrollResponse carries the device token, returned exactly once.
type EnrollResponse struct {
	DeviceID    int64       `json:"device_id"`
	DeviceToken string      `json:"device_token"`
	Status      string      `json:"status"` // active | pending
	Config      AgentConfig `json:"config"`
}

// HostSample is one averaged host metrics sample.
type HostSample struct {
	TS            time.Time `json:"ts"`
	CPUPct        float64   `json:"cpu_pct"`
	CPUMaxPct     float64   `json:"cpu_max_pct"`
	MemUsedBytes  int64     `json:"mem_used_bytes"`
	MemTotalBytes int64     `json:"mem_total_bytes"`
}

// DiskSample is one volume free-space sample.
type DiskSample struct {
	TS         time.Time `json:"ts"`
	Volume     string    `json:"volume"`
	TotalBytes int64     `json:"total_bytes"`
	FreeBytes  int64     `json:"free_bytes"`
}

// CollectorError reports a non-fatal collector failure.
type CollectorError struct {
	Collector string     `json:"collector"`
	Message   string     `json:"message"`
	At        *time.Time `json:"at,omitempty"`
}

// AgentHealth describes the agent process itself.
type AgentHealth struct {
	Version    string           `json:"version"`
	UptimeS    int64            `json:"uptime_s,omitempty"`
	RSSBytes   int64            `json:"rss_bytes,omitempty"`
	SpoolItems int              `json:"spool_items"`
	Errors     []CollectorError `json:"errors,omitempty"`
}

// MetricsBatch is posted every metrics_send_interval_s (also a heartbeat).
type MetricsBatch struct {
	SentAt       time.Time    `json:"sent_at"`
	BootTime     *time.Time   `json:"boot_time,omitempty"`
	LoggedOnUser *string      `json:"logged_on_user,omitempty"`
	Host         []HostSample `json:"host"`
	Disks        []DiskSample `json:"disks,omitempty"`
	Agent        *AgentHealth `json:"agent,omitempty"`
}

// Accepted counts samples the server has durably stored (new or duplicates of
// already-received ones). Out-of-window samples are dropped and not counted.
type Accepted struct {
	Host  int `json:"host"`
	Disks int `json:"disks"`
}

// MetricsResponse tells the agent what (if anything) to do next.
type MetricsResponse struct {
	Accepted           Accepted `json:"accepted"`
	ConfigVersion      int      `json:"config_version"`
	InventoryRequested bool     `json:"inventory_requested"`
	RotateToken        bool     `json:"rotate_token"`
}

// TokenRotateResponse returns a fresh device token.
type TokenRotateResponse struct {
	DeviceToken        string    `json:"device_token"`
	PreviousValidUntil time.Time `json:"previous_valid_until"`
}

// FieldError describes one validation failure.
type FieldError struct {
	Field   string `json:"field"`
	Message string `json:"message"`
}

// Problem is an RFC 9457 problem document with a machine-readable code.
type Problem struct {
	Type   string       `json:"type"`
	Title  string       `json:"title"`
	Status int          `json:"status"`
	Detail string       `json:"detail,omitempty"`
	Code   string       `json:"code"`
	Errors []FieldError `json:"errors,omitempty"`
}

// Machine-readable problem codes used by the agent API.
const (
	CodeValidationFailed = "validation_failed"
	CodeInvalidToken     = "invalid_token"
	CodePendingApproval  = "pending_approval"
	CodeDeviceRevoked    = "device_revoked"
	CodeAlreadyEnrolled  = "already_enrolled"
	CodePayloadTooLarge  = "payload_too_large"
	CodeRateLimited      = "rate_limited"
	CodeNotFound         = "not_found"
	CodeMethodNotAllowed = "method_not_allowed"
	CodeInternal         = "internal_error"
)
