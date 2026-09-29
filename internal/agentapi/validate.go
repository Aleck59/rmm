package agentapi

import (
	"fmt"
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/Aleck59/rmm/internal/protocol"
)

// Limits mirror the constraints in docs/api/openapi.yaml.
const (
	maxEnrollBody  = 64 << 10 // 64 KiB
	maxMetricsBody = 1 << 20  // 1 MiB after decompression
	maxSamples     = 1000
	maxAgentErrors = 50
)

var (
	volumeRe = regexp.MustCompile(`^[A-Z]:$`)
	macRe    = regexp.MustCompile(`^([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}$`)
	uuidRe   = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
	archs    = map[string]bool{"x86": true, "x64": true, "arm64": true}
)

// validator accumulates field errors.
type validator struct{ errs []protocol.FieldError }

func (v *validator) add(field, format string, args ...any) {
	v.errs = append(v.errs, protocol.FieldError{Field: field, Message: fmt.Sprintf(format, args...)})
}

func (v *validator) length(field, s string, lo, hi int) {
	n := utf8.RuneCountInString(s)
	switch {
	case !utf8.ValidString(s):
		v.add(field, "must be valid UTF-8")
	case n < lo:
		v.add(field, "must not be empty")
	case n > hi:
		v.add(field, "must be at most %d characters", hi)
	}
}

func (v *validator) ok() bool { return len(v.errs) == 0 }

// canonicalUUID returns the lower-case form of a textual UUID, or "" if s is
// not a UUID.
func canonicalUUID(s string) string {
	if !uuidRe.MatchString(s) {
		return ""
	}
	return strings.ToLower(s)
}

func validateEnroll(req *protocol.EnrollRequest) []protocol.FieldError {
	var v validator
	if canonicalUUID(req.AgentUID) == "" {
		v.add("agent_uid", "must be a UUID")
	}
	v.length("agent_version", req.AgentVersion, 1, 32)
	v.length("hostname", req.Hostname, 1, 255)
	v.length("domain", req.Domain, 0, 255)
	v.length("os.name", req.OS.Name, 1, 256)
	v.length("os.version", req.OS.Version, 1, 64)
	v.length("os.display_version", req.OS.DisplayVersion, 0, 32)
	if !archs[req.OS.Arch] {
		v.add("os.arch", "must be one of x86, x64, arm64")
	}
	v.length("hardware_ids.machine_guid", req.HardwareIDs.MachineGUID, 0, 64)
	v.length("hardware_ids.serial_number", req.HardwareIDs.SerialNumber, 0, 128)
	if u := req.HardwareIDs.SMBIOSUUID; u != nil && *u != "" && canonicalUUID(*u) == "" {
		v.add("hardware_ids.smbios_uuid", "must be a UUID")
	}
	if len(req.HardwareIDs.MACs) > 32 {
		v.add("hardware_ids.macs", "must have at most 32 items")
	}
	for i, m := range req.HardwareIDs.MACs {
		if !macRe.MatchString(m) {
			v.add(fmt.Sprintf("hardware_ids.macs[%d]", i), "must be a MAC address")
		}
	}
	return v.errs
}

func validateMetrics(b *protocol.MetricsBatch) []protocol.FieldError {
	var v validator
	if b.SentAt.IsZero() {
		v.add("sent_at", "is required")
	}
	if len(b.Host) > maxSamples {
		v.add("host", "must have at most %d items", maxSamples)
	}
	if len(b.Disks) > maxSamples {
		v.add("disks", "must have at most %d items", maxSamples)
	}
	if !v.ok() {
		return v.errs // do not walk oversized arrays
	}
	for i, h := range b.Host {
		f := fmt.Sprintf("host[%d]", i)
		if h.TS.IsZero() {
			v.add(f+".ts", "is required")
		}
		if h.CPUPct < 0 || h.CPUPct > 100 {
			v.add(f+".cpu_pct", "must be between 0 and 100")
		}
		if h.CPUMaxPct < 0 || h.CPUMaxPct > 100 {
			v.add(f+".cpu_max_pct", "must be between 0 and 100")
		}
		if h.MemTotalBytes <= 0 {
			v.add(f+".mem_total_bytes", "must be positive")
		}
		if h.MemUsedBytes < 0 || h.MemUsedBytes > h.MemTotalBytes {
			v.add(f+".mem_used_bytes", "must be between 0 and mem_total_bytes")
		}
	}
	for i, d := range b.Disks {
		f := fmt.Sprintf("disks[%d]", i)
		if d.TS.IsZero() {
			v.add(f+".ts", "is required")
		}
		if !volumeRe.MatchString(d.Volume) {
			v.add(f+".volume", "must look like C:")
		}
		if d.TotalBytes <= 0 {
			v.add(f+".total_bytes", "must be positive")
		}
		if d.FreeBytes < 0 || d.FreeBytes > d.TotalBytes {
			v.add(f+".free_bytes", "must be between 0 and total_bytes")
		}
	}
	if b.LoggedOnUser != nil {
		v.length("logged_on_user", *b.LoggedOnUser, 0, 256)
	}
	if b.Agent != nil {
		v.length("agent.version", b.Agent.Version, 1, 32)
		if len(b.Agent.Errors) > maxAgentErrors {
			v.add("agent.errors", "must have at most %d items", maxAgentErrors)
		}
		for i, e := range b.Agent.Errors {
			v.length(fmt.Sprintf("agent.errors[%d].collector", i), e.Collector, 1, 128)
			v.length(fmt.Sprintf("agent.errors[%d].message", i), e.Message, 0, 500)
		}
	}
	return v.errs
}
