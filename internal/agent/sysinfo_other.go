//go:build !windows

package agent

import (
	"os"
	"runtime"
	"strings"
)

func defaultDataDir() string { return "invmon-agent-data" }

// collectSysInfo reports development values off Windows.
func collectSysInfo() SysInfo {
	si := SysInfo{Arch: processArch(), OSName: "dev (" + runtime.GOOS + ")", OSVersion: "0.0.0"}
	si.Hostname, _ = os.Hostname()
	if b, err := os.ReadFile("/etc/machine-id"); err == nil {
		si.MachineGUID = strings.TrimSpace(string(b))
	}
	return si
}
