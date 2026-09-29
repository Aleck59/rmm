package agent

import "runtime"

// SysInfo identifies the machine at enrollment.
type SysInfo struct {
	Hostname         string
	Domain           string // DNS domain; empty in a workgroup
	OSName           string
	OSVersion        string
	OSDisplayVersion string
	Build            int
	UBR              int
	Arch             string // x86 | x64 | arm64
	MachineGUID      string
}

// processArch maps the Go architecture to the API's arch values. The
// installer deploys the build matching the OS, so this equals the OS arch.
func processArch() string {
	switch runtime.GOARCH {
	case "386":
		return "x86"
	case "amd64":
		return "x64"
	default:
		return runtime.GOARCH // arm64
	}
}
