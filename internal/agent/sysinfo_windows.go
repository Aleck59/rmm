//go:build windows

package agent

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

func defaultDataDir() string {
	base := os.Getenv("ProgramData")
	if base == "" {
		base = `C:\ProgramData`
	}
	return filepath.Join(base, "InvMon", "Agent")
}

func collectSysInfo() SysInfo {
	si := SysInfo{Arch: processArch()}
	si.Hostname, _ = os.Hostname()
	si.Domain = computerNameEx(windows.ComputerNameDnsDomain)

	v := windows.RtlGetVersion()
	si.Build = int(v.BuildNumber)

	var product, display string
	// KEY_WOW64_64KEY: read the native view even from a 32-bit process.
	if k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows NT\CurrentVersion`,
		registry.QUERY_VALUE|registry.WOW64_64KEY); err == nil {
		product, _, _ = k.GetStringValue("ProductName")
		display, _, _ = k.GetStringValue("DisplayVersion")
		if display == "" {
			display, _, _ = k.GetStringValue("ReleaseId")
		}
		if ubr, _, err := k.GetIntegerValue("UBR"); err == nil {
			si.UBR = int(ubr)
		}
		k.Close()
	}
	// Windows 11 still reports "Windows 10 …" in ProductName; the build decides.
	if si.Build >= 22000 {
		product = strings.Replace(product, "Windows 10", "Windows 11", 1)
	}
	if display == "" { // Windows 7: "Service Pack 1" → "SP1"
		if csd := windows.UTF16ToString(v.CsdVersion[:]); strings.HasPrefix(csd, "Service Pack ") {
			display = "SP" + strings.TrimPrefix(csd, "Service Pack ")
		}
	}
	if product == "" {
		product = "Windows"
	}
	si.OSName = product
	si.OSDisplayVersion = display
	si.OSVersion = fmt.Sprintf("%d.%d.%d", v.MajorVersion, v.MinorVersion, v.BuildNumber)
	if si.UBR > 0 {
		si.OSVersion += fmt.Sprintf(".%d", si.UBR)
	}

	if k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Cryptography`,
		registry.QUERY_VALUE|registry.WOW64_64KEY); err == nil {
		si.MachineGUID, _, _ = k.GetStringValue("MachineGuid")
		k.Close()
	}
	return si
}

func computerNameEx(nameType uint32) string {
	n := uint32(256)
	buf := make([]uint16, n)
	if err := windows.GetComputerNameEx(nameType, &buf[0], &n); err != nil {
		return ""
	}
	return windows.UTF16ToString(buf[:n])
}
