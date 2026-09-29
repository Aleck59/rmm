//go:build windows

package agent

import (
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	kernel32                 = windows.NewLazySystemDLL("kernel32.dll")
	procGetSystemTimes       = kernel32.NewProc("GetSystemTimes")
	procGlobalMemoryStatusEx = kernel32.NewProc("GlobalMemoryStatusEx")
	procGetTickCount64       = kernel32.NewProc("GetTickCount64")
)

// memoryStatusEx mirrors MEMORYSTATUSEX.
type memoryStatusEx struct {
	Length               uint32
	MemoryLoad           uint32
	TotalPhys            uint64
	AvailPhys            uint64
	TotalPageFile        uint64
	AvailPageFile        uint64
	TotalVirtual         uint64
	AvailVirtual         uint64
	AvailExtendedVirtual uint64
}

// NewCollector returns the Win32 collector.
func NewCollector() Collector { return &winCollector{} }

type winCollector struct {
	mu                     sync.Mutex
	prevIdle, prevKernUser uint64
	primed                 bool
}

func filetimeToUint64(ft windows.Filetime) uint64 {
	return uint64(ft.HighDateTime)<<32 | uint64(ft.LowDateTime)
}

// CPUPercent uses GetSystemTimes deltas: kernel time includes idle time, so
// busy = (kernel + user) - idle.
func (c *winCollector) CPUPercent() (float64, error) {
	var idle, kernel, user windows.Filetime
	r, _, err := procGetSystemTimes.Call(
		uintptr(unsafe.Pointer(&idle)), uintptr(unsafe.Pointer(&kernel)), uintptr(unsafe.Pointer(&user)))
	if r == 0 {
		return 0, err
	}
	i := filetimeToUint64(idle)
	ku := filetimeToUint64(kernel) + filetimeToUint64(user)

	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.primed {
		c.prevIdle, c.prevKernUser, c.primed = i, ku, true
		return 0, errPriming
	}
	dIdle, dTotal := i-c.prevIdle, ku-c.prevKernUser
	c.prevIdle, c.prevKernUser = i, ku
	if dTotal == 0 {
		return 0, nil
	}
	busy := float64(dTotal-dIdle) * 100 / float64(dTotal)
	return clampPct(busy), nil
}

func (c *winCollector) Memory() (uint64, uint64, error) {
	var ms memoryStatusEx
	ms.Length = uint32(unsafe.Sizeof(ms))
	r, _, err := procGlobalMemoryStatusEx.Call(uintptr(unsafe.Pointer(&ms)))
	if r == 0 {
		return 0, 0, err
	}
	return ms.TotalPhys - ms.AvailPhys, ms.TotalPhys, nil
}

func (c *winCollector) Volumes() ([]Volume, error) {
	buf := make([]uint16, 256)
	n, err := windows.GetLogicalDriveStrings(uint32(len(buf)), &buf[0])
	if err != nil {
		return nil, err
	}
	var out []Volume
	for _, root := range splitMultiSZ(buf[:n]) {
		rootPtr, err := windows.UTF16PtrFromString(root)
		if err != nil || windows.GetDriveType(rootPtr) != windows.DRIVE_FIXED {
			continue
		}
		var freeToCaller, total, totalFree uint64
		if err := windows.GetDiskFreeSpaceEx(rootPtr, &freeToCaller, &total, &totalFree); err != nil || total == 0 {
			continue // e.g. an unformatted or locked volume
		}
		name := root
		if len(name) >= 2 {
			name = name[:2] // "C:\" → "C:"
		}
		out = append(out, Volume{Name: name, Total: total, Free: totalFree})
	}
	return out, nil
}

func (c *winCollector) BootTime() (time.Time, error) {
	r1, r2, _ := procGetTickCount64.Call()
	ms := uint64(r1)
	if unsafe.Sizeof(uintptr(0)) == 4 { // 32-bit: 64-bit result in EDX:EAX
		ms = uint64(r2)<<32 | uint64(r1)
	}
	return time.Now().Add(-time.Duration(ms) * time.Millisecond).Truncate(time.Second), nil
}

// splitMultiSZ splits a double-NUL-terminated UTF-16 string list.
func splitMultiSZ(b []uint16) []string {
	var out []string
	start := 0
	for i, ch := range b {
		if ch == 0 {
			if i > start {
				out = append(out, windows.UTF16ToString(b[start:i]))
			}
			start = i + 1
		}
	}
	return out
}
