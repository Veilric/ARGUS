//go:build windows

package sysmon

import (
	"syscall"
	"unsafe"
)

var (
	modkernel32              = syscall.NewLazyDLL("kernel32.dll")
	procGlobalMemoryStatusEx = modkernel32.NewProc("GlobalMemoryStatusEx")
	procGetSystemTimes       = modkernel32.NewProc("GetSystemTimes")
)

type memorystatusex struct {
	dwLength                uint32
	dwMemoryLoad            uint32
	ullTotalPhys            uint64
	ullAvailPhys            uint64
	ullTotalPageFile        uint64
	ullAvailPageFile        uint64
	ullTotalVirtual         uint64
	ullAvailVirtual         uint64
	ullAvailExtendedVirtual uint64
}

type filetime struct {
	dwLowDateTime  uint32
	dwHighDateTime uint32
}

func filetimeToUint64(ft filetime) uint64 {
	return (uint64(ft.dwHighDateTime) << 32) | uint64(ft.dwLowDateTime)
}

func (m *Monitor) sampleOS(stats *Stats, elapsed float64) {
	// 1. Genuine RAM telemetry via Win32 GlobalMemoryStatusEx
	var mem memorystatusex
	mem.dwLength = uint32(unsafe.Sizeof(mem))
	r1, _, _ := procGlobalMemoryStatusEx.Call(uintptr(unsafe.Pointer(&mem)))
	if r1 != 0 && mem.ullTotalPhys > 0 {
		totalGB := float64(mem.ullTotalPhys) / (1024 * 1024 * 1024)
		availGB := float64(mem.ullAvailPhys) / (1024 * 1024 * 1024)
		usedGB := totalGB - availGB
		stats.RAMTotalGB = totalGB
		stats.RAMUsedGB = usedGB
		stats.RAMPercent = float64(mem.dwMemoryLoad)
	} else {
		stats.RAMTotalGB = 0
		stats.RAMUsedGB = 0
		stats.RAMPercent = 0
	}

	// 2. Genuine CPU utilization via Win32 GetSystemTimes
	var idleTime, kernelTime, userTime filetime
	r2, _, _ := procGetSystemTimes.Call(
		uintptr(unsafe.Pointer(&idleTime)),
		uintptr(unsafe.Pointer(&kernelTime)),
		uintptr(unsafe.Pointer(&userTime)),
	)
	if r2 != 0 {
		curIdle := filetimeToUint64(idleTime)
		curKernel := filetimeToUint64(kernelTime)
		curUser := filetimeToUint64(userTime)

		if m.lastCPUTotal > 0 {
			idleDelta := curIdle - m.lastCPUIdle
			// In Win32 GetSystemTimes, kernelTime includes idleTime
			kernelDelta := curKernel - m.lastKernelTime
			userDelta := curUser - m.lastUserTime
			totalDelta := kernelDelta + userDelta

			if totalDelta > 0 && totalDelta >= idleDelta {
				busyDelta := totalDelta - idleDelta
				stats.CPUPercent = (float64(busyDelta) / float64(totalDelta)) * 100.0
				if stats.CPUPercent < 0 {
					stats.CPUPercent = 0
				} else if stats.CPUPercent > 100 {
					stats.CPUPercent = 100
				}
			} else {
				stats.CPUPercent = -1
			}
		} else {
			// First sample baseline
			stats.CPUPercent = 0
		}

		m.lastCPUIdle = curIdle
		m.lastKernelTime = curKernel
		m.lastUserTime = curUser
		m.lastCPUTotal = curKernel + curUser
	} else {
		stats.CPUPercent = -1 // Explicitly unavailable
	}
}
