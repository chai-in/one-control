package indexing

import (
	"encoding/json"
	ole "github.com/go-ole/go-ole"
	"golang.org/x/sys/windows"
	"syscall"
	"unsafe"
)

func readLocations(catalog *ole.IUnknown) (string, []Location) {
	table := *(**[32]uintptr)(unsafe.Pointer(catalog))
	var scope *ole.IUnknown
	hr, _, _ := syscall.SyscallN(table[28], uintptr(unsafe.Pointer(catalog)), uintptr(unsafe.Pointer(&scope)))
	if int32(hr) < 0 || scope == nil {
		return "unavailable", nil
	}
	defer scope.Release()
	table = *(**[32]uintptr)(unsafe.Pointer(scope))
	var rules *ole.IUnknown
	hr, _, _ = syscall.SyscallN(table[10], uintptr(unsafe.Pointer(scope)), uintptr(unsafe.Pointer(&rules)))
	if int32(hr) < 0 || rules == nil {
		return "unavailable", nil
	}
	defer rules.Release()
	table = *(**[32]uintptr)(unsafe.Pointer(rules))
	locations := []Location{}
	encodedBytes := 0
	for {
		var rule *ole.IUnknown
		var fetched uint32
		hr, _, _ = syscall.SyscallN(table[3], uintptr(unsafe.Pointer(rules)), 1, uintptr(unsafe.Pointer(&rule)), uintptr(unsafe.Pointer(&fetched)))
		if int32(hr) < 0 {
			return "partial", locations
		}
		if fetched == 0 {
			return "configured-rules", locations
		}
		if rule == nil {
			return "partial", locations
		}
		location, ok := readLocation(rule)
		rule.Release()
		if !ok || len(locations) == 64 {
			return "partial", locations
		}
		encoded, _ := json.Marshal(location)
		if encodedBytes+len(encoded) > 32768 {
			return "partial", locations
		}
		encodedBytes += len(encoded)
		locations = append(locations, location)
	}
}
func readLocation(rule *ole.IUnknown) (Location, bool) {
	table := *(**[32]uintptr)(unsafe.Pointer(rule))
	var pattern *uint16
	hr, _, _ := syscall.SyscallN(table[3], uintptr(unsafe.Pointer(rule)), uintptr(unsafe.Pointer(&pattern)))
	if int32(hr) < 0 || pattern == nil {
		return Location{}, false
	}
	defer ole.CoTaskMemFree(uintptr(unsafe.Pointer(pattern)))
	value := windows.UTF16PtrToString(pattern)
	if len(value) > 1024 {
		return Location{}, false
	}
	var included, defaultRule int32
	hr, _, _ = syscall.SyscallN(table[4], uintptr(unsafe.Pointer(rule)), uintptr(unsafe.Pointer(&included)))
	if int32(hr) < 0 {
		return Location{}, false
	}
	hr, _, _ = syscall.SyscallN(table[5], uintptr(unsafe.Pointer(rule)), uintptr(unsafe.Pointer(&defaultRule)))
	if int32(hr) < 0 {
		return Location{}, false
	}
	return Location{Pattern: value, Included: included != 0, Default: defaultRule != 0}, true
}
