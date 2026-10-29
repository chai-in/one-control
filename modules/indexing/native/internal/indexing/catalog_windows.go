package indexing

import (
	ole "github.com/go-ole/go-ole"
	"golang.org/x/sys/windows"
	"runtime"
	"syscall"
	"unsafe"
)

// Vtable slots follow Microsoft's SearchAPI.h ISearchManager and
// ISearchCatalogManager interfaces. Only observational methods are called.
func readCatalog(snapshot *Snapshot) {
	result := Catalog{Status: "unavailable"}
	defer func() { snapshot.Catalog = result }()
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if ole.CoInitializeEx(0, ole.COINIT_MULTITHREADED) != nil {
		return
	}
	defer ole.CoUninitialize()
	manager, err := ole.CreateInstance(ole.NewGUID("{7D096C5F-AC08-4F1F-BEB7-5C22C517CE39}"), ole.NewGUID("{AB310581-AC80-11D1-8DF3-00C04FB6EF69}"))
	if err != nil {
		return
	}
	defer manager.Release()
	name, _ := windows.UTF16PtrFromString("SystemIndex")
	var catalog *ole.IUnknown
	table := *(**[32]uintptr)(unsafe.Pointer(manager))
	hr, _, _ := syscall.SyscallN(table[10], uintptr(unsafe.Pointer(manager)), uintptr(unsafe.Pointer(name)), uintptr(unsafe.Pointer(&catalog)))
	runtime.KeepAlive(name)
	if int32(hr) < 0 || catalog == nil {
		return
	}
	defer catalog.Release()
	table = *(**[32]uintptr)(unsafe.Pointer(catalog))
	var state, reason uint32
	hr, _, _ = syscall.SyscallN(table[6], uintptr(unsafe.Pointer(catalog)), uintptr(unsafe.Pointer(&state)), uintptr(unsafe.Pointer(&reason)))
	if int32(hr) < 0 {
		return
	}
	statuses := []string{"idle", "paused", "recovering", "full-crawl", "incremental-crawl", "processing-notifications", "shutting-down"}
	if state >= uint32(len(statuses)) {
		return
	}
	result.Status, result.PausedReason = statuses[state], reason
	var count int32
	hr, _, _ = syscall.SyscallN(table[15], uintptr(unsafe.Pointer(catalog)), uintptr(unsafe.Pointer(&count)))
	if int32(hr) >= 0 && count >= 0 {
		result.Items = &count
	}
	snapshot.LocationScope, snapshot.Locations = readLocations(catalog)
}
