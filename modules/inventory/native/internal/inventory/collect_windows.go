//go:build windows

package inventory

import (
	"context"
	"runtime"
	"sync"
	"syscall"
	"time"
	"unicode/utf16"
	"unsafe"
)

var kernel = syscall.NewLazyDLL("kernel32.dll")
var computerName = kernel.NewProc("GetComputerNameExW")
var wow64Process2 = kernel.NewProc("IsWow64Process2")
var processorCount = kernel.NewProc("GetActiveProcessorCount")
var groupCount = kernel.NewProc("GetActiveProcessorGroupCount")
var memoryStatus = kernel.NewProc("GlobalMemoryStatusEx")
var tickCount = kernel.NewProc("GetTickCount64")
var loadSystemLibrary = kernel.NewProc("LoadLibraryExW")
var versionOnce sync.Once
var versionProc *syscall.Proc
var versionErr error

type procedure interface {
	Find() error
	Call(...uintptr) (uintptr, uintptr, error)
}

// Pointer arguments use concrete syscall calls so their lifetimes remain visible to the compiler.
func invoke(ctx context.Context, p procedure, args ...uintptr) (uintptr, uintptr, Reason) {
	if ctx.Err() != nil {
		return 0, 0, QueryFailed
	}
	if p.Find() != nil {
		return 0, 0, ProcedureUnavailable
	}
	if ctx.Err() != nil {
		return 0, 0, QueryFailed
	}
	r1, r2, _ := p.Call(args...)
	return r1, r2, NoReason
}

type windowsQueries struct {
	hostname           func(context.Context) Observation[string]
	version            func(context.Context) Observation[WindowsVersion]
	nativeArchitecture func(context.Context) Observation[Architecture]
	cpu                func(context.Context) Observation[CPUTopology]
	memory             func(context.Context) Observation[PhysicalMemory]
	elapsed            func(context.Context) Observation[uint64]
}

func collectPlatform(ctx context.Context, at time.Time) (Report, error) {
	return collectWindows(ctx, at, windowsQueries{
		hostname:           func(ctx context.Context) Observation[string] { return readHostname(ctx, computerName) },
		version:            readVersion,
		nativeArchitecture: func(ctx context.Context) Observation[Architecture] { return readNativeArchitecture(ctx, wow64Process2) },
		cpu:                func(ctx context.Context) Observation[CPUTopology] { return readCPU(ctx, groupCount, processorCount) },
		memory:             func(ctx context.Context) Observation[PhysicalMemory] { return readMemory(ctx, memoryStatus) },
		elapsed:            func(ctx context.Context) Observation[uint64] { return readElapsed(ctx, tickCount) },
	})
}

func collectWindows(ctx context.Context, at time.Time, q windowsQueries) (Report, error) {
	r := initialReport(at)
	steps := []func(){
		func() { r.Hostname = q.hostname(ctx) },
		func() { r.OSVersion = q.version(ctx) },
		func() { r.NativeArchitecture = q.nativeArchitecture(ctx) },
		func() { r.ProcessArchitecture = processArchitecture() },
		func() { r.CPU = q.cpu(ctx) },
		func() { r.Memory = q.memory(ctx) },
		func() { r.ElapsedSinceStartMilliseconds = q.elapsed(ctx) },
	}
	for _, step := range steps {
		if err := ctx.Err(); err != nil {
			return Report{}, err
		}
		step()
		if err := ctx.Err(); err != nil {
			return Report{}, err
		}
	}
	return r, nil
}

func readHostname(ctx context.Context, p *syscall.LazyProc) Observation[string] {
	if p.Find() != nil {
		return unavailable[string](ProcedureUnavailable)
	}
	if ctx.Err() != nil {
		return unavailable[string](QueryFailed)
	}
	var buffer [maximumHostnameBytes + 1]uint16
	size := uint32(len(buffer))
	ok, _, callErr := p.Call(5, uintptr(unsafe.Pointer(&buffer[0])), uintptr(unsafe.Pointer(&size)))
	return hostnameObservation(uint32(ok), callErr, size, buffer[:])
}

func hostnameObservation(ok uint32, callErr error, size uint32, buffer []uint16) Observation[string] {
	if uint32(ok) == 0 {
		if callErr == syscall.ERROR_MORE_DATA && size >= uint32(len(buffer)) {
			return unavailable[string](InvalidResult)
		}
		return unavailable[string](QueryFailed)
	}
	if size >= uint32(len(buffer)) {
		return unavailable[string](InvalidResult)
	}
	return hostnameFromUTF16(buffer[:size])
}

func hostnameFromUTF16(units []uint16) Observation[string] {
	for i := 0; i < len(units); i++ {
		u := units[i]
		if u >= 0xd800 && u <= 0xdbff {
			if i+1 >= len(units) || units[i+1] < 0xdc00 || units[i+1] > 0xdfff {
				return unavailable[string](InvalidResult)
			}
			i++
		} else if u >= 0xdc00 && u <= 0xdfff {
			return unavailable[string](InvalidResult)
		}
	}
	name := string(utf16.Decode(units))
	if !validHostname(name) {
		return unavailable[string](InvalidResult)
	}
	return available(name)
}

type versionInfo struct {
	Size, Major, Minor, Build, Platform uint32
	ServicePack                         [128]uint16
}

func readVersion(ctx context.Context) Observation[WindowsVersion] {
	versionOnce.Do(func() {
		if loadSystemLibrary.Find() != nil {
			versionErr = syscall.EINVAL
			return
		}
		name, _ := syscall.UTF16PtrFromString("ntdll.dll")
		handle, _, _ := loadSystemLibrary.Call(uintptr(unsafe.Pointer(name)), 0, 0x800)
		if handle == 0 {
			versionErr = syscall.EINVAL
			return
		}
		dll := syscall.DLL{Name: "ntdll.dll", Handle: syscall.Handle(handle)}
		versionProc, versionErr = dll.FindProc("RtlGetVersion")
	})
	if versionErr != nil {
		return unavailable[WindowsVersion](ProcedureUnavailable)
	}
	if ctx.Err() != nil {
		return unavailable[WindowsVersion](QueryFailed)
	}
	var v versionInfo
	v.Size = uint32(unsafe.Sizeof(v))
	status, _, _ := versionProc.Call(uintptr(unsafe.Pointer(&v)))
	return versionObservation(uint32(status), v)
}

func versionObservation(status uint32, v versionInfo) Observation[WindowsVersion] {
	if status != 0 {
		return unavailable[WindowsVersion](QueryFailed)
	}
	result := WindowsVersion{v.Major, v.Minor, v.Build}
	if !validVersion(result) {
		return unavailable[WindowsVersion](InvalidResult)
	}
	return available(result)
}

func readNativeArchitecture(ctx context.Context, p *syscall.LazyProc) Observation[Architecture] {
	if p.Find() != nil {
		return unavailable[Architecture](ProcedureUnavailable)
	}
	if ctx.Err() != nil {
		return unavailable[Architecture](QueryFailed)
	}
	var process, native uint16
	ok, _, _ := p.Call(^uintptr(0), uintptr(unsafe.Pointer(&process)), uintptr(unsafe.Pointer(&native)))
	return architectureObservation(uint32(ok), native)
}

func architectureObservation(ok uint32, native uint16) Observation[Architecture] {
	if ok == 0 {
		return unavailable[Architecture](QueryFailed)
	}
	var a Architecture
	switch native {
	case 0x014c:
		a = X86
	case 0x8664:
		a = X64
	case 0x01c0, 0x01c4:
		a = ARM32
	case 0xaa64:
		a = ARM64
	case 0x0200:
		a = IA64
	default:
		return unavailable[Architecture](InvalidResult)
	}
	return available(a)
}

func processArchitecture() Observation[Architecture] {
	switch runtime.GOARCH {
	case "386":
		return available(X86)
	case "amd64":
		return available(X64)
	case "arm":
		return available(ARM32)
	case "arm64":
		return available(ARM64)
	default:
		return unavailable[Architecture](InvalidResult)
	}
}

func readCPU(ctx context.Context, groups, processors procedure) Observation[CPUTopology] {
	before, _, reason := invoke(ctx, groups)
	if reason != NoReason {
		return unavailable[CPUTopology](reason)
	}
	count, _, reason := invoke(ctx, processors, 0xffff)
	if reason != NoReason {
		return unavailable[CPUTopology](reason)
	}
	after, _, reason := invoke(ctx, groups)
	if reason != NoReason {
		return unavailable[CPUTopology](reason)
	}
	before = uintptr(uint16(before))
	after = uintptr(uint16(after))
	count = uintptr(uint32(count))
	if before == 0 || count == 0 || after == 0 {
		return unavailable[CPUTopology](QueryFailed)
	}
	c := CPUTopology{uint32(count), uint16(before)}
	if before != after || !validCPU(c) {
		return unavailable[CPUTopology](InvalidResult)
	}
	return available(c)
}

type memoryInfo struct {
	Length, Load                                                                                         uint32
	TotalPhys, AvailPhys, TotalPageFile, AvailPageFile, TotalVirtual, AvailVirtual, AvailExtendedVirtual uint64
}

func readMemory(ctx context.Context, p *syscall.LazyProc) Observation[PhysicalMemory] {
	if p.Find() != nil {
		return unavailable[PhysicalMemory](ProcedureUnavailable)
	}
	if ctx.Err() != nil {
		return unavailable[PhysicalMemory](QueryFailed)
	}
	var m memoryInfo
	m.Length = uint32(unsafe.Sizeof(m))
	ok, _, _ := p.Call(uintptr(unsafe.Pointer(&m)))
	return memoryObservation(uint32(ok), m)
}

func memoryObservation(ok uint32, m memoryInfo) Observation[PhysicalMemory] {
	if ok == 0 {
		return unavailable[PhysicalMemory](QueryFailed)
	}
	result := PhysicalMemory{m.TotalPhys, m.AvailPhys}
	if !validMemory(result) {
		return unavailable[PhysicalMemory](InvalidResult)
	}
	return available(result)
}

func tickValue(r1, r2 uintptr, is386 bool) uint64 {
	if is386 {
		return uint64(uint32(r1)) | uint64(uint32(r2))<<32
	}
	return uint64(r1)
}

func readElapsed(ctx context.Context, p procedure) Observation[uint64] {
	r1, r2, reason := invoke(ctx, p)
	if reason != NoReason {
		return unavailable[uint64](reason)
	}
	value := tickValue(r1, r2, runtime.GOARCH == "386")
	if !validElapsed(value) {
		return unavailable[uint64](InvalidResult)
	}
	return available(value)
}
