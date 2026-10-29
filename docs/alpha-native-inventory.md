# Native inventory collector reference

```go
report, err := inventory.Collect(ctx)
if err != nil {
	return err
}
if report.Memory.Status == inventory.Available {
	showMemory(report.Memory.Value.TotalBytes, report.Memory.Value.AvailableBytes)
}
payload, err := json.Marshal(report)
```

`onecontrol/native/internal/inventory` returns a fixed local observation report. It performs no persistence, transport, authorization, or module activation. The caller supplies a non-nil context. Reports contain mutable public pointers. Callers must not mutate a report or its pointed values concurrently with `Validate`, `json.Marshal`, or another reader.

## Data shape

`Report` has `schemaVersion`, `collectedAt`, and ten named `Observation[T]` fields. Each observation has `status`, an optional `reason`, and a typed `value` only when available. The local schema version is 1. It does not define a shared heartbeat or host protocol.

| Field | Typed value and meaning |
| --- | --- |
| `hostname` | ASCII physical DNS hostname without a suffix. |
| `osVersion` | Numeric Windows `major`, `minor`, and `build`. |
| `nativeArchitecture` | Native Windows machine architecture. |
| `processArchitecture` | Independent binary compile target from `runtime.GOARCH`. |
| `cpu` | `activeLogicalProcessors` across all active groups and `activeProcessorGroups`. |
| `memory` | `totalBytes` available to Windows and immediately reusable `availableBytes`. |
| `elapsedSinceStartMilliseconds` | OS elapsed milliseconds since system start. Zero is valid. |
| `serverContact` | Always unsupported, outside collector scope. |
| `bootIdentity` | Always unsupported, outside collector scope. |
| `powerState` | Always unsupported, outside collector scope. |

`CollectedAt` is the endpoint's UTC wall clock at collection start. It can be incorrect. It proves no server contact, boot identity, boot timestamp, or ordering across machines. It is nonzero and uses a year from 1 through 9999.

The closed statuses are `available`, `unavailable`, and `unsupported`. Available values have no reason. Unavailable values have no value and use `procedure_unavailable`, `query_failed`, or `invalid_result`. Windows observations on other platforms use `unsupported` with `platform_unsupported`. The three scope exclusions use `unsupported` with `outside_collector_scope` on every platform.

Architectures are `x86`, `x64`, `arm32`, `arm64`, and `ia64`. Unknown native identifiers are unavailable. A missing native architecture API does not erase the independently known process architecture.

## Windows API sources and limits

Only fixed system DLL and procedure names enter the adapter. Go's standard `syscall` package loads its registered `kernel32.dll` from the system directory. The adapter loads `ntdll.dll` with `LoadLibraryExW` and `LOAD_LIBRARY_SEARCH_SYSTEM32`. Procedure resolution is guarded before calls. Missing exports and query failures produce bounded reasons without raw operating-system diagnostics.

| API | Exact interpretation |
| --- | --- |
| [GetComputerNameExW](https://learn.microsoft.com/en-us/windows/win32/api/sysinfoapi/nf-sysinfoapi-getcomputernameexw) | Uses `ComputerNamePhysicalDnsHostname`. A fixed UTF-16 buffer admits 1 through 253 ASCII bytes containing letters, digits, hyphen, or underscore. Invalid UTF-16, suffixes, controls, and overlength values are rejected without rewriting identity. This conservative subset can reject unusual Windows names. |
| [User-mode RtlGetVersion](https://learn.microsoft.com/en-us/windows/win32/devnotes/rtlgetversion) | Uses numeric major, minor, and build. Major and build must be nonzero. No marketing version, update revision, or supported-feature claim is derived. |
| [IsWow64Process2](https://learn.microsoft.com/en-us/windows/win32/api/wow64apiset/nf-wow64apiset-iswow64process2) | Uses the native machine output. No registry or emulation fallback is attempted. |
| [GetActiveProcessorCount](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-getactiveprocessorcount) and [GetActiveProcessorGroupCount](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-getactiveprocessorgroupcount) | Uses `ALL_PROCESSOR_GROUPS`. Group counts before and after the logical count must be equal and nonzero. Logical processors must be at least the group count. This is not an atomic topology snapshot. Counts can change within existing groups. It reports no physical cores, sockets, affinity, or utilization. |
| [GlobalMemoryStatusEx](https://learn.microsoft.com/en-us/windows/win32/api/sysinfoapi/nf-sysinfoapi-globalmemorystatusex) and [MEMORYSTATUSEX](https://learn.microsoft.com/en-us/windows/win32/api/sysinfoapi/ns-sysinfoapi-memorystatusex) | Reports physical bytes available to Windows and immediately reusable bytes. Total is nonzero. Available may be zero and cannot exceed total. This is not installed DIMM capacity. |
| [GetTickCount64](https://learn.microsoft.com/en-us/windows/win32/api/sysinfoapi/nf-sysinfoapi-gettickcount64) | Reports elapsed system time. The 386 adapter joins the low and high return registers. Zero is valid and stale last-error values are ignored. No sleep history, awake time, or current power state is inferred. |

All exported `uint64` values must be at most 9007199254740991 so JavaScript can represent them exactly. Larger native readings become unavailable. Publicly constructed invalid reports fail validation.

`Validate` is pure. `Report.MarshalJSON` validates before encoding and rejects an escaped payload larger than 4096 bytes. Direct `json.Marshal(report)` uses this same boundary. No invalid report produces partial JSON. The fixed allowlist bounds accepted serialization below the budget even with maximal numeric values and timestamps. Escape-heavy hostnames are invalid before encoding.

`Collect` checks cancellation before collection, between queries, and after queries return. Cancellation returns a zero report with the context error. Individual Windows calls cannot be interrupted, so the context does not promise a hard syscall timeout. Other API failures remain partial observations. Collection does not start abandoned goroutines.

The unsupported implementation reports all seven Windows observations as platform unsupported. It does not collect another platform's hostname or hardware opportunistically.

## Integration proposal and acceptance limits

This is a local collector awaiting the root-owned host, optional-module, and server result contracts. It is not a released thin module. No bootstrap caller, executable, IPC result channel, enrollment, signature, selection, scheduler, or server route is added.

The future host must own current authority, explicit inventory selection, scheduling, cancellation, bounded result admission, and transport. The server must independently admit results under current identity and selection and record contact using its own clock. Disabling inventory must stop its work and reject later inventory admission. Core bootstrap contact remains separate.

The default collector excludes usernames, serials, installed applications, network enumeration, detailed activity, shells, registry fallbacks, and file writes. No external deployment or endpoint setting changes belong to this package. Local Windows tests establish collection on the development host. Production computers, multi-group hardware, ARM64 emulation, optional-host lifecycle, and real-machine acceptance remain separate gates.

Focused verification runs `go test -count=1 ./internal/inventory` from `native` with the pinned local Go toolchain. The live test logs bounded JSON and requires every allowlisted Windows observation on the current modern Windows host. Pure tests cover invalid reports, closed enums, zero measurements, safe-integer boundaries, exact JSON keys, omitted unavailable values, and serialization limits. Windows-specific tests cover missing exports, fixed error conversion, partial failures, UTF-16 rejection, changing groups, return widths, cancellation, and 386 tick reconstruction. Other-platform execution uses the explicit unsupported implementation.
