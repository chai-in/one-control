//go:build windows

package inventory

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"
	"unicode/utf16"
	"unsafe"
)

func TestLiveWindowsCollection(t *testing.T) {
	before := time.Now().UTC()
	r, err := Collect(context.Background())
	after := time.Now().UTC()
	if err != nil {
		t.Fatal(err)
	}
	if err := Validate(r); err != nil {
		t.Fatal(err)
	}
	if r.CollectedAt.Location() != time.UTC || r.CollectedAt.Before(before) || r.CollectedAt.After(after) {
		t.Fatalf("endpoint time %s outside [%s, %s]", r.CollectedAt, before, after)
	}
	for _, s := range []Status{r.Hostname.Status, r.OSVersion.Status, r.NativeArchitecture.Status, r.ProcessArchitecture.Status, r.CPU.Status, r.Memory.Status, r.ElapsedSinceStartMilliseconds.Status} {
		if s != Available {
			t.Fatalf("modern Windows collection did not produce every allowlisted observation: %+v", r)
		}
	}
	expectedProcess := map[string]Architecture{"386": X86, "amd64": X64, "arm": ARM32, "arm64": ARM64}[runtime.GOARCH]
	if *r.ProcessArchitecture.Value != expectedProcess {
		t.Fatal(*r.ProcessArchitecture.Value)
	}
	if unsafe.Sizeof(versionInfo{}) != 276 || unsafe.Sizeof(memoryInfo{}) != 64 {
		t.Fatal("incorrect Windows structure layout")
	}
	payload, err := json.Marshal(r)
	if err != nil || len(payload) > MaximumJSONBytes {
		t.Fatalf("%s %v", payload, err)
	}
	t.Logf("live bounded inventory JSON (%d bytes): %s", len(payload), payload)
}

type scalarProcedure struct {
	findErr error
	returns []uintptr
	second  uintptr
	callErr error
	calls   int
	onCall  func()
}

func (p *scalarProcedure) Find() error { return p.findErr }
func (p *scalarProcedure) Call(...uintptr) (uintptr, uintptr, error) {
	i := p.calls
	p.calls++
	if p.onCall != nil {
		p.onCall()
	}
	var r uintptr
	if len(p.returns) != 0 {
		if i >= len(p.returns) {
			i = len(p.returns) - 1
		}
		r = p.returns[i]
	}
	return r, p.second, p.callErr
}

func TestMissingProcedureAndFailureConversion(t *testing.T) {
	ctx := context.Background()
	missing := kernel.NewProc("OneControlInventoryDeliberatelyMissingExport")
	if got := readHostname(ctx, missing); got.Status != Unavailable || got.Reason != ProcedureUnavailable || got.Value != nil {
		t.Fatal(got)
	}
	if got := readNativeArchitecture(ctx, missing); got.Reason != ProcedureUnavailable {
		t.Fatal(got)
	}
	if got := readMemory(ctx, missing); got.Reason != ProcedureUnavailable {
		t.Fatal(got)
	}
	p := &scalarProcedure{findErr: errors.New("private raw diagnostic")}
	if got := readElapsed(ctx, p); got.Reason != ProcedureUnavailable || p.calls != 0 {
		t.Fatal(got, p.calls)
	}
	if got := memoryObservation(0, memoryInfo{TotalPhys: 42}); got.Reason != QueryFailed || got.Value != nil {
		t.Fatal(got)
	}
	if got := architectureObservation(0, 0x8664); got.Reason != QueryFailed || got.Value != nil {
		t.Fatal(got)
	}
	if got := architectureObservation(1, 0xffff); got.Reason != InvalidResult {
		t.Fatal(got)
	}
	if got := versionObservation(0xc0000001, versionInfo{Major: 10, Build: 26200}); got.Reason != QueryFailed {
		t.Fatal(got)
	}
	if got := versionObservation(0, versionInfo{}); got.Reason != InvalidResult {
		t.Fatal(got)
	}
	if got := memoryObservation(1, memoryInfo{TotalPhys: 42, AvailPhys: 0}); got.Status != Available || got.Value.AvailableBytes != 0 {
		t.Fatal(got)
	}
	if got := memoryObservation(1, memoryInfo{TotalPhys: 1, AvailPhys: 2}); got.Reason != InvalidResult {
		t.Fatal(got)
	}
	if got := readElapsed(ctx, &scalarProcedure{callErr: errors.New("stale last error")}); got.Status != Available || *got.Value != 0 {
		t.Fatal(got)
	}
}

func TestHostnameUTF16Boundary(t *testing.T) {
	var buffer [maximumHostnameBytes + 1]uint16
	if got := hostnameObservation(0, syscall.EINVAL, uint32(len(buffer)), buffer[:]); got.Reason != QueryFailed {
		t.Fatal(got)
	}
	if got := hostnameObservation(0, syscall.ERROR_MORE_DATA, uint32(len(buffer)+1), buffer[:]); got.Reason != InvalidResult {
		t.Fatal(got)
	}
	if got := hostnameObservation(1, nil, uint32(len(buffer)), buffer[:]); got.Reason != InvalidResult {
		t.Fatal(got)
	}
	for _, units := range [][]uint16{{0xd800}, {0xdc00}, {0xd800, 'a'}, {'a', 0}, {'a', '\n'}, utf16.Encode([]rune("pc.example")), utf16.Encode([]rune(strings.Repeat("a", 254))), {0xd83d, 0xde00}} {
		if got := hostnameFromUTF16(units); got.Status != Unavailable || got.Reason != InvalidResult || got.Value != nil {
			t.Fatalf("%x admitted: %+v", units, got)
		}
	}
	if got := hostnameFromUTF16(utf16.Encode([]rune("PC_1-a"))); got.Status != Available || *got.Value != "PC_1-a" {
		t.Fatal(got)
	}
}

func TestCPUTopologyChangesAndReturnWidths(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct {
		groups     []uintptr
		processors uintptr
		reason     Reason
	}{
		{[]uintptr{1, 2}, 4, InvalidResult},
		{[]uintptr{0, 0}, 4, QueryFailed},
		{[]uintptr{2, 2}, 0, QueryFailed},
		{[]uintptr{2, 2}, 1, InvalidResult},
		{[]uintptr{0x10001, 0x20001}, 4, NoReason},
	} {
		got := readCPU(ctx, &scalarProcedure{returns: tc.groups}, &scalarProcedure{returns: []uintptr{tc.processors}})
		if got.Reason != tc.reason {
			t.Fatalf("%+v -> %+v", tc, got)
		}
	}
	wide := uint64(1)<<32 | 4
	got := readCPU(ctx, &scalarProcedure{returns: []uintptr{1}}, &scalarProcedure{returns: []uintptr{uintptr(wide)}})
	if got.Status != Available || got.Value.ActiveLogicalProcessors != 4 || got.Value.ActiveProcessorGroups != 1 {
		t.Fatal(got)
	}
	ctx, cancel := context.WithCancel(context.Background())
	groups := &scalarProcedure{returns: []uintptr{1}}
	processors := &scalarProcedure{returns: []uintptr{4}, onCall: cancel}
	got = readCPU(ctx, groups, processors)
	if got.Status != Unavailable || groups.calls != 1 {
		t.Fatal(got, groups.calls)
	}
}

func TestTickRegisters(t *testing.T) {
	if got := tickValue(0x89abcdef, 0x12345678, true); got != 0x1234567889abcdef {
		t.Fatalf("%x", got)
	}
	if got := tickValue(0, 1, true); got != 1<<32 {
		t.Fatalf("%x", got)
	}
	if got := tickValue(123, 456, false); got != 123 {
		t.Fatal(got)
	}
	if got := readElapsed(context.Background(), &scalarProcedure{returns: []uintptr{0}, second: 1}); got.Status != Available || (runtime.GOARCH == "386" && *got.Value != 1<<32) {
		t.Fatal(got)
	}
}

func fakeQueries() windowsQueries {
	return windowsQueries{
		hostname:           func(context.Context) Observation[string] { return available("Test-PC") },
		version:            func(context.Context) Observation[WindowsVersion] { return available(WindowsVersion{10, 0, 26200}) },
		nativeArchitecture: func(context.Context) Observation[Architecture] { return available(X64) },
		cpu:                func(context.Context) Observation[CPUTopology] { return available(CPUTopology{4, 1}) },
		memory:             func(context.Context) Observation[PhysicalMemory] { return available(PhysicalMemory{42, 0}) },
		elapsed:            func(context.Context) Observation[uint64] { return available(uint64(0)) },
	}
}

func TestPartialFailuresPreserveOtherObservations(t *testing.T) {
	q := fakeQueries()
	q.nativeArchitecture = func(context.Context) Observation[Architecture] {
		return unavailable[Architecture](ProcedureUnavailable)
	}
	q.memory = func(context.Context) Observation[PhysicalMemory] { return unavailable[PhysicalMemory](QueryFailed) }
	at := time.Date(2026, 10, 20, 1, 2, 3, 0, time.UTC)
	r, err := collectWindows(context.Background(), at, q)
	if err != nil || Validate(r) != nil {
		t.Fatal(r, err)
	}
	if r.NativeArchitecture.Reason != ProcedureUnavailable || r.Memory.Reason != QueryFailed || r.ProcessArchitecture.Status != Available || r.Hostname.Status != Available || r.ElapsedSinceStartMilliseconds.Status != Available || r.CollectedAt != at {
		t.Fatal(r)
	}
}

func TestCancellationBetweenQueriesDiscardsAllObservations(t *testing.T) {
	for _, last := range []bool{false, true} {
		ctx, cancel := context.WithCancel(context.Background())
		q := fakeQueries()
		if last {
			q.elapsed = func(context.Context) Observation[uint64] { cancel(); return available(uint64(42)) }
		} else {
			q.hostname = func(context.Context) Observation[string] { cancel(); return available("Test-PC") }
			q.version = func(context.Context) Observation[WindowsVersion] {
				t.Fatal("query after cancellation")
				return Observation[WindowsVersion]{}
			}
		}
		r, err := collectWindows(ctx, time.Now().UTC(), q)
		if !errors.Is(err, context.Canceled) || !reflect.DeepEqual(r, Report{}) {
			t.Fatal(r, err)
		}
	}
}
