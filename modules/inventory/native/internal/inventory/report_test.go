package inventory

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"
)

func validReport() Report {
	r := initialReport(time.Date(2026, 10, 20, 1, 2, 3, 4, time.UTC))
	r.Hostname = available("Test-PC_1")
	r.OSVersion = available(WindowsVersion{10, 0, 26200})
	r.NativeArchitecture = available(X64)
	r.ProcessArchitecture = available(X86)
	r.CPU = available(CPUTopology{64, 2})
	r.Memory = available(PhysicalMemory{8192, 0})
	r.ElapsedSinceStartMilliseconds = available(uint64(0))
	return r
}

func TestReportJSONContract(t *testing.T) {
	r := validReport()
	r.Hostname = unavailable[string](QueryFailed)
	payload, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	if len(payload) > MaximumJSONBytes {
		t.Fatalf("size %d", len(payload))
	}
	var actual map[string]json.RawMessage
	if err := json.Unmarshal(payload, &actual); err != nil {
		t.Fatal(err)
	}
	keys := []string{"schemaVersion", "collectedAt", "hostname", "osVersion", "nativeArchitecture", "processArchitecture", "cpu", "memory", "elapsedSinceStartMilliseconds", "serverContact", "bootIdentity", "powerState"}
	if len(actual) != len(keys) {
		t.Fatalf("keys %v", actual)
	}
	for _, key := range keys {
		if _, ok := actual[key]; !ok {
			t.Errorf("missing %s", key)
		}
	}
	if string(actual["hostname"]) != `{"status":"unavailable","reason":"query_failed"}` {
		t.Fatal(string(actual["hostname"]))
	}
	if string(actual["osVersion"]) != `{"status":"available","value":{"major":10,"minor":0,"build":26200}}` {
		t.Fatal(string(actual["osVersion"]))
	}
	if string(actual["memory"]) != `{"status":"available","value":{"totalBytes":8192,"availableBytes":0}}` {
		t.Fatal(string(actual["memory"]))
	}
	if string(actual["elapsedSinceStartMilliseconds"]) != `{"status":"available","value":0}` {
		t.Fatal(string(actual["elapsedSinceStartMilliseconds"]))
	}
	for _, field := range []string{"serverContact", "bootIdentity", "powerState"} {
		if string(actual[field]) != `{"status":"unsupported","reason":"outside_collector_scope"}` {
			t.Fatal(string(actual[field]))
		}
	}
	var at time.Time
	if err := json.Unmarshal(actual["collectedAt"], &at); err != nil || !at.Equal(r.CollectedAt) || at.Location() != time.UTC {
		t.Fatalf("timestamp %s %v", at, err)
	}
}

func TestInvalidReportsCannotMarshal(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Report)
		code   ValidationCode
	}{
		{"schema", func(r *Report) { r.SchemaVersion = 2 }, CodeInvalidSchema},
		{"timestamp-zero", func(r *Report) { r.CollectedAt = time.Time{} }, CodeInvalidTimestamp},
		{"timestamp-offset", func(r *Report) { r.CollectedAt = r.CollectedAt.In(time.FixedZone("offset", 3600)) }, CodeInvalidTimestamp},
		{"timestamp-year", func(r *Report) { r.CollectedAt = time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC) }, CodeInvalidTimestamp},
		{"status", func(r *Report) { r.Hostname.Status = "invented" }, CodeInvalidObservation},
		{"missing-value", func(r *Report) { r.Hostname.Value = nil }, CodeInvalidObservation},
		{"available-reason", func(r *Report) { r.Hostname.Reason = QueryFailed }, CodeInvalidObservation},
		{"unavailable-value", func(r *Report) { r.Hostname.Status = Unavailable; r.Hostname.Reason = QueryFailed }, CodeInvalidObservation},
		{"unavailable-reason", func(r *Report) { r.Hostname = unavailable[string]("raw error") }, CodeInvalidObservation},
		{"unsupported-value", func(r *Report) { r.Hostname.Status = Unsupported; r.Hostname.Reason = PlatformUnsupported }, CodeInvalidObservation},
		{"unsupported-reason", func(r *Report) { r.Hostname = Observation[string]{Status: Unsupported, Reason: OutsideCollectorScope} }, CodeInvalidObservation},
		{"empty-hostname", func(r *Report) { r.Hostname = available("") }, CodeInvalidHostname},
		{"long-hostname", func(r *Report) { r.Hostname = available(strings.Repeat("a", 254)) }, CodeInvalidHostname},
		{"hostname-control", func(r *Report) { r.Hostname = available("a\nb") }, CodeInvalidHostname},
		{"hostname-suffix", func(r *Report) { r.Hostname = available("pc.example") }, CodeInvalidHostname},
		{"hostname-utf8", func(r *Report) { r.Hostname = available("pc\xff") }, CodeInvalidHostname},
		{"version-major", func(r *Report) { r.OSVersion.Value.Major = 0 }, CodeInvalidVersion},
		{"version-build", func(r *Report) { r.OSVersion.Value.Build = 0 }, CodeInvalidVersion},
		{"native-enum", func(r *Report) { r.NativeArchitecture = available(Architecture("unknown")) }, CodeInvalidArchitecture},
		{"process-enum", func(r *Report) { r.ProcessArchitecture = available(Architecture("unknown")) }, CodeInvalidArchitecture},
		{"cpu-zero", func(r *Report) { r.CPU = available(CPUTopology{}) }, CodeInvalidCPU},
		{"cpu-inconsistent", func(r *Report) { r.CPU = available(CPUTopology{1, 2}) }, CodeInvalidCPU},
		{"memory-total", func(r *Report) { r.Memory = available(PhysicalMemory{}) }, CodeInvalidMemory},
		{"memory-inconsistent", func(r *Report) { r.Memory = available(PhysicalMemory{1, 2}) }, CodeInvalidMemory},
		{"memory-limit", func(r *Report) { r.Memory = available(PhysicalMemory{MaximumExactInteger + 1, 0}) }, CodeInvalidMemory},
		{"elapsed-limit", func(r *Report) { r.ElapsedSinceStartMilliseconds = available(MaximumExactInteger + 1) }, CodeInvalidElapsed},
		{"server-contact", func(r *Report) { r.ServerContact = available(NoValue{}) }, CodeInvalidScope},
		{"boot-identity", func(r *Report) { r.BootIdentity.Reason = PlatformUnsupported }, CodeInvalidScope},
		{"power-state", func(r *Report) { r.PowerState.Status = Available }, CodeInvalidScope},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := validReport()
			tc.mutate(&r)
			var ve ValidationError
			if err := Validate(r); !errors.As(err, &ve) || ve.Code != tc.code {
				t.Fatalf("Validate = %v, want %s", err, tc.code)
			}
			if payload, err := json.Marshal(r); err == nil || payload != nil {
				t.Fatalf("Marshal = %s, %v", payload, err)
			}
		})
	}
}

func TestClosedObservationStates(t *testing.T) {
	for _, reason := range []Reason{ProcedureUnavailable, QueryFailed, InvalidResult} {
		r := validReport()
		r.Hostname = unavailable[string](reason)
		if err := Validate(r); err != nil {
			t.Fatal(err)
		}
	}
	for _, a := range []Architecture{X86, X64, ARM32, ARM64, IA64} {
		r := validReport()
		r.NativeArchitecture = available(a)
		if err := Validate(r); err != nil {
			t.Fatal(err)
		}
	}
}

func TestSerializationBound(t *testing.T) {
	r := validReport()
	r.Hostname = available(strings.Repeat("z", maximumHostnameBytes))
	r.CollectedAt = time.Date(9999, 12, 31, 23, 59, 59, 999999999, time.UTC)
	r.OSVersion = available(WindowsVersion{^uint32(0), ^uint32(0), ^uint32(0)})
	r.CPU = available(CPUTopology{^uint32(0), ^uint16(0)})
	r.Memory = available(PhysicalMemory{MaximumExactInteger, MaximumExactInteger})
	r.ElapsedSinceStartMilliseconds = available(MaximumExactInteger)
	payload, err := json.Marshal(r)
	if err != nil || len(payload) > MaximumJSONBytes {
		t.Fatalf("size %d, %v", len(payload), err)
	}
	for _, escaped := range []string{strings.Repeat("\x00", 253), strings.Repeat("\\", 253), strings.Repeat("\"", 253), strings.Repeat("<", 253), strings.Repeat("a", MaximumJSONBytes)} {
		r.Hostname = available(escaped)
		if payload, err := json.Marshal(r); err == nil || payload != nil {
			t.Fatalf("escaped input admitted: %d bytes", len(payload))
		}
	}
}

func TestCancellationReturnsNoReport(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	r, err := Collect(ctx)
	if !errors.Is(err, context.Canceled) || !reflect.DeepEqual(r, Report{}) {
		t.Fatalf("%+v %v", r, err)
	}
}
