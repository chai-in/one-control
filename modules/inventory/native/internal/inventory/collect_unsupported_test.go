//go:build !windows

package inventory

import (
	"context"
	"reflect"
	"testing"
	"time"
)

func TestUnsupportedPlatformExactReport(t *testing.T) {
	before := time.Now().UTC()
	r, err := Collect(context.Background())
	after := time.Now().UTC()
	if err != nil {
		t.Fatal(err)
	}
	if r.CollectedAt.Before(before) || r.CollectedAt.After(after) {
		t.Fatal(r.CollectedAt)
	}
	want := initialReport(r.CollectedAt)
	want.Hostname = platformUnsupported[string]()
	want.OSVersion = platformUnsupported[WindowsVersion]()
	want.NativeArchitecture = platformUnsupported[Architecture]()
	want.ProcessArchitecture = platformUnsupported[Architecture]()
	want.CPU = platformUnsupported[CPUTopology]()
	want.Memory = platformUnsupported[PhysicalMemory]()
	want.ElapsedSinceStartMilliseconds = platformUnsupported[uint64]()
	if !reflect.DeepEqual(r, want) {
		t.Fatalf("%+v", r)
	}
	if err := Validate(r); err != nil {
		t.Fatal(err)
	}
}
