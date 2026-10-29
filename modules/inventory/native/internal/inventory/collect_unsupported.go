//go:build !windows

package inventory

import (
	"context"
	"time"
)

func collectPlatform(ctx context.Context, at time.Time) (Report, error) {
	r := initialReport(at)
	r.Hostname = platformUnsupported[string]()
	r.OSVersion = platformUnsupported[WindowsVersion]()
	r.NativeArchitecture = platformUnsupported[Architecture]()
	r.ProcessArchitecture = platformUnsupported[Architecture]()
	r.CPU = platformUnsupported[CPUTopology]()
	r.Memory = platformUnsupported[PhysicalMemory]()
	r.ElapsedSinceStartMilliseconds = platformUnsupported[uint64]()
	if err := ctx.Err(); err != nil {
		return Report{}, err
	}
	return r, nil
}
