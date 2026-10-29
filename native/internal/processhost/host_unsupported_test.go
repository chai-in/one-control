//go:build !windows

package processhost

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func TestUnsupportedContainment(t *testing.T) {
	_, err := Start(Config{Executable: "/not-launched", Instance: strings.Repeat("b", 64), ReadinessTimeout: time.Second, OperationTimeout: time.Second, StopTimeout: time.Second})
	if !errors.Is(err, ErrUnsupported) {
		t.Fatalf("unsupported host accepted: %v", err)
	}
}
