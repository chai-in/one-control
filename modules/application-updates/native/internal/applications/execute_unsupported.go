//go:build !windows

package applications

import (
	"context"
	"encoding/json"
	"onecontrol/native/internal/featurehost"
)

func Execute(context.Context, json.RawMessage) featurehost.TaskResult {
	return featurehost.TaskResult{State: "failed", Result: json.RawMessage(`{"reason":"platform_unsupported"}`)}
}
