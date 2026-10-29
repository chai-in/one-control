package featurehost

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func taskRequest(t *testing.T, tasks *Tasks, operation string, value any) map[string]any {
	t.Helper()
	raw, _ := json.Marshal(value)
	response, err := tasks.Handle(context.Background(), operation, raw)
	if err != nil {
		t.Fatal(err)
	}
	var result map[string]any
	if json.Unmarshal(response, &result) != nil {
		t.Fatal("invalid task response")
	}
	return result
}
func TestTaskRunsOnceAndTransfersBoundedImmutableChunks(t *testing.T) {
	var calls atomic.Int32
	release := make(chan struct{})
	expected := json.RawMessage(`{"value":"` + strings.Repeat("x", 10000) + `"}`)
	tasks := NewTasks(func(ctx context.Context, command json.RawMessage) TaskResult {
		calls.Add(1)
		select {
		case <-release:
		case <-ctx.Done():
		}
		return TaskResult{State: "succeeded", Result: expected}
	})
	defer tasks.Close()
	id := "12345678-1234-4234-8234-123456789012"
	expires := time.Now().Add(time.Minute)
	start := map[string]any{"id": id, "command": map[string]any{"kind": "fixture"}, "leaseExpiresAt": expires, "endsAt": expires.Add(time.Minute)}
	taskRequest(t, tasks, "task.start", start)
	taskRequest(t, tasks, "task.start", start)
	close(release)
	var combined []byte
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		reply := taskRequest(t, tasks, "task.poll", map[string]any{"id": id, "leaseExpiresAt": expires, "offset": len(combined)})
		if reply["state"] == "running" {
			time.Sleep(time.Millisecond)
			continue
		}
		if reply["state"] != "succeeded" || int(reply["offset"].(float64)) != len(combined) {
			t.Fatal("inconsistent result")
		}
		part, err := base64.RawURLEncoding.DecodeString(reply["data"].(string))
		if err != nil || len(part) > 4096 {
			t.Fatal("unbounded result chunk")
		}
		combined = append(combined, part...)
		if len(combined) == int(reply["total"].(float64)) {
			break
		}
	}
	if string(combined) != string(expected) || calls.Load() != 1 {
		t.Fatal("result mismatch or task replay")
	}
}

func TestTaskLeaseExpiryCancelsWorkAndCannotBeRevived(t *testing.T) {
	cancelled := make(chan struct{})
	release := make(chan struct{})
	tasks := NewTasks(func(ctx context.Context, _ json.RawMessage) TaskResult {
		<-ctx.Done()
		close(cancelled)
		<-release
		return TaskResult{State: "indeterminate", Result: json.RawMessage(`{}`)}
	})
	defer tasks.Close()
	defer close(release)
	id := "12345678-1234-4234-8234-123456789012"
	taskRequest(t, tasks, "task.start", map[string]any{"id": id, "command": map[string]any{"kind": "fixture"}, "leaseExpiresAt": time.Now().Add(100 * time.Millisecond), "endsAt": time.Now().Add(time.Minute)})
	select {
	case <-cancelled:
	case <-time.After(2 * time.Second):
		t.Fatal("expired task was not cancelled")
	}
	raw, _ := json.Marshal(map[string]any{"id": id, "leaseExpiresAt": time.Now().Add(30 * time.Second), "offset": 0})
	if _, err := tasks.Handle(context.Background(), "task.poll", raw); err == nil {
		t.Fatal("expired work was revived")
	}
}
