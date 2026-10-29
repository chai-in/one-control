package featurehost

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"sync"
	"time"
)

const MaxTaskResult = 128 * 1024
const taskChunk = 4096

type TaskResult struct {
	State  string
	Result json.RawMessage
}
type TaskHandler func(context.Context, json.RawMessage) TaskResult
type task struct {
	id      string
	command json.RawMessage
	ends    time.Time
	expires time.Time
	timer   *time.Timer
	cancel  context.CancelFunc
	result  *TaskResult
}
type Tasks struct {
	mu      sync.Mutex
	current *task
	closed  bool
	handle  TaskHandler
}

func NewTasks(handle TaskHandler) *Tasks { return &Tasks{handle: handle} }
func (tasks *Tasks) Close() {
	tasks.mu.Lock()
	defer tasks.mu.Unlock()
	tasks.closed = true
	if tasks.current != nil {
		tasks.current.timer.Stop()
		tasks.current.cancel()
	}
}
func decodeTask(raw []byte, value any) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(value) != nil || decoder.Decode(new(any)) != io.EOF {
		return errors.New("invalid_task_request")
	}
	return nil
}
func (tasks *Tasks) Handle(_ context.Context, operation string, raw []byte) ([]byte, error) {
	tasks.mu.Lock()
	defer tasks.mu.Unlock()
	if tasks.closed {
		return nil, errors.New("task_host_closed")
	}
	switch operation {
	case "task.start":
		var input struct {
			ID             string          `json:"id"`
			Command        json.RawMessage `json:"command"`
			LeaseExpiresAt time.Time       `json:"leaseExpiresAt"`
			EndsAt         time.Time       `json:"endsAt"`
		}
		if decodeTask(raw, &input) != nil || len(input.ID) != 36 || !json.Valid(input.Command) || !time.Now().Before(input.LeaseExpiresAt) || input.LeaseExpiresAt.After(input.EndsAt) || input.LeaseExpiresAt.After(time.Now().Add(3*time.Minute)) {
			return nil, errors.New("invalid_task_start")
		}
		if tasks.current != nil {
			if tasks.current.id == input.ID {
				if !bytes.Equal(tasks.current.command, input.Command) || !tasks.current.ends.Equal(input.EndsAt) {
					return nil, errors.New("task_conflict")
				}
				return json.Marshal(map[string]any{"state": "accepted"})
			}
			if tasks.current.result == nil {
				return nil, errors.New("task_busy")
			}
		}
		ctx, cancel := context.WithCancel(context.Background())
		current := &task{id: input.ID, command: append(json.RawMessage(nil), input.Command...), ends: input.EndsAt, expires: input.LeaseExpiresAt, cancel: cancel}
		current.timer = time.AfterFunc(time.Until(current.expires), cancel)
		tasks.current = current
		go func() {
			result := tasks.handle(ctx, current.command)
			tasks.mu.Lock()
			defer tasks.mu.Unlock()
			current.timer.Stop()
			cancel()
			if (result.State != "succeeded" && result.State != "failed" && result.State != "indeterminate") || !json.Valid(result.Result) || len(result.Result) > MaxTaskResult {
				result = TaskResult{State: "indeterminate", Result: json.RawMessage(`{"reason":"invalid_provider_result"}`)}
			}
			current.result = &result
		}()
		return json.Marshal(map[string]any{"state": "accepted"})
	case "task.poll":
		var input struct {
			ID             string    `json:"id"`
			LeaseExpiresAt time.Time `json:"leaseExpiresAt"`
			Offset         int       `json:"offset"`
		}
		if decodeTask(raw, &input) != nil || tasks.current == nil || tasks.current.id != input.ID {
			return nil, errors.New("task_not_found")
		}
		current := tasks.current
		if current.result == nil {
			// A later poll cannot revive a lease that already expired locally.
			if !time.Now().Before(current.expires) || !time.Now().Before(input.LeaseExpiresAt) {
				current.cancel()
				return nil, errors.New("task_lease_expired")
			}
			if input.LeaseExpiresAt.After(current.ends) || input.LeaseExpiresAt.After(time.Now().Add(3*time.Minute)) {
				return nil, errors.New("invalid_task_lease")
			}
			if input.LeaseExpiresAt.After(current.expires) {
				current.expires = input.LeaseExpiresAt
				current.timer.Reset(time.Until(current.expires))
			}
			return json.Marshal(map[string]any{"state": "running"})
		}
		if input.Offset < 0 || input.Offset > len(current.result.Result) {
			return nil, errors.New("invalid_task_offset")
		}
		end := min(input.Offset+taskChunk, len(current.result.Result))
		return json.Marshal(map[string]any{"state": current.result.State, "offset": input.Offset, "total": len(current.result.Result), "data": base64.RawURLEncoding.EncodeToString(current.result.Result[input.Offset:end])})
	default:
		return nil, errors.New("unsupported_task_operation")
	}
}
