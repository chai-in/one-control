package indexing

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"testing"
)

type fakeSearch struct {
	snapshot Snapshot
	calls    []string
	cancel   context.CancelFunc
	fail     bool
}

func (s *fakeSearch) Snapshot() (Snapshot, error) { return s.snapshot, nil }
func (s *fakeSearch) Configure(startup string) error {
	s.calls = append(s.calls, "configure:"+startup)
	s.snapshot.Startup = startup
	if s.cancel != nil {
		s.cancel()
	}
	return nil
}
func (s *fakeSearch) Start(context.Context) error {
	s.calls = append(s.calls, "start")
	s.snapshot.Service = "running"
	if s.fail {
		return errors.New("lost result")
	}
	return nil
}
func (s *fakeSearch) Stop(context.Context) error {
	s.calls = append(s.calls, "stop")
	s.snapshot.Service = "stopped"
	return nil
}
func (s *fakeSearch) Close() {}
func TestChangesHonorLeaseAndPreserveEnablementWhenPausing(t *testing.T) {
	for _, tc := range []struct {
		name, command, state string
		cancel, fail         bool
		calls                []string
	}{
		{"enable", `{"kind":"indexing.enable","startup":"automatic-delayed"}`, "succeeded", false, false, []string{"configure:automatic-delayed", "start"}},
		{"cancel after startup", `{"kind":"indexing.enable","startup":"automatic"}`, "indeterminate", true, false, []string{"configure:automatic"}},
		{"lost start result", `{"kind":"indexing.resume"}`, "indeterminate", false, true, []string{"start"}},
		{"temporary stop", `{"kind":"indexing.pause"}`, "succeeded", false, false, []string{"stop"}},
		{"disable", `{"kind":"indexing.disable"}`, "succeeded", false, false, []string{"configure:disabled", "stop"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			service := &fakeSearch{snapshot: Snapshot{Supported: true, Service: "running", Startup: "automatic"}, fail: tc.fail}
			if tc.cancel {
				service.cancel = cancel
			}
			result := execute(ctx, json.RawMessage(tc.command), func(write bool) (provider, error) {
				if !write {
					t.Fatal("mutation opened read-only")
				}
				return service, nil
			})
			if result.State != tc.state || !reflect.DeepEqual(service.calls, tc.calls) {
				t.Fatalf("state=%s calls=%v", result.State, service.calls)
			}
		})
	}
}
func TestReadAndDisabledResumeDoNotMutate(t *testing.T) {
	service := &fakeSearch{snapshot: Snapshot{Supported: true, Service: "stopped", Startup: "disabled"}}
	result := execute(context.Background(), json.RawMessage(`{"kind":"indexing.status"}`), func(write bool) (provider, error) {
		if write {
			t.Fatal("status requested write access")
		}
		return service, nil
	})
	if result.State != "succeeded" {
		t.Fatal(result)
	}
	result = execute(context.Background(), json.RawMessage(`{"kind":"indexing.resume"}`), func(bool) (provider, error) { return service, nil })
	if result.State != "failed" || len(service.calls) != 0 {
		t.Fatalf("disabled resume mutated: %s %v", result.State, service.calls)
	}
}
