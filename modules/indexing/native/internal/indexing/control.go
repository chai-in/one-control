package indexing

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"onecontrol/native/internal/featurehost"
)

type command struct {
	Kind    string `json:"kind"`
	Startup string `json:"startup,omitempty"`
}
type Snapshot struct {
	Supported      bool       `json:"supported"`
	Service        string     `json:"service"`
	Startup        string     `json:"startup"`
	Catalog        Catalog    `json:"catalog"`
	PauseMechanism string     `json:"pauseMechanism"`
	LocationScope  string     `json:"locationScope"`
	Locations      []Location `json:"locations,omitempty"`
}
type Location struct {
	Pattern  string `json:"pattern"`
	Included bool   `json:"included"`
	Default  bool   `json:"default"`
}
type Catalog struct {
	Status       string `json:"status"`
	PausedReason uint32 `json:"pausedReason,omitempty"`
	Items        *int32 `json:"items,omitempty"`
}
type provider interface {
	Snapshot() (Snapshot, error)
	Configure(string) error
	Start(context.Context) error
	Stop(context.Context) error
	Close()
}

func Execute(ctx context.Context, raw json.RawMessage) featurehost.TaskResult {
	return execute(ctx, raw, openSearch)
}
func execute(ctx context.Context, raw json.RawMessage, openProvider func(bool) (provider, error)) featurehost.TaskResult {
	var input command
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&input) != nil || decoder.Decode(new(any)) != io.EOF {
		return result("failed", nil, nil, "invalid_indexing_command")
	}
	switch input.Kind {
	case "indexing.status", "indexing.disable", "indexing.pause", "indexing.resume":
		if input.Startup != "" {
			return result("failed", nil, nil, "invalid_indexing_command")
		}
	case "indexing.enable":
		if input.Startup != "automatic" && input.Startup != "automatic-delayed" && input.Startup != "manual" {
			return result("failed", nil, nil, "invalid_indexing_startup")
		}
	default:
		return result("failed", nil, nil, "invalid_indexing_command")
	}
	search, err := openProvider(input.Kind != "indexing.status")
	if err != nil {
		return result("failed", nil, nil, "search_service_unavailable")
	}
	defer search.Close()
	before, err := search.Snapshot()
	if err != nil {
		return result("failed", nil, nil, "search_status_unavailable")
	}
	if input.Kind == "indexing.status" {
		return result("succeeded", nil, &before, "")
	}
	if !before.Supported {
		return result("failed", &before, nil, "search_feature_not_installed")
	}
	if ctx.Err() != nil {
		return result("failed", &before, nil, "lease_expired_before_change")
	}
	// Each service/configuration call may have taken effect even when its return
	// is lost. Never replay an uncertain change or claim rollback of it.
	switch input.Kind {
	case "indexing.enable":
		err = search.Configure(input.Startup)
		if err == nil && ctx.Err() == nil {
			err = search.Start(ctx)
		} else if err == nil {
			err = ctx.Err()
		}
	case "indexing.disable":
		err = search.Configure("disabled")
		if err == nil && ctx.Err() == nil {
			err = search.Stop(ctx)
		} else if err == nil {
			err = ctx.Err()
		}
	case "indexing.pause":
		err = search.Stop(ctx)
	case "indexing.resume":
		if before.Startup == "disabled" {
			return result("failed", &before, nil, "enable_search_before_resume")
		}
		err = search.Start(ctx)
	}
	after, readErr := search.Snapshot()
	if err != nil || readErr != nil || ctx.Err() != nil {
		return result("indeterminate", &before, nil, "search_change_requires_reconciliation")
	}
	expected := "running"
	if input.Kind == "indexing.disable" || input.Kind == "indexing.pause" {
		expected = "stopped"
	}
	if after.Service != expected {
		return result("indeterminate", &before, &after, "search_service_did_not_settle")
	}
	return result("succeeded", &before, &after, "")
}
func result(state string, before, after *Snapshot, reason string) featurehost.TaskResult {
	raw, _ := json.Marshal(struct {
		Before *Snapshot `json:"before,omitempty"`
		After  *Snapshot `json:"after,omitempty"`
		Reason string    `json:"reason,omitempty"`
	}{before, after, reason})
	return featurehost.TaskResult{State: state, Result: raw}
}

var errUnsupported = errors.New("platform_unsupported")
