package controlplane

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"onecontrol/native/internal/lifecycle"
	"time"
)

func taskPermission(module string) string {
	switch module {
	case "windows-updates":
		return "windows.manage"
	case "indexing":
		return "indexing.manage"
	case "user-session-host":
		return "sessions.read"
	case "application-updates":
		return "applications.manage"
	}
	return ""
}
func (c *Client) taskUncertain(ctx context.Context, manager *lifecycle.Manager, store *JobStore, reason string) error {
	store.runningID = ""
	stopErr := manager.Suspend()
	body, _ := json.Marshal(map[string]string{"reason": reason})
	if err := store.completed("indeterminate", body); err != nil {
		return errors.Join(err, stopErr)
	}
	return errors.Join(c.reportJob(ctx, store), stopErr)
}
func (c *Client) startTask(ctx context.Context, manager *lifecycle.Manager, store *JobStore, permission string) error {
	lease := store.state.Lease
	payload, _ := json.Marshal(map[string]any{"id": lease.ID, "command": lease.Command, "leaseExpiresAt": lease.LeaseExpiresAt, "endsAt": lease.EndsAt})
	result, err := manager.Invoke(ctx, lease.ModuleID, permission, "task.start", payload)
	var accepted struct {
		State string `json:"state"`
	}
	if err != nil || result.PolicyDigest != lease.PolicyDigest || json.Unmarshal(result.Payload, &accepted) != nil || accepted.State != "accepted" {
		return c.taskUncertain(ctx, manager, store, "provider_start_unresolved")
	}
	store.runningID = store.state.RequestID
	return nil
}
func (c *Client) pollTask(ctx context.Context, manager *lifecycle.Manager, store *JobStore) error {
	state := store.state
	lease := state.Lease
	permission := taskPermission(lease.ModuleID)
	if permission == "" || !time.Now().Before(lease.LeaseExpiresAt) || !time.Now().Before(lease.EndsAt) {
		return c.taskUncertain(ctx, manager, store, "provider_lease_expired")
	}
	snapshot := manager.Snapshot()
	if snapshot == nil {
		return c.taskUncertain(ctx, manager, store, "provider_policy_unavailable")
	}
	policyDigest := snapshot.Checkpoint.PolicyDigest
	payload, _ := json.Marshal(map[string]any{"claimId": state.RequestID, "leaseToken": state.LeaseToken, "policyDigest": policyDigest})
	raw, err := c.request(ctx, http.MethodPost, "/native-jobs/"+lease.ID+"/renew", payload, true)
	if err != nil {
		return c.taskUncertain(ctx, manager, store, "provider_renewal_unresolved")
	}
	var renewal struct {
		LeaseExpiresAt time.Time `json:"leaseExpiresAt"`
	}
	if json.Unmarshal(raw, &renewal) != nil || !time.Now().Before(renewal.LeaseExpiresAt) || renewal.LeaseExpiresAt.After(lease.EndsAt) {
		return c.taskUncertain(ctx, manager, store, "provider_lease_invalid")
	}
	next := *state
	copyLease := *lease
	copyLease.LeaseExpiresAt = renewal.LeaseExpiresAt
	copyLease.PolicyDigest = policyDigest
	next.Lease = &copyLease
	next.PolicyDigest = policyDigest
	if err = store.save(&next); err != nil {
		return errors.Join(err, manager.Suspend())
	}
	var result []byte
	outcome := ""
	total := -1
	for {
		payload, _ = json.Marshal(map[string]any{"id": lease.ID, "leaseExpiresAt": renewal.LeaseExpiresAt, "offset": len(result)})
		chunk, err := manager.Invoke(ctx, lease.ModuleID, permission, "task.poll", payload)
		var response struct {
			State  string `json:"state"`
			Offset int    `json:"offset"`
			Total  int    `json:"total"`
			Data   string `json:"data"`
		}
		if err != nil || chunk.PolicyDigest != policyDigest || json.Unmarshal(chunk.Payload, &response) != nil {
			return c.taskUncertain(ctx, manager, store, "provider_result_unresolved")
		}
		if response.State == "running" && len(result) == 0 {
			return nil
		}
		if (response.State != "succeeded" && response.State != "failed" && response.State != "indeterminate") || response.Total <= 0 || response.Total > 128*1024 || response.Offset != len(result) || (total >= 0 && (total != response.Total || outcome != response.State)) {
			return c.taskUncertain(ctx, manager, store, "provider_result_invalid")
		}
		part, err := base64.RawURLEncoding.Strict().DecodeString(response.Data)
		if err != nil || len(part) == 0 || len(part) > 4096 || len(result)+len(part) > response.Total {
			return c.taskUncertain(ctx, manager, store, "provider_result_invalid")
		}
		total, outcome = response.Total, response.State
		result = append(result, part...)
		if len(result) == total {
			break
		}
	}
	if !json.Valid(result) {
		return c.taskUncertain(ctx, manager, store, "provider_result_invalid")
	}
	if err = store.completed(outcome, result); err != nil {
		return err
	}
	store.runningID = ""
	return c.reportJob(ctx, store)
}
