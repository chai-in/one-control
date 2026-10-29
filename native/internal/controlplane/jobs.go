package controlplane

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"time"

	"onecontrol/native/internal/lifecycle"
	"onecontrol/native/internal/protectedstore"
)

type nativeLease struct {
	ID             string          `json:"id"`
	ClaimID        string          `json:"claimId"`
	LeaseExpiresAt time.Time       `json:"leaseExpiresAt"`
	EndsAt         time.Time       `json:"endsAt"`
	Command        json.RawMessage `json:"command"`
	Release        json.RawMessage `json:"release"`
	ModuleID       string          `json:"moduleId"`
	ModuleVersion  string          `json:"moduleVersion"`
	PolicyDigest   string          `json:"policyDigest"`
	EnrollmentID   string          `json:"enrollmentId"`
}
type claimResponse struct {
	Lease *nativeLease `json:"lease"`
}
type jobState struct {
	SchemaVersion int             `json:"schemaVersion"`
	EnrollmentID  string          `json:"enrollmentId"`
	Phase         string          `json:"phase"`
	RequestID     string          `json:"requestId"`
	LeaseToken    string          `json:"leaseToken"`
	PolicyDigest  string          `json:"policyDigest"`
	Lease         *nativeLease    `json:"lease"`
	Terminal      json.RawMessage `json:"terminal,omitempty"`
}

// JobStore is owned by the bootstrap's protected single-writer lock. Secrets
// are sealed at rest; a restored execution intent becomes indeterminate.
type JobStore struct {
	path, enrollment string
	state            *jobState
	poisoned         bool
	runningID        string
}

func (store *JobStore) Pending() bool {
	return store.state != nil && store.state.Phase != "acknowledged"
}

func OpenJobStore(path, enrollment string) (*JobStore, error) {
	store := &JobStore{path: path, enrollment: enrollment}
	raw, err := protectedstore.ReadSecret(path)
	if errors.Is(err, os.ErrNotExist) {
		return store, nil
	}
	if err != nil {
		return nil, err
	}
	defer clear(raw)
	if json.Unmarshal(raw, &store.state) != nil || store.state == nil || store.state.SchemaVersion != 1 || store.state.EnrollmentID != enrollment {
		return nil, errors.New("invalid_native_job_store")
	}
	return store, nil
}
func (s *JobStore) save(state *jobState) error {
	if s.poisoned {
		return errors.New("native_job_store_unavailable")
	}
	raw, err := json.Marshal(state)
	if err != nil {
		return err
	}
	defer clear(raw)
	if err = protectedstore.WriteSecret(s.path, raw); err != nil {
		s.poisoned = true
		return err
	}
	s.state = state
	return nil
}
func uuid() (string, error) {
	var bytes [16]byte
	if _, err := rand.Read(bytes[:]); err != nil {
		return "", err
	}
	bytes[6] = (bytes[6] & 15) | 64
	bytes[8] = (bytes[8] & 63) | 128
	return fmt.Sprintf("%x-%x-%x-%x-%x", bytes[:4], bytes[4:6], bytes[6:8], bytes[8:10], bytes[10:]), nil
}

func (s *JobStore) completed(outcome string, result json.RawMessage) error {
	state := *s.state
	raw, err := json.Marshal(struct {
		ClaimID    string          `json:"claimId"`
		LeaseToken string          `json:"leaseToken"`
		State      string          `json:"state"`
		Result     json.RawMessage `json:"result"`
	}{state.RequestID, state.LeaseToken, outcome, result})
	if err != nil {
		return err
	}
	state.Phase, state.Terminal = "completed", raw
	return s.save(&state)
}

func (c *Client) reportJob(ctx context.Context, store *JobStore) error {
	state := store.state
	raw, err := c.request(ctx, http.MethodPost, "/native-jobs/"+state.Lease.ID+"/report", state.Terminal, true)
	if err != nil {
		return err
	}
	var receipt struct {
		JobID   string `json:"jobId"`
		ClaimID string `json:"claimId"`
	}
	if json.Unmarshal(raw, &receipt) != nil || receipt.JobID != state.Lease.ID || receipt.ClaimID != state.RequestID {
		return errors.New("native_terminal_receipt_mismatch")
	}
	next := *state
	next.Phase = "acknowledged"
	return store.save(&next)
}

// ExecuteJob admits at most one operation per cycle. Only this invocation's
// freshly received lease may execute. Restarted intents are never replayed.
func (c *Client) ExecuteJob(ctx context.Context, manager *lifecycle.Manager, store *JobStore) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if store.poisoned || c.credential == "" {
		return errors.New("native_job_store_unavailable")
	}
	if store.state != nil && store.state.Phase != "acknowledged" {
		if store.state.Phase == "started" && store.runningID == store.state.RequestID {
			return c.pollTask(ctx, manager, store)
		}
		switch store.state.Phase {
		case "claim-submitted":
			raw, err := c.request(ctx, http.MethodGet, "/native-claims/"+store.state.RequestID, nil, true)
			if err != nil {
				return errors.New("native_claim_outcome_unresolved")
			}
			var recovered struct {
				State    string        `json:"state"`
				Response claimResponse `json:"response"`
			}
			if json.Unmarshal(raw, &recovered) != nil || recovered.State == "quarantined" {
				return errors.New("native_claim_outcome_unresolved")
			}
			if recovered.State == "empty" && recovered.Response.Lease == nil {
				next := *store.state
				next.Phase = "acknowledged"
				return store.save(&next)
			}
			if recovered.Response.Lease == nil {
				return errors.New("native_claim_outcome_unresolved")
			}
			lease := recovered.Response.Lease
			if lease.ClaimID != store.state.RequestID || lease.EnrollmentID != store.enrollment {
				return errors.New("native_claim_binding_mismatch")
			}
			next := *store.state
			next.Lease, next.Phase = lease, "admitted"
			if err = store.save(&next); err != nil {
				return err
			}
			fallthrough
		case "admitted", "started":
			if err := store.completed("indeterminate", json.RawMessage(`{"reason":"recovered_intent_not_replayed"}`)); err != nil {
				return err
			}
		case "completed":
		default:
			return errors.New("invalid_native_job_state")
		}
		return c.reportJob(ctx, store)
	}
	snapshot := manager.Snapshot()
	if snapshot == nil {
		return errors.New("native_policy_unavailable")
	}
	requestID, err := uuid()
	if err != nil {
		return err
	}
	var token [32]byte
	if _, err = rand.Read(token[:]); err != nil {
		return err
	}
	state := &jobState{SchemaVersion: 1, EnrollmentID: store.enrollment, Phase: "claim-submitted", RequestID: requestID, LeaseToken: base64.RawURLEncoding.EncodeToString(token[:]), PolicyDigest: snapshot.Checkpoint.PolicyDigest}
	if err = store.save(state); err != nil {
		return err
	}
	body, _ := json.Marshal(struct {
		RequestID      string `json:"requestId"`
		LeaseTokenHash string `json:"leaseTokenHash"`
		PolicyDigest   string `json:"policyDigest"`
	}{state.RequestID, CredentialHash(state.LeaseToken), state.PolicyDigest})
	raw, err := c.request(ctx, http.MethodPost, "/native-claim", body, true)
	if err != nil {
		var rejected *HTTPError
		if errors.As(err, &rejected) && (rejected.Status == 400 || rejected.Status == 401 || rejected.Status == 403 || rejected.Status == 409) {
			next := *state
			next.Phase = "acknowledged"
			if saveErr := store.save(&next); saveErr != nil {
				return saveErr
			}
		}
		return err
	}
	var response claimResponse
	if json.Unmarshal(raw, &response) != nil {
		return errors.New("invalid_native_claim")
	}
	if response.Lease == nil {
		next := *state
		next.Phase = "acknowledged"
		return store.save(&next)
	}
	lease := response.Lease
	if lease.ClaimID != requestID || lease.EnrollmentID != store.enrollment || lease.PolicyDigest != state.PolicyDigest {
		return errors.New("native_claim_binding_mismatch")
	}
	next := *state
	next.Phase, next.Lease = "admitted", lease
	if err = store.save(&next); err != nil {
		return err
	}
	var command struct {
		Kind string `json:"kind"`
	}
	if json.Unmarshal(lease.Command, &command) != nil {
		return errors.New("invalid_native_command")
	}
	permission := ""
	switch command.Kind {
	case "inventory.scan":
		if lease.ModuleID == "inventory" {
			permission = "inventory.read"
		}
	case "windows.scan", "windows.install":
		if lease.ModuleID == "windows-updates" {
			permission = "windows.manage"
		}
	}
	if permission == "" {
		if err = store.completed("failed", json.RawMessage(`{"reason":"provider_not_available"}`)); err != nil {
			return err
		}
		return c.reportJob(ctx, store)
	}
	policy, err := manager.Policy(time.Now().Unix())
	if err != nil {
		return err
	}
	if policy.Enabled[lease.ModuleID] != lease.ModuleVersion {
		return errors.New("native_job_selection_changed")
	}
	deadline := lease.LeaseExpiresAt
	if lease.EndsAt.Before(deadline) {
		deadline = lease.EndsAt
	}
	if !time.Now().Before(deadline) {
		if err = store.completed("failed", json.RawMessage(`{"reason":"lease_expired_before_execution"}`)); err != nil {
			return err
		}
		return c.reportJob(ctx, store)
	}
	next = *store.state
	next.Phase = "started"
	if err = store.save(&next); err != nil {
		return err
	}
	if lease.ModuleID == "windows-updates" {
		return c.startTask(ctx, manager, store, permission)
	}
	operationCtx, cancel := context.WithDeadline(ctx, deadline)
	result, operationErr := manager.Invoke(operationCtx, lease.ModuleID, permission, command.Kind, nil)
	cancel()
	if operationErr != nil {
		err = store.completed("indeterminate", json.RawMessage(`{"reason":"provider_outcome_unresolved"}`))
	} else if result.PolicyDigest != lease.PolicyDigest || !json.Valid(result.Payload) {
		err = store.completed("indeterminate", json.RawMessage(`{"reason":"provider_receipt_mismatch"}`))
	} else {
		err = store.completed("succeeded", json.RawMessage(result.Payload))
	}
	if err != nil {
		return err
	}
	return c.reportJob(ctx, store)
}
