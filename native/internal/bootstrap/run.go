package bootstrap

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"reflect"
	"slices"
	"time"

	"onecontrol/native/internal/authority"
	"onecontrol/native/internal/controlplane"
	"onecontrol/native/internal/lifecycle"
	"onecontrol/native/internal/ownership"
	"onecontrol/native/internal/packages"
	"onecontrol/native/internal/protectedstore"
)

type Status struct {
	SchemaVersion int    `json:"schemaVersion"`
	Version       string `json:"version"`
	DeviceID      string `json:"deviceId"`
	EnrollmentID  string `json:"enrollmentId"`
	State         string `json:"state"`
	ObservedAt    string `json:"observedAt"`
	LastSuccess   string `json:"lastSuccess,omitempty"`
	LastInventory string `json:"lastInventory,omitempty"`
	Error         string `json:"error,omitempty"`
	CommandError  string `json:"commandError,omitempty"`
}

func (installation *Installation) Run(ctx context.Context, ready func()) (result error) {
	lockCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	owner, err := ownership.Acquire(lockCtx, filepath.Join(installation.Root, "bootstrap-owner.lock"))
	cancel()
	if err != nil {
		return err
	}
	defer owner.Close()
	state, err := installation.readIdentity()
	if err != nil {
		return err
	}
	if state.Status != "enrolled" || !installation.matches(state.Enrollment) {
		return errors.New("native_enrollment_required")
	}
	client, err := controlplane.Open(installation.Config.Origin, state.Credential, installation.TLSRoots)
	if err != nil {
		return err
	}
	defer func() { client.Close() }()
	packageRoot := filepath.Join(installation.Root, "modules")
	if err = protectedstore.Create(packageRoot); err != nil {
		return err
	}
	delivery, err := packages.Open(packages.Options{Origins: installation.Config.ArtifactOrigins, Networks: installation.Networks, Roots: installation.TLSRoots, Trust: installation.Trust, PublisherKeys: installation.Config.Publishers, StagingRoot: packageRoot, ResolveURL: func(ctx context.Context, artifact packages.Approval) (string, error) {
		return client.ResolveArtifactURL(ctx, artifact)
	}})
	if err != nil {
		return err
	}
	defer delivery.Close()
	openCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	manager, err := lifecycle.Open(openCtx, lifecycle.Options{Root: packageRoot, Trust: installation.Trust, Binding: authority.Binding{DeviceID: state.Enrollment.DeviceID, EnrollmentID: state.Enrollment.EnrollmentID, Platform: state.Enrollment.Platform, Scope: state.Enrollment.Scope}, BootstrapVersion: Version, Delivery: delivery})
	cancel()
	if err != nil {
		return err
	}
	status := Status{SchemaVersion: 1, Version: Version, DeviceID: state.Enrollment.DeviceID, EnrollmentID: state.Enrollment.EnrollmentID, State: "starting"}
	writeStatus := func(state string, operationError error) error {
		status.State, status.ObservedAt, status.Error = state, time.Now().UTC().Format(time.RFC3339), ""
		if operationError != nil {
			status.Error = operationError.Error()
		}
		raw, e := json.Marshal(status)
		if e != nil {
			return e
		}
		return protectedstore.Write(filepath.Join(installation.Root, "status.json"), raw)
	}
	defer func() {
		closeErr := manager.Close()
		result = errors.Join(result, closeErr)
		state := "stopped"
		if closeErr != nil {
			state = "custody-unknown"
		}
		result = errors.Join(result, writeStatus(state, result))
	}()
	outboxCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	outbox, err := controlplane.OpenReportOutbox(outboxCtx, filepath.Join(installation.Root, "reports.journal"), state.Enrollment.EnrollmentID)
	cancel()
	if err != nil {
		return err
	}
	defer outbox.Close()
	jobs, err := controlplane.OpenJobStore(filepath.Join(installation.Root, "jobs.dpapi"), state.Enrollment.EnrollmentID)
	if err != nil {
		return err
	}
	if err = writeStatus("starting", nil); err != nil {
		return err
	}
	if ready != nil {
		ready()
	}
	ticker := time.NewTicker(time.Duration(installation.Config.ReconcileSeconds) * time.Second)
	defer ticker.Stop()
	var inventoryAt time.Time
	for {
		if ctx.Err() != nil {
			return nil
		}
		cycleErr := func() error {
			if state.PendingCredential != "" || time.Now().Unix()-state.RotatedAt >= 30*24*60*60 {
				var e error
				client, e = installation.rotate(ctx, state, client)
				if e != nil {
					return e
				}
			}
			binding, e := client.Enrollment(ctx)
			if e != nil {
				return e
			}
			if !reflect.DeepEqual(binding, state.Enrollment) {
				return errors.New("enrollment_binding_mismatch")
			}
			if e = client.Heartbeat(ctx); e != nil {
				return e
			}
			if e = client.Reconcile(ctx, manager); e != nil {
				return e
			}
			policy, e := manager.Policy(time.Now().Unix())
			if e != nil {
				return e
			}
			status.CommandError = ""
			if jobs.Pending() || policy.Enabled["inventory"] != "" || policy.Enabled["windows-updates"] != "" || policy.Enabled["deployment"] != "" || policy.Enabled["indexing"] != "" {
				if e = client.ExecuteJob(ctx, manager, jobs); e != nil {
					status.CommandError = e.Error()
				}
			}
			if policy.Enabled["inventory"] != "" && !slices.Contains(policy.Disabled, "inventory") && time.Since(inventoryAt) >= time.Duration(installation.Config.InventorySeconds)*time.Second {
				if e = client.CollectInventory(ctx, manager, outbox); e != nil {
					return e
				}
				inventoryAt = time.Now()
				status.LastInventory = inventoryAt.UTC().Format(time.RFC3339)
			}
			status.LastSuccess = time.Now().UTC().Format(time.RFC3339)
			return nil
		}()
		if ctx.Err() != nil {
			return nil
		}
		if cycleErr != nil {
			stopErr := manager.Suspend()
			if err = writeStatus("unavailable", cycleErr); err != nil {
				return err
			}
			if stopErr != nil {
				return errors.Join(cycleErr, stopErr)
			}
		} else if err = writeStatus("connected", nil); err != nil {
			return err
		}
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
	}
}
