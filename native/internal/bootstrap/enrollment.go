package bootstrap

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"time"

	"onecontrol/native/internal/controlplane"
	"onecontrol/native/internal/ownership"
	"onecontrol/native/internal/protectedstore"
)

type identityState struct {
	SchemaVersion      int                     `json:"schemaVersion"`
	InstallationDigest string                  `json:"installationDigest"`
	Status             string                  `json:"status"`
	Credential         string                  `json:"credential"`
	PendingCredential  string                  `json:"pendingCredential,omitempty"`
	RotatedAt          int64                   `json:"rotatedAt"`
	Enrollment         controlplane.Enrollment `json:"enrollment"`
}

func (installation *Installation) readIdentity() (*identityState, error) {
	raw, err := protectedstore.ReadSecret(filepath.Join(installation.Root, "identity.dpapi"))
	if err != nil {
		return nil, err
	}
	defer clear(raw)
	var state identityState
	if err = strictJSON(raw, &state); err != nil {
		return nil, err
	}
	if state.SchemaVersion != 1 || state.InstallationDigest != installation.Digest {
		return nil, errors.New("identity_installation_mismatch")
	}
	return &state, nil
}

func (installation *Installation) saveIdentity(state *identityState) error {
	raw, err := json.Marshal(state)
	if err != nil {
		return err
	}
	defer clear(raw)
	return protectedstore.WriteSecret(filepath.Join(installation.Root, "identity.dpapi"), raw)
}

func newCredential() (string, error) {
	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw[:]), nil
}

func (installation *Installation) matches(enrollment controlplane.Enrollment) bool {
	return enrollment.DeviceID == installation.Config.DeviceID && enrollment.Platform == installation.Config.Platform && enrollment.Scope.Kind == "machine" && enrollment.Scope.MachineID == installation.Config.MachineID && enrollment.Scope.Principal == nil && enrollment.Scope.SessionID == nil && enrollment.Scope.SessionIncarnation == nil && enrollment.Scope.LocalNonce == nil && enrollment.EnrollmentID != ""
}

// Enroll never replays a submitted invitation. The locally generated credential
// recovers the original binding after an uncertain server response.
func (installation *Installation) Enroll(ctx context.Context, invitationFile string) (controlplane.Enrollment, error) {
	lockCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	owner, err := ownership.Acquire(lockCtx, filepath.Join(installation.Root, "bootstrap-owner.lock"))
	if err != nil {
		return controlplane.Enrollment{}, err
	}
	defer owner.Close()
	state, err := installation.readIdentity()
	if errors.Is(err, os.ErrNotExist) {
		credential, e := newCredential()
		if e != nil {
			return controlplane.Enrollment{}, e
		}
		state = &identityState{SchemaVersion: 1, InstallationDigest: installation.Digest, Status: "prepared", Credential: credential}
		if err = installation.saveIdentity(state); err != nil {
			return controlplane.Enrollment{}, err
		}
	} else if err != nil {
		return controlplane.Enrollment{}, err
	}
	client, err := controlplane.Open(installation.Config.Origin, state.Credential, installation.TLSRoots)
	if err != nil {
		return controlplane.Enrollment{}, err
	}
	defer client.Close()
	var enrollment controlplane.Enrollment
	if state.Status == "prepared" {
		raw, e := protectedstore.Read(invitationFile, 4096)
		if e != nil {
			return enrollment, e
		}
		var invitation struct {
			Token string `json:"token"`
		}
		e = strictJSON(raw, &invitation)
		clear(raw)
		if e != nil || invitation.Token == "" {
			return enrollment, errors.New("invalid_native_invitation_file")
		}
		state.Status = "submitted"
		if err = installation.saveIdentity(state); err != nil {
			return enrollment, err
		}
		enrollment, err = client.Enroll(ctx, invitation.Token)
		invitation.Token = ""
		if err != nil {
			enrollment, err = client.Enrollment(ctx)
		}
	} else if state.Status == "submitted" || state.Status == "enrolled" {
		enrollment, err = client.Enrollment(ctx)
	} else {
		return enrollment, errors.New("invalid_enrollment_state")
	}
	if err != nil {
		return enrollment, errors.New("enrollment_outcome_unresolved")
	}
	if !installation.matches(enrollment) || (state.Status == "enrolled" && !reflect.DeepEqual(state.Enrollment, enrollment)) {
		return controlplane.Enrollment{}, errors.New("enrollment_binding_mismatch")
	}
	state.Status, state.Enrollment = "enrolled", enrollment
	if state.RotatedAt == 0 {
		state.RotatedAt = time.Now().Unix()
	}
	if err = installation.saveIdentity(state); err != nil {
		return enrollment, err
	}
	return enrollment, nil
}

func (installation *Installation) rotate(ctx context.Context, state *identityState, client *controlplane.Client) (*controlplane.Client, error) {
	if state.PendingCredential == "" {
		credential, err := newCredential()
		if err != nil {
			return client, err
		}
		state.PendingCredential = credential
		if err = installation.saveIdentity(state); err != nil {
			return client, err
		}
		// The intent is durable before submission. Future cycles only probe the
		// pending credential; an uncertain mutation is not automatically replayed.
		_ = client.Rotate(ctx, controlplane.CredentialHash(state.PendingCredential))
	}
	replacement, err := controlplane.Open(installation.Config.Origin, state.PendingCredential, installation.TLSRoots)
	if err != nil {
		return client, err
	}
	binding, err := replacement.Enrollment(ctx)
	if err != nil || !reflect.DeepEqual(binding, state.Enrollment) {
		replacement.Close()
		return client, errors.New("credential_rotation_unresolved")
	}
	state.Credential, state.PendingCredential, state.RotatedAt = state.PendingCredential, "", time.Now().Unix()
	if err = installation.saveIdentity(state); err != nil {
		replacement.Close()
		return client, err
	}
	client.Close()
	return replacement, nil
}
