package applications

import (
	"context"
	"encoding/json"
	"onecontrol/native/internal/featurehost"
	"onecontrol/native/modules/user-session-host/session"
)

func Execute(ctx context.Context, raw json.RawMessage) featurehost.TaskResult {
	input, args, err := parse(raw)
	if err != nil {
		return featurehost.TaskResult{State: "failed", Result: json.RawMessage(`{"reason":"invalid_application_command"}`)}
	}
	executed := session.RunWinGet(ctx, session.Target{SessionID: input.Session.SessionID, UserSID: input.Session.UserSID, LogonID: input.Session.LogonID}, args)
	state, reason := "succeeded", "provider_completed"
	if executed.Err != nil {
		state, reason = "failed", "selected_user_provider_unavailable"
		if executed.Started {
			state, reason = "indeterminate", "user_provider_outcome_unresolved"
		}
	} else if executed.ExitCode == 0x8A15002B && input.Kind == "applications.upgrade" {
		reason = "no_applicable_update"
	} else if executed.ExitCode != 0 {
		state, reason = "indeterminate", "user_provider_exit_unresolved"
		if input.Kind == "applications.check" {
			state, reason = "failed", "winget_unavailable"
		}
	}
	receipt := map[string]any{"reason": reason, "provider": "winget", "executionStarted": executed.Started, "session": input.Session, "packageId": input.PackageID, "version": input.Version, "scope": "selected-user", "agreementPolicy": "organisation-default"}
	if executed.Err == nil {
		receipt["exitCode"] = executed.ExitCode
	}
	if reason == "no_applicable_update" {
		receipt["outcome"] = reason
		receipt["changed"] = false
	}
	result, _ := json.Marshal(receipt)
	return featurehost.TaskResult{State: state, Result: result}
}
