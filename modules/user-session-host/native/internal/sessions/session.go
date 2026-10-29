package sessions

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"onecontrol/native/internal/featurehost"
)

type Session struct {
	ID         uint32 `json:"sessionId"`
	Station    string `json:"station"`
	State      string `json:"state"`
	User       string `json:"user"`
	Domain     string `json:"domain"`
	UserSID    string `json:"userSid,omitempty"`
	LogonID    string `json:"logonId,omitempty"`
	Selectable bool   `json:"selectable"`
	Reason     string `json:"reason,omitempty"`
}

func Execute(ctx context.Context, raw json.RawMessage) featurehost.TaskResult {
	var command struct {
		Kind string `json:"kind"`
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&command) != nil || decoder.Decode(new(any)) != io.EOF || command.Kind != "sessions.list" {
		return failure("invalid_session_command")
	}
	list, partial, err := collect(ctx)
	if err != nil {
		return failure("session_query_unavailable")
	}
	result, _ := json.Marshal(map[string]any{"sessions": list, "partial": partial})
	return featurehost.TaskResult{State: "succeeded", Result: result}
}
func failure(reason string) featurehost.TaskResult {
	raw, _ := json.Marshal(map[string]string{"reason": reason})
	return featurehost.TaskResult{State: "failed", Result: raw}
}
