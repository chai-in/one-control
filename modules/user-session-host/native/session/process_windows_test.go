package session

import (
	"context"
	"testing"
)

func TestNoProcessStartsForMissingOrCancelledSession(t *testing.T) {
	target := Target{SessionID: 0xfffffffe, UserSID: "S-1-5-21-1-2-3-1001", LogonID: "0000000000001234"}
	result := RunWinGet(context.Background(), target, []string{"--version"})
	if result.Started || result.Err == nil {
		t.Fatal("unbound process admitted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	result = RunWinGet(ctx, target, []string{"--version"})
	if result.Started || result.Err != context.Canceled {
		t.Fatal("cancelled process admitted")
	}
}
