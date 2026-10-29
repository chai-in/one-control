package sessions

import (
	"context"
	"testing"
)

func TestReadOnlySessionCollection(t *testing.T) {
	values, _, err := collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, value := range values {
		if value.Selectable && (value.State != "active" || value.UserSID == "" || value.LogonID == "") {
			t.Fatal("unbound session selectable")
		}
	}
}
func TestMissingSessionCannotYieldToken(t *testing.T) {
	token, err := Bind(Target{SessionID: 0xfffffffe, UserSID: "S-1-5-21-1-2-3-1001", LogonID: "0000000000001234"})
	if token != 0 {
		token.Close()
		t.Fatal("received token for nonexistent session")
	}
	if err == nil {
		t.Fatal("missing session admitted")
	}
}
