package applications

import (
	"strings"
	"testing"
)

const selected = `"session":{"sessionId":1,"userSid":"S-1-5-21-1-2-3-1001","logonId":"0000000000001234"}`

func TestPinnedSelectedUserUpgrade(t *testing.T) {
	input, args, err := parse([]byte(`{"kind":"applications.upgrade","packageId":"Microsoft.PowerToys","version":"1.2.3",` + selected + `}`))
	if err != nil || input.Session.SessionID != 1 {
		t.Fatal(err)
	}
	joined := strings.Join(args, " ")
	for _, required := range []string{"--id Microsoft.PowerToys --exact", "--version 1.2.3", "--source winget --scope user", "--silent --disable-interactivity"} {
		if !strings.Contains(joined, required) {
			t.Fatalf("missing %s", required)
		}
	}
	for _, forbidden := range []string{"--all", "--force", "--allow-reboot", "--ignore-security-hash", "--override"} {
		if strings.Contains(joined, forbidden) {
			t.Fatal(forbidden)
		}
	}
}
func TestRejectsUnboundAndUnpinnedRequests(t *testing.T) {
	for _, raw := range []string{
		`{"kind":"applications.check"}`,
		`{"kind":"applications.check","packageId":"--all",` + selected + `}`,
		`{"kind":"applications.upgrade","packageId":"--all","version":"1.2.3",` + selected + `}`,
		`{"kind":"applications.upgrade","packageId":"App.Test","version":"latest",` + selected + `}`,
		strings.Replace(`{"kind":"applications.check",`+selected+`}`, `"sessionId":1`, `"sessionId":0`, 1),
		strings.Replace(`{"kind":"applications.check",`+selected+`}`, `0000000000001234`, `stale`, 1),
	} {
		if _, _, err := parse([]byte(raw)); err == nil {
			t.Fatalf("accepted %s", raw)
		}
	}
}
