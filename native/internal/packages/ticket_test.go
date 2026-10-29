package packages

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestTicketDownloadsKeepSignedArtifactIdentity(t *testing.T) {
	files := []fixtureEntry{{"data/payload.txt", []byte("selected module fixture"), false}}
	archive := fixtureZIP(files)
	p := attestation(files, archive)
	reads := 0
	service := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reads++
		if r.URL.Path != "/package.zip" || r.URL.Query().Get("s") != "fixture-read-capability" {
			t.Error("missing exact artifact ticket")
			w.WriteHeader(403)
			return
		}
		w.Header().Set("Content-Length", fmt.Sprint(len(archive)))
		w.Header().Set("Content-Type", "application/zip")
		w.Write(archive)
	}))
	defer service.Close()
	original := approval(p, service.URL+"/package.zip")
	for _, valid := range []bool{true, false} {
		o := options(t, service)
		o.ResolveURL = func(_ context.Context, a Approval) (string, error) {
			if a != original {
				t.Error("artifact identity changed before authorization")
			}
			if valid {
				return a.URL + "?s=fixture-read-capability", nil
			}
			return service.URL + "/other.zip?s=fixture-read-capability", nil
		}
		delivery, err := open(o, true)
		if err != nil {
			t.Fatal(err)
		}
		_, err = delivery.Stage(context.Background(), original, signed(t, p, "publisher", publisherRole), 150)
		delivery.Close()
		if valid && err != nil {
			t.Fatal(err)
		}
		if !valid && (err == nil || !strings.Contains(err.Error(), "artifact_authorization_mismatch")) {
			t.Fatal("ticket changed signed path", err)
		}
	}
	if reads != 1 {
		t.Fatal("unapproved URL was fetched")
	}
}
