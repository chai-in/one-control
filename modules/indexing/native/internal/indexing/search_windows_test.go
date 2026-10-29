package indexing

import (
	"context"
	"encoding/json"
	"testing"
)

func TestActualWindowsSearchStatusDoesNotChangeService(t *testing.T) {
	search, err := openSearch(false)
	if err != nil {
		t.Fatal(err)
	}
	defer search.Close()
	before, err := search.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	result := Execute(context.Background(), json.RawMessage(`{"kind":"indexing.status"}`))
	if result.State != "succeeded" {
		t.Fatalf("%s", result.Result)
	}
	after, err := search.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("service=%s startup=%s catalog=%s scope=%s rules=%d", after.Service, after.Startup, after.Catalog.Status, after.LocationScope, len(after.Locations))
	if before.Startup != after.Startup {
		t.Fatal("read-only status changed startup")
	}
	if after.PauseMechanism != "service-stop-fallback" {
		t.Fatal("pause mechanism mislabeled")
	}
	if !after.Supported && after.Service != "not-installed" {
		t.Fatal("unsupported feature mislabeled")
	}
}
