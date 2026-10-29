package packages

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// Deadline cancellation runs asynchronously. This context holds that notification
// pending while the real TLS response crosses its published deadline.
type pendingDeadlineContext struct {
	context.Context
	deadline time.Time
}

func (c pendingDeadlineContext) Deadline() (time.Time, bool) { return c.deadline, true }

func TestDownloadDeadlineBeforeCancellationNotification(t *testing.T) {
	entries := []fixtureEntry{{"data/x", []byte("payload"), false}}
	b := fixtureZIP(entries)
	p := attestation(entries, b)
	sig := signed(t, p, "publisher", publisherRole)
	headers := make(chan struct{})
	release := make(chan struct{})
	s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/zip")
		w.Header().Set("Content-Length", fmtInt(len(b)))
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush()
		close(headers)
		<-release
		_, _ = w.Write(b)
	}))
	defer s.Close()
	o := options(t, s)
	d, err := open(o, true)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	ctx := pendingDeadlineContext{Context: context.Background(), deadline: time.Now().Add(200 * time.Millisecond)}
	result := make(chan error, 1)
	go func() {
		_, err := d.Stage(ctx, approval(p, s.URL), sig, 150)
		result <- err
	}()
	select {
	case <-headers:
	case <-time.After(5 * time.Second):
		close(release)
		t.Fatal("TLS fixture did not send headers")
	}
	if remaining := time.Until(ctx.deadline); remaining > 0 {
		time.Sleep(remaining)
	}
	close(release)
	select {
	case err = <-result:
	case <-time.After(5 * time.Second):
		t.Fatal("download did not finish after body release")
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("body accepted after published deadline with cancellation pending: %v", err)
	}
	actual, err := os.ReadDir(o.StagingRoot)
	if err != nil || len(actual) != 0 {
		t.Fatalf("expired download staged bytes: entries=%d err=%v", len(actual), err)
	}
	t.Log("real TLS body released after caller deadline; cancellation pending; deadline rejected; no staged bytes")
}

func TestDownloadBeforeDeadlineWithCancellationPending(t *testing.T) {
	entries := []fixtureEntry{{"data/x", []byte("payload"), false}}
	b := fixtureZIP(entries)
	p := attestation(entries, b)
	s := server(t, b)
	o := options(t, s)
	d, err := open(o, true)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	ctx := pendingDeadlineContext{Context: context.Background(), deadline: time.Now().Add(time.Second)}
	r, err := d.Stage(ctx, approval(p, s.URL), signed(t, p, "publisher", publisherRole), 150)
	if err != nil {
		t.Fatal(err)
	}
	actual, err := os.ReadFile(filepath.Join(o.StagingRoot, r.StagingDirectory(), "data", "x"))
	if err != nil || string(actual) != "payload" {
		t.Fatalf("timely download payload=%q err=%v", actual, err)
	}
}
