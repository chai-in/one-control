package ownership

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"
)

type publishedDeadline struct {
	context.Context
	at time.Time
}

func (c *publishedDeadline) Deadline() (time.Time, bool) {
	return c.at, true
}

func TestAcquisitionPreflightDoesNotOpen(t *testing.T) {
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	expired := &publishedDeadline{Context: context.Background(), at: time.Now().Add(-time.Second)}
	for _, tc := range []struct {
		name string
		ctx  context.Context
		want error
	}{
		{"canceled", canceled, context.Canceled},
		{"expired-callback-pending", expired, context.DeadlineExceeded},
		{"unbounded", context.Background(), nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "writer.lock")
			calls := 0
			o, err := acquire(tc.ctx, path, func(path string) (*os.File, error) { calls++; return open(path) })
			if o != nil {
				o.Close()
				t.Fatal("preflight returned owner")
			}
			if err == nil || (tc.want != nil && err != tc.want) {
				t.Fatalf("error %v, want %v", err, tc.want)
			}
			if calls != 0 {
				t.Fatalf("opener called %d times", calls)
			}
			if _, err := os.Stat(path); !os.IsNotExist(err) {
				t.Fatalf("lock created: %v", err)
			}
		})
	}
}

func TestAcquisitionAfterSynchronousOpen(t *testing.T) {
	for _, mode := range []string{"canceled", "expired-callback-pending", "live-after-old-budget"} {
		t.Run(mode, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "writer.lock")
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			published := &publishedDeadline{Context: ctx, at: time.Now().Add(time.Second)}
			var caller context.Context = ctx
			if mode == "expired-callback-pending" {
				caller = published
			}
			opened, release := make(chan struct{}), make(chan struct{})
			releaseOpener := sync.OnceFunc(func() { close(release) })
			var openedFile *os.File
			type result struct {
				owner *Owner
				err   error
			}
			finished := make(chan result, 1)
			var got *result
			t.Cleanup(func() {
				cancel()
				releaseOpener()
				if got == nil {
					r := <-finished
					got = &r
				}
				if got.owner != nil {
					got.owner.Close()
				}
			})
			go func() {
				o, err := acquire(caller, path, func(path string) (*os.File, error) {
					f, err := open(path)
					openedFile = f
					close(opened)
					<-release
					return f, err
				})
				finished <- result{o, err}
			}()
			select {
			case <-opened:
			case r := <-finished:
				got = &r
				t.Fatalf("acquisition ended before opener barrier: %v", got.err)
			case <-ctx.Done():
				t.Fatalf("opener barrier timeout: %v", ctx.Err())
			}
			switch mode {
			case "canceled":
				cancel()
			case "expired-callback-pending":
				<-time.After(time.Until(published.at))
				if caller.Err() != nil {
					t.Fatal("deadline callback was not pending")
				}
			case "live-after-old-budget":
				<-time.After(300 * time.Millisecond)
			}
			releaseOpener()
			r := <-finished
			got = &r
			if mode == "live-after-old-budget" {
				if got.err != nil || got.owner == nil {
					t.Fatalf("live caller refused: %v", got.err)
				}
				got.owner.Close()
			} else {
				want := context.Canceled
				if mode == "expired-callback-pending" {
					want = context.DeadlineExceeded
				}
				if got.owner != nil {
					got.owner.Close()
					t.Fatal("terminated caller acquired")
				}
				if got.err != want {
					t.Fatalf("error %v, want plain %v", got.err, want)
				}
				if err := openedFile.Close(); !errors.Is(err, os.ErrClosed) {
					t.Fatalf("returned handle was not closed: %v", err)
				}
			}
			next, err := acquireTest(path, time.Second)
			if err != nil {
				t.Fatal("returned handle retained ownership", err)
			}
			next.Close()
		})
	}
}

func TestWaitingContenderAcquiresAfterClose(t *testing.T) {
	path := filepath.Join(t.TempDir(), "writer.lock")
	first, err := acquireTest(path, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	runtime.GC()
	runtime.GC()
	if other, err := acquireTest(path, 80*time.Millisecond); err != context.DeadlineExceeded {
		if other != nil {
			other.Close()
		}
		t.Fatalf("live owner admitted competitor: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	opened := make(chan struct{})
	type result struct {
		owner *Owner
		err   error
	}
	finished := make(chan result, 1)
	var got *result
	t.Cleanup(func() {
		cancel()
		if got == nil {
			r := <-finished
			got = &r
		}
		if got.owner != nil {
			got.owner.Close()
		}
	})
	go func() {
		o, err := acquire(ctx, path, func(path string) (*os.File, error) { f, err := open(path); close(opened); return f, err })
		finished <- result{o, err}
	}()
	select {
	case <-opened:
	case r := <-finished:
		got = &r
		t.Fatalf("contender ended before opener readiness: %v", got.err)
	case <-ctx.Done():
		t.Fatalf("contender opener readiness timed out: %v", ctx.Err())
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case r := <-finished:
		got = &r
	case <-ctx.Done():
		t.Fatalf("contender did not finish after owner close: %v", ctx.Err())
	}
	if got.err != nil {
		t.Fatal(got.err)
	}
	if got.owner == nil {
		t.Fatal("waiting contender received no owner")
	}
	got.owner.Close()
	runtime.KeepAlive(first)
}
