package custody

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func ledgerSession(t *testing.T, v *vault) uint64 {
	t.Helper()
	out := call(t, v, command{op: attach})
	want(t, out.err, nil)
	t.Cleanup(func() { want(t, call(t, v, command{op: detach, session: out.session}).err, nil) })
	return out.session
}

func enqueue(t *testing.T, v *vault, session uint64, id string) request {
	t.Helper()
	q := req(id)
	want(t, call(t, v, command{op: admit, session: session, request: q}).err, nil)
	return q
}

func complete(t *testing.T, v *vault, q request, n int) {
	t.Helper()
	var effect atomic.Int32
	want(t, call(t, v, command{op: dispatch, request: q, work: testWorker{effects: &effect}}).err, nil)
	joined(t, v, n)
	if effect.Load() != 1 {
		t.Fatal("useful worker did not execute exactly once")
	}
}

func TestSeparateWriterAndGlobalQuotas(t *testing.T) {
	for _, scope := range []string{"writer", "global"} {
		for _, resource := range []string{"queued", "dispatched", "terminals", "tombstones", "sessions", "responses"} {
			t.Run(scope+"/"+resource, func(t *testing.T) {
				l := testLimits()
				switch resource {
				case "queued":
					l.writer.queued = 1
					if scope == "global" {
						l.service.queued = 1
					}
				case "dispatched":
					l.writer.dispatched = 1
					if scope == "global" {
						l.service.dispatched = 1
					}
				case "terminals":
					l.writer.terminals = 1
					l.writer.dispatched = 1
					if scope == "global" {
						l.service.terminals = 1
						l.service.dispatched = 1
					}
				case "tombstones":
					l.writer.tombstones = 1
					l.writer.queued = 1
					if scope == "global" {
						l.service.tombstones = 1
						l.service.queued = 1
					}
				case "sessions":
					l.writer.sessions = 1
					if scope == "global" {
						l.service.sessions = 1
					}
				case "responses":
					l.writer.responses = 1
					if scope == "global" {
						l.service.responses = 1
					}
				}
				r, e := newRegistry(l)
				want(t, e, nil)
				f1, f2 := startFixture(t), startFixture(t)
				if resource == "responses" {
					gate := newGate()
					v1 := pinTestWriter(t, r, "one", f1.process, gate.release)
					t.Cleanup(gate.open)
					v2 := pinTestWriter(t, r, "two", f2.process)
					ctx, cancel := context.WithTimeout(context.Background(), 15*time.Millisecond)
					want(t, v1.call(ctx, command{op: attach}).err, context.DeadlineExceeded)
					cancel()
					target := v1
					if scope == "global" {
						target = v2
					}
					want(t, call(t, target, command{op: attach}).err, errCapacity)
					if scope == "writer" {
						s := call(t, v2, command{op: attach})
						want(t, s.err, nil)
						want(t, call(t, v2, command{op: detach, session: s.session}).err, nil)
					}
					gate.open()
					deadline := time.Now().Add(time.Second)
					for call(t, v1, command{op: inspect}).view.sessions != 1 {
						if time.Now().After(deadline) {
							t.Fatal("abandoned caller erased admitted attachment")
						}
					}
					want(t, call(t, v1, command{op: detach, session: 1}).err, nil)
					s := call(t, v2, command{op: attach})
					want(t, s.err, nil)
					want(t, call(t, v2, command{op: detach, session: s.session}).err, nil)
					t.Log("response saturation uses a test-only paused runner; no hung kernel claim")
					return
				}
				v1, v2 := pinTestWriter(t, r, "one", f1.process), pinTestWriter(t, r, "two", f2.process)
				if resource == "sessions" {
					s1 := call(t, v1, command{op: attach})
					want(t, s1.err, nil)
					target := v1
					if scope == "global" {
						target = v2
					}
					want(t, call(t, target, command{op: attach}).err, errCapacity)
					want(t, call(t, v1, command{op: detach, session: s1.session}).err, nil)
					s2 := call(t, v2, command{op: attach})
					want(t, s2.err, nil)
					want(t, call(t, v2, command{op: detach, session: s2.session}).err, nil)
					return
				}
				s1, s2 := ledgerSession(t, v1), ledgerSession(t, v2)
				a := enqueue(t, v1, s1, "first")
				target, targetSession := v1, s1
				if scope == "global" {
					target, targetSession = v2, s2
				}
				switch resource {
				case "queued":
					want(t, call(t, target, command{op: admit, session: targetSession, request: req("blocked")}).err, errCapacity)
					complete(t, v1, a, 1)
					enqueue(t, target, targetSession, "after-queue-release")
				case "terminals", "tombstones":
					complete(t, v1, a, 1)
					want(t, call(t, target, command{op: admit, session: targetSession, request: req("blocked")}).err, errCapacity)
					want(t, call(t, v1, command{op: retire, request: a}).err, nil)
					want(t, call(t, v1, command{op: retire, request: a}).err, nil)
					if resource == "terminals" {
						enqueue(t, target, targetSession, "after-retirement")
					} else {
						want(t, call(t, target, command{op: admit, session: targetSession, request: req("still-blocked")}).err, errCapacity)
						if scope == "writer" {
							enqueue(t, v2, s2, "other-writer-positive")
						}
					}
				case "dispatched":
					entered, release := make(chan struct{}), make(chan struct{})
					var once sync.Once
					t.Cleanup(func() { once.Do(func() { close(release) }) })
					want(t, call(t, v1, command{op: dispatch, request: a, work: testWorker{entered: entered, release: release}}).err, nil)
					await(t, entered, "quota-held dispatched worker")
					b := enqueue(t, target, targetSession, "second")
					want(t, call(t, target, command{op: dispatch, request: b, work: testWorker{}}).err, errCapacity)
					if scope == "writer" {
						c := enqueue(t, v2, s2, "independent-positive")
						complete(t, v2, c, 1)
					}
					once.Do(func() { close(release) })
					joined(t, v1, 1)
					completed := 1
					if target == v1 {
						completed = 2
					}
					complete(t, target, b, completed)
				}
			})
		}
	}
}

func TestFreshWriterPositiveAndPermanentFenceCapacity(t *testing.T) {
	l := testLimits()
	l.writers = 2
	r, e := newRegistry(l)
	want(t, e, nil)
	f1 := startFixture(t)
	v1 := pinTestWriter(t, r, "old", f1.process)
	s1 := startSession(t, f1, v1, f1.ends[0], nil, nil, false)
	f1.issue(t, 0, "old-queued", false)
	q := observe(t, s1, nil)
	f1.kill(t)
	await(t, v1.sealedEvent, "old writer automatic seal")
	await(t, s1.done, "old transport join")
	s1.detach(t, v1)
	want(t, call(t, v1, command{op: retire, request: q}).err, nil)
	f2 := startFixture(t)
	v2 := pinTestWriter(t, r, "fresh", f2.process)
	if sameWriter(f1.process, f2.process) {
		t.Fatal("fresh writer is old process object")
	}
	if pinTestWriter(t, r, "fresh", f2.process) != v2 {
		t.Fatal("same live incarnation created a second vault")
	}
	s2 := startSession(t, f2, v2, f2.ends[0], nil, nil, false)
	f2.issue(t, 0, "fresh-useful", false)
	fresh := observe(t, s2, nil)
	if a := f2.issue(t, 0, "", true); a != "admitted" {
		t.Fatal(a)
	}
	complete(t, v2, fresh, 1)
	want(t, r.register("third", &vault{registry: r}), errCapacity)
	want(t, r.register("old", &vault{registry: r}), errBinding)
	want(t, call(t, v1, command{op: admit, session: s1.id, request: req("old-replay")}).err, errSealed)
	t.Log("fresh writer=1 useful ledger worker=1; old writer record remains fenced; no replacement feature activation or protected epoch claim")
}

func TestControlSlotsProgressAtAdmissionExhaustion(t *testing.T) {
	l := testLimits()
	l.writer.controls = 1
	l.service.controls = l.writers
	r, e := newRegistry(l)
	want(t, e, nil)
	f := startFixture(t)
	gate := newGate()
	v := pinTestWriter(t, r, "control", f.process, gate.release)
	t.Cleanup(gate.open)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Millisecond)
	want(t, v.call(ctx, command{op: inspect}).err, context.DeadlineExceeded)
	cancel()
	want(t, call(t, v, command{op: inspect}).err, errCapacity)
	gate.open()
	deadline := time.Now().Add(time.Second)
	for {
		out := call(t, v, command{op: inspect})
		if out.err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("control slot did not return")
		}
	}
	f.kill(t)
	await(t, v.sealedEvent, "automatic death under reserved control capacity")
}

func TestExplicitSealOnlyCounterexample(t *testing.T) {
	f := startFixture(t)
	explicitOnlySealed := false
	brokenAdmission := func() bool { return !explicitOnlySealed }
	if !brokenAdmission() {
		t.Fatal("counterexample positive failed")
	}
	f.kill(t)
	if dead, e := f.process.dead(); e != nil || !dead {
		t.Fatal(dead, e)
	}
	if !brokenAdmission() {
		t.Fatal("counterexample unexpectedly observed automatic death")
	}
	explicitOnlySealed = true
	if brokenAdmission() {
		t.Fatal("counterexample explicit seal failed")
	}
	t.Log("negative control retained: dead exact writer remains admitted by explicit-seal-only owner; no production code uses this owner")
}

func TestLimitsRejectUnboundedAndInconsistentBudgets(t *testing.T) {
	for _, mutate := range []func(*limits){func(l *limits) { l.writers = 0 }, func(l *limits) { l.service.responses = 65537 }, func(l *limits) { l.writer.terminals = 1 }, func(l *limits) { l.service.controls = 1 }, func(l *limits) { l.writer.sessions = 0 }} {
		l := testLimits()
		mutate(&l)
		_, e := newRegistry(l)
		want(t, e, errCapacity)
	}
}
