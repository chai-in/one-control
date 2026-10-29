package wake

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type fixture struct {
	t        *testing.T
	receiver *net.UDPConn
	dials    atomic.Int32
	writes   []writeObservation
}

type writeObservation struct {
	started, finished time.Time
	n                 int
	err               error
}

type observedConnection struct {
	connection
	writes *[]writeObservation
}

func (conn *observedConnection) Write(payload []byte) (int, error) {
	started := time.Now()
	n, err := conn.connection.Write(payload)
	*conn.writes = append(*conn.writes, writeObservation{started: started, finished: time.Now(), n: n, err: err})
	return n, err
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	receiver, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { receiver.Close() })
	return &fixture{t: t, receiver: receiver}
}

func fictionalSite() Site {
	return Site{ID: "fictional-site", InterfaceName: "fictional0", SourceIPv4: "192.168.76.10", SubnetIPv4: "192.168.76.0/24"}
}

func fictionalTarget() Target {
	return Target{SiteID: "fictional-site", MAC: "02:11:22:Ab:CD:ef"}
}

func fictionalInterface(name string) (interfaceState, error) {
	return interfaceState{index: 41, name: name, flags: net.FlagUp | net.FlagBroadcast, addresses: []netip.Prefix{netip.MustParsePrefix("192.168.76.10/24")}}, nil
}

func (f *fixture) connect(ctx context.Context, path localPath) (connection, error) {
	f.dials.Add(1)
	if path.name != "fictional0" || path.source != netip.MustParseAddr("192.168.76.10") || path.subnet != netip.MustParsePrefix("192.168.76.0/24") || path.destination != netip.MustParseAddrPort("192.168.76.255:9") {
		f.t.Error("sender selected an unexpected fictional network path")
		return nil, errors.New("unexpected path")
	}
	dialer := net.Dialer{LocalAddr: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)}}
	conn, err := dialer.DialContext(ctx, "udp4", f.receiver.LocalAddr().String())
	if err != nil {
		return nil, err
	}
	return &observedConnection{connection: conn, writes: &f.writes}, nil
}

func (f *fixture) packet() {
	f.t.Helper()
	if !f.readPacket(time.Second) {
		f.t.Fatal("expected a captured packet")
	}
}

func (f *fixture) readPacket(timeout time.Duration) bool {
	f.t.Helper()
	if err := f.receiver.SetReadDeadline(time.Now().Add(timeout)); err != nil {
		f.t.Fatal(err)
	}
	var payload [2048]byte
	n, _, err := f.receiver.ReadFromUDP(payload[:])
	var timeoutError net.Error
	if errors.As(err, &timeoutError) && timeoutError.Timeout() {
		return false
	}
	if err != nil {
		f.t.Fatal(err)
	}
	if n != 102 {
		f.t.Fatalf("packet length = %d, want 102", n)
	}
	for i := 0; i < 6; i++ {
		if payload[i] != 0xff {
			f.t.Fatalf("packet byte %d = %02x, want ff", i, payload[i])
		}
	}
	want := [6]byte{0x02, 0x11, 0x22, 0xab, 0xcd, 0xef}
	for repeat := 0; repeat < 16; repeat++ {
		for octet, value := range want {
			position := 6 + repeat*6 + octet
			if payload[position] != value {
				f.t.Fatalf("packet byte %d = %02x, want %02x", position, payload[position], value)
			}
		}
	}
	return true
}

func (f *fixture) quiet(duration time.Duration) {
	f.t.Helper()
	if err := f.receiver.SetReadDeadline(time.Now().Add(duration)); err != nil {
		f.t.Fatal(err)
	}
	var payload [2048]byte
	n, _, err := f.receiver.ReadFromUDP(payload[:])
	if err == nil {
		f.t.Fatalf("unexpected extra datagram of %d bytes", n)
	}
	var timeout net.Error
	if !errors.As(err, &timeout) || !timeout.Timeout() {
		f.t.Fatalf("receiver did not observe a timeout: %v", err)
	}
}

func TestLoopbackCapturesExactlyThreeCompletePackets(t *testing.T) {
	f := newFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	done := make(chan result, 1)
	go func() {
		report, err := send(ctx, fictionalSite(), fictionalTarget(), fictionalInterface, f.connect)
		done <- result{report, err}
	}()
	for range 3 {
		f.packet()
	}
	got := await(t, done)
	if got.err != nil || got.report.Attempts != [3]AttemptOutcome{LocalKernelAccepted, LocalKernelAccepted, LocalKernelAccepted} || f.dials.Load() != 1 {
		t.Fatalf("report=%+v dials=%d err=%v", got.report, f.dials.Load(), got.err)
	}
	if len(f.writes) != 3 {
		t.Fatalf("observed %d writes, want 3", len(f.writes))
	}
	for i := 1; i < len(f.writes); i++ {
		gap := f.writes[i].started.Sub(f.writes[i-1].finished)
		if gap < 90*time.Millisecond {
			t.Fatalf("write gap = %v, want at least 100 ms within timer tolerance", gap)
		}
	}
	f.quiet(30 * time.Millisecond)
}

func TestPrivateSubnetBroadcastDerivation(t *testing.T) {
	for _, test := range []struct{ source, subnet, destination string }{
		{"10.2.3.4", "10.0.0.0/8", "10.255.255.255:9"},
		{"172.16.0.1", "172.16.0.0/12", "172.31.255.255:9"},
		{"192.168.2.1", "192.168.0.0/16", "192.168.255.255:9"},
		{"192.168.76.9", "192.168.76.8/30", "192.168.76.11:9"},
	} {
		t.Run(test.subnet, func(t *testing.T) {
			site := fictionalSite()
			site.SourceIPv4, site.SubnetIPv4 = test.source, test.subnet
			path, err := parse(site, fictionalTarget())
			if err != nil || path.destination.String() != test.destination {
				t.Fatalf("destination=%v err=%v, want %s", path.destination, err, test.destination)
			}
		})
	}
}

func TestInvalidConfigurationEmitsNothing(t *testing.T) {
	cases := []struct {
		name string
		edit func(*Site, *Target)
	}{
		{"empty-site", func(s *Site, _ *Target) { s.ID = "" }},
		{"long-site", func(s *Site, _ *Target) { s.ID = strings.Repeat("s", 129) }},
		{"site-space", func(s *Site, target *Target) { s.ID = " fictional-site"; target.SiteID = s.ID }},
		{"site-mismatch", func(_ *Site, target *Target) { target.SiteID = "another-site" }},
		{"empty-interface", func(s *Site, _ *Target) { s.InterfaceName = "" }},
		{"long-interface", func(s *Site, _ *Target) { s.InterfaceName = strings.Repeat("n", 256) }},
		{"interface-space", func(s *Site, _ *Target) { s.InterfaceName += " " }},
		{"interface-nul", func(s *Site, _ *Target) { s.InterfaceName += "\x00" }},
	}
	for _, mac := range []string{"", "00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff", "01:11:22:ab:cd:ef", "02-11-22-ab-cd-ef", "021122abcdef", "2:11:22:ab:cd:ef", "02:11:22:ab:cd:ef:01:02", "02:11:22:ab:cd:eg", " 02:11:22:ab:cd:ef", "02:11:22:ab:cd:ef ", "02:11-22:ab:cd:ef"} {
		cases = append(cases, struct {
			name string
			edit func(*Site, *Target)
		}{"mac-" + mac, func(_ *Site, target *Target) { target.MAC = mac }})
	}
	for _, source := range []string{"", "192.168.76.0", "192.168.76.255", "192.168.77.10", "8.8.8.8", "127.0.0.1", "169.254.1.2", "224.1.1.1", "0.0.0.0", "::1", "::ffff:192.168.76.10", "192.168.076.10", "192.168.76.10 "} {
		cases = append(cases, struct {
			name string
			edit func(*Site, *Target)
		}{"source-" + source, func(s *Site, _ *Target) { s.SourceIPv4 = source }})
	}
	for _, subnet := range []string{"", "192.168.76.10/24", "192.168.76.0/31", "192.168.76.10/32", "192.168.0.0/15", "0.0.0.0/0", "8.8.8.0/24", "127.0.0.0/8", "169.254.0.0/16", "224.0.0.0/4", "::ffff:192.168.76.0/120", "192.168.76.0/024", "192.168.76.0/24 "} {
		cases = append(cases, struct {
			name string
			edit func(*Site, *Target)
		}{"subnet-" + subnet, func(s *Site, _ *Target) { s.SubnetIPv4 = subnet }})
	}
	f := newFixture(t)
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			site, target := fictionalSite(), fictionalTarget()
			test.edit(&site, &target)
			report, err := send(context.Background(), site, target, fictionalInterface, f.connect)
			if err == nil || report != (Report{}) || f.dials.Load() != 0 {
				t.Fatalf("invalid configuration reached send: report=%+v err=%v", report, err)
			}
		})
	}
	f.quiet(15 * time.Millisecond)
	if _, err := send(context.Background(), fictionalSite(), fictionalTarget(), fictionalInterface, f.connect); err != nil {
		t.Fatal(err)
	}
	for range 3 {
		f.packet()
	}
	f.quiet(15 * time.Millisecond)
}

func TestInterfaceRejectionBeforeDial(t *testing.T) {
	cases := []struct {
		name string
		edit func(*interfaceState) error
	}{
		{"missing", func(*interfaceState) error { return errors.New("missing") }},
		{"down", func(s *interfaceState) error { s.flags &^= net.FlagUp; return nil }},
		{"no-broadcast", func(s *interfaceState) error { s.flags &^= net.FlagBroadcast; return nil }},
		{"loopback", func(s *interfaceState) error { s.flags |= net.FlagLoopback; return nil }},
		{"point-to-point", func(s *interfaceState) error { s.flags |= net.FlagPointToPoint; return nil }},
		{"wrong-name", func(s *interfaceState) error { s.name = "another0"; return nil }},
		{"missing-index", func(s *interfaceState) error { s.index = 0; return nil }},
		{"missing-source", func(s *interfaceState) error { s.addresses = nil; return nil }},
		{"wrong-prefix", func(s *interfaceState) error {
			s.addresses = []netip.Prefix{netip.MustParsePrefix("192.168.76.10/25")}
			return nil
		}},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			f := newFixture(t)
			lookup := func(name string) (interfaceState, error) {
				state, _ := fictionalInterface(name)
				err := test.edit(&state)
				return state, err
			}
			report, err := send(context.Background(), fictionalSite(), fictionalTarget(), lookup, f.connect)
			if err == nil || report != (Report{}) || f.dials.Load() != 0 {
				t.Fatalf("report=%+v dials=%d err=%v", report, f.dials.Load(), err)
			}
			f.quiet(5 * time.Millisecond)
		})
	}
}

func TestInterfaceChangePreservesFirstCapturedWrite(t *testing.T) {
	for _, change := range []string{"replaced", "renumbered", "flags", "removed"} {
		t.Run(change, func(t *testing.T) {
			f := newFixture(t)
			queries := 0
			lookup := func(name string) (interfaceState, error) {
				queries++
				state, _ := fictionalInterface(name)
				if queries >= 3 {
					switch change {
					case "replaced":
						state.index++
					case "renumbered":
						state.addresses = []netip.Prefix{netip.MustParsePrefix("192.168.76.11/24")}
					case "flags":
						state.flags |= net.FlagMulticast
					case "removed":
						return state, errors.New("removed")
					}
				}
				return state, nil
			}
			report, err := send(context.Background(), fictionalSite(), fictionalTarget(), lookup, f.connect)
			if err == nil || report.Attempts != [3]AttemptOutcome{LocalKernelAccepted, NotAttempted, NotAttempted} {
				t.Fatalf("report=%+v err=%v", report, err)
			}
			f.packet()
			f.quiet(20 * time.Millisecond)
		})
	}
}

type pendingDeadline struct {
	context.Context
	at time.Time
}

func (ctx pendingDeadline) Deadline() (time.Time, bool) { return ctx.at, true }

func TestPublicSendRejectsCanceledAndExpiredContexts(t *testing.T) {
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	expired := pendingDeadline{Context: context.Background(), at: time.Now().Add(-time.Second)}
	for _, test := range []struct {
		ctx  context.Context
		want error
	}{{canceled, context.Canceled}, {expired, context.DeadlineExceeded}} {
		f := newFixture(t)
		report, err := Send(test.ctx, fictionalSite(), fictionalTarget())
		if !errors.Is(err, test.want) || report != (Report{}) {
			t.Fatalf("report=%+v err=%v want=%v", report, err, test.want)
		}
		f.quiet(5 * time.Millisecond)
	}
	if report, err := Send(nil, fictionalSite(), fictionalTarget()); err == nil || report != (Report{}) {
		t.Fatalf("nil context report=%+v err=%v", report, err)
	}
}

type result struct {
	report Report
	err    error
}

func await(t *testing.T, done <-chan result) result {
	t.Helper()
	select {
	case got := <-done:
		return got
	case <-time.After(2 * time.Second):
		t.Fatal("sender did not stop within the test bound")
		return result{}
	}
}

func TestLoopbackCancellationAfterFirstCapturedPacket(t *testing.T) {
	f := newFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	release := make(chan struct{})
	var once sync.Once
	releaseWrite := func() { once.Do(func() { close(release) }) }
	defer releaseWrite()
	connect := func(ctx context.Context, path localPath) (connection, error) {
		conn, err := f.connect(ctx, path)
		return &captureGateConnection{connection: conn, release: release}, err
	}
	done := make(chan result, 1)
	go func() {
		report, err := send(ctx, fictionalSite(), fictionalTarget(), fictionalInterface, connect)
		done <- result{report, err}
	}()
	f.packet()
	cancel()
	releaseWrite()
	got := await(t, done)
	if !errors.Is(got.err, context.Canceled) || got.report.Attempts != [3]AttemptOutcome{LocalKernelAccepted, NotAttempted, NotAttempted} {
		t.Fatalf("report=%+v err=%v", got.report, got.err)
	}
	f.quiet(130 * time.Millisecond)
}

type captureGateConnection struct {
	connection
	release <-chan struct{}
}

func (conn *captureGateConnection) Write(payload []byte) (int, error) {
	n, err := conn.connection.Write(payload)
	if err == nil {
		<-conn.release
	}
	return n, err
}

func TestLoopbackEarlierDeadlinePreservesObservedWrites(t *testing.T) {
	for _, pending := range []bool{false, true} {
		t.Run(map[bool]string{false: "notified", true: "notification-pending"}[pending], func(t *testing.T) {
			f := newFixture(t)
			var ctx context.Context
			var cancel context.CancelFunc = func() {}
			deadline := time.Now().Add(70 * time.Millisecond)
			if pending {
				ctx = pendingDeadline{Context: context.Background(), at: deadline}
			} else {
				ctx, cancel = context.WithDeadline(context.Background(), deadline)
			}
			defer cancel()
			report, err := send(ctx, fictionalSite(), fictionalTarget(), fictionalInterface, f.connect)
			t.Logf("deadline pending=%v report=%+v writes=%d returned_after_deadline=%v err=%v", pending, report, len(f.writes), time.Since(deadline), err)
			for i, write := range f.writes {
				t.Logf("write=%d n=%d err=%v started_before_deadline=%v finished_before_deadline=%v", i, write.n, write.err, deadline.Sub(write.started), deadline.Sub(write.finished))
			}
			if !errors.Is(err, context.DeadlineExceeded) || time.Now().Before(deadline) || len(f.writes) > 1 {
				t.Fatalf("report=%+v err=%v", report, err)
			}
			var want Report
			if len(f.writes) == 1 {
				write := f.writes[0]
				if write.n == 102 && write.err == nil {
					want.Attempts[0] = LocalKernelAccepted
					f.packet()
				} else {
					want.Attempts[0] = UnknownWrite
					f.readPacket(60 * time.Millisecond)
				}
			}
			if report != want {
				t.Fatalf("report=%+v want=%+v from observed writes", report, want)
			}
			f.quiet(60 * time.Millisecond)
		})
	}
}

func TestDeadlineExpiringDuringInterfaceQueryNeverDials(t *testing.T) {
	f := newFixture(t)
	ctx := pendingDeadline{Context: context.Background(), at: time.Now().Add(15 * time.Millisecond)}
	lookup := func(name string) (interfaceState, error) {
		time.Sleep(25 * time.Millisecond)
		return fictionalInterface(name)
	}
	report, err := send(ctx, fictionalSite(), fictionalTarget(), lookup, f.connect)
	if !errors.Is(err, context.DeadlineExceeded) || report != (Report{}) || f.dials.Load() != 0 {
		t.Fatalf("report=%+v dials=%d err=%v", report, f.dials.Load(), err)
	}
	f.quiet(10 * time.Millisecond)
}

type faultConnection struct {
	connection
	calls int
	short bool
}

func (conn *faultConnection) Write(payload []byte) (int, error) {
	conn.calls++
	if conn.calls == 1 {
		return conn.connection.Write(payload)
	}
	if conn.short {
		return len(payload) - 1, nil
	}
	return 0, io.ErrUnexpectedEOF
}

func TestSyntheticWriteFaultAfterRealFirstCaptureIsUnknown(t *testing.T) {
	for _, short := range []bool{false, true} {
		t.Run(map[bool]string{false: "error", true: "short-write"}[short], func(t *testing.T) {
			f := newFixture(t)
			var fault *faultConnection
			connect := func(ctx context.Context, path localPath) (connection, error) {
				conn, err := f.connect(ctx, path)
				fault = &faultConnection{connection: conn, short: short}
				return fault, err
			}
			report, err := send(context.Background(), fictionalSite(), fictionalTarget(), fictionalInterface, connect)
			want := io.ErrUnexpectedEOF
			if short {
				want = io.ErrShortWrite
			}
			if !errors.Is(err, want) || fault.calls != 2 || report.Attempts != [3]AttemptOutcome{LocalKernelAccepted, UnknownWrite, NotAttempted} {
				t.Fatalf("report=%+v calls=%d err=%v", report, fault.calls, err)
			}
			f.packet()
			f.quiet(20 * time.Millisecond)
		})
	}
}

type blockedConnection struct {
	started chan struct{}
	closed  chan struct{}
	once    sync.Once
}

func (conn *blockedConnection) Write([]byte) (int, error) {
	close(conn.started)
	<-conn.closed
	return 0, net.ErrClosed
}
func (conn *blockedConnection) SetWriteDeadline(time.Time) error { return nil }
func (conn *blockedConnection) Close() error {
	conn.once.Do(func() { close(conn.closed) })
	return nil
}

func TestSyntheticBlockedWriterClosesOnCancellationAndBudget(t *testing.T) {
	for _, cancelCaller := range []bool{true, false} {
		t.Run(map[bool]string{true: "caller-cancel", false: "one-second-budget"}[cancelCaller], func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			conn := &blockedConnection{started: make(chan struct{}), closed: make(chan struct{})}
			connect := func(context.Context, localPath) (connection, error) { return conn, nil }
			done := make(chan result, 1)
			start := time.Now()
			go func() {
				report, err := send(ctx, fictionalSite(), fictionalTarget(), fictionalInterface, connect)
				done <- result{report, err}
			}()
			select {
			case <-conn.started:
			case <-time.After(time.Second):
				t.Fatal("synthetic writer did not start")
			}
			want := context.DeadlineExceeded
			if cancelCaller {
				cancel()
				want = context.Canceled
			}
			got := await(t, done)
			if !errors.Is(got.err, want) || got.report.Attempts != [3]AttemptOutcome{UnknownWrite, NotAttempted, NotAttempted} {
				t.Fatalf("report=%+v err=%v", got.report, got.err)
			}
			if elapsed := time.Since(start); elapsed > 1500*time.Millisecond {
				t.Fatalf("synthetic cancellation took %v", elapsed)
			}
			select {
			case <-conn.closed:
			default:
				t.Fatal("sender returned before synthetic connection closed")
			}
		})
	}
}
