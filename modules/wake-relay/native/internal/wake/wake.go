// Package wake sends bounded magic packets for a caller-approved local target.
// Its inputs are configuration, not authorization.
package wake

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strings"
	"time"
)

type Site struct {
	ID            string
	InterfaceName string
	SourceIPv4    string
	SubnetIPv4    string
}

type Target struct {
	SiteID string
	MAC    string
}

type AttemptOutcome uint8

const (
	NotAttempted AttemptOutcome = iota
	LocalKernelAccepted
	UnknownWrite
)

type Report struct {
	Attempts [3]AttemptOutcome
}

type localPath struct {
	name        string
	source      netip.Addr
	subnet      netip.Prefix
	destination netip.AddrPort
	packet      [102]byte
}

type interfaceState struct {
	index     int
	name      string
	flags     net.Flags
	addresses []netip.Prefix
}

type connection interface {
	Write([]byte) (int, error)
	SetWriteDeadline(time.Time) error
	Close() error
}

// Send submits at most three packets, with 100 ms gaps and a one-second budget.
// LocalKernelAccepted proves only that a complete write returned without error.
func Send(ctx context.Context, site Site, target Target) (Report, error) {
	return send(ctx, site, target, lookupInterface, dial)
}

func send(ctx context.Context, site Site, target Target, lookup func(string) (interfaceState, error), connect func(context.Context, localPath) (connection, error)) (report Report, err error) {
	if ctx == nil {
		return report, errors.New("wake requires a caller context")
	}
	deadline := time.Now().Add(time.Second)
	if earlier, ok := ctx.Deadline(); ok && earlier.Before(deadline) {
		deadline = earlier
	}
	ctx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	if err := contextError(ctx); err != nil {
		return report, err
	}
	path, err := parse(site, target)
	if err != nil {
		return report, err
	}
	initial, err := lookup(path.name)
	if cause := contextError(ctx); cause != nil {
		return report, cause
	}
	if err != nil {
		return report, fmt.Errorf("wake interface: %w", err)
	}
	if err := checkInterface(initial, path); err != nil {
		return report, err
	}
	if err := contextError(ctx); err != nil {
		return report, err
	}
	conn, err := connect(ctx, path)
	if err != nil {
		return report, fmt.Errorf("wake dial: %w", err)
	}
	closed := make(chan struct{})
	stop := context.AfterFunc(ctx, func() {
		conn.Close()
		close(closed)
	})
	defer func() {
		if !stop() {
			<-closed
		}
		conn.Close()
	}()
	if err := conn.SetWriteDeadline(deadline); err != nil {
		return report, fmt.Errorf("wake write deadline: %w", err)
	}
	for i := range report.Attempts {
		if err := contextError(ctx); err != nil {
			return report, err
		}
		current, err := lookup(path.name)
		if cause := contextError(ctx); cause != nil {
			return report, cause
		}
		if err != nil {
			return report, fmt.Errorf("wake interface: %w", err)
		}
		if err := checkInterface(current, path); err != nil {
			return report, err
		}
		if current.index != initial.index || current.name != initial.name || current.flags != initial.flags {
			return report, errors.New("wake interface changed")
		}
		if err := contextError(ctx); err != nil {
			return report, err
		}
		n, err := conn.Write(path.packet[:])
		if err != nil || n != len(path.packet) {
			report.Attempts[i] = UnknownWrite
			if cause := contextError(ctx); cause != nil {
				return report, cause
			}
			if err == nil {
				err = io.ErrShortWrite
			}
			return report, fmt.Errorf("wake write: %w", err)
		}
		report.Attempts[i] = LocalKernelAccepted
		if i < len(report.Attempts)-1 {
			timer := time.NewTimer(100 * time.Millisecond)
			select {
			case <-ctx.Done():
				timer.Stop()
				return report, contextError(ctx)
			case <-timer.C:
			}
		}
	}
	return report, nil
}

func contextError(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if deadline, ok := ctx.Deadline(); ok && !time.Now().Before(deadline) {
		return context.DeadlineExceeded
	}
	return nil
}

func parse(site Site, target Target) (localPath, error) {
	var path localPath
	if site.ID == "" || len(site.ID) > 128 || strings.TrimSpace(site.ID) != site.ID || site.ID != target.SiteID {
		return path, errors.New("wake site identity is invalid")
	}
	if site.InterfaceName == "" || len(site.InterfaceName) > 255 || strings.TrimSpace(site.InterfaceName) != site.InterfaceName || strings.ContainsRune(site.InterfaceName, 0) {
		return path, errors.New("wake requires an exact interface name")
	}
	if len(site.SourceIPv4) > 15 || len(site.SubnetIPv4) > 18 {
		return path, errors.New("wake IPv4 configuration exceeds its bound")
	}
	source, err := netip.ParseAddr(site.SourceIPv4)
	if err != nil || !source.Is4() {
		return path, errors.New("wake source must be literal IPv4")
	}
	subnet, err := netip.ParsePrefix(site.SubnetIPv4)
	if err != nil || !subnet.Addr().Is4() || subnet != subnet.Masked() || subnet.String() != site.SubnetIPv4 || subnet.Bits() > 30 {
		return path, errors.New("wake subnet must be canonical and host capable")
	}
	private := false
	for _, block := range [...]string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"} {
		allowed := netip.MustParsePrefix(block)
		if subnet.Bits() >= allowed.Bits() && allowed.Contains(subnet.Addr()) {
			private = true
		}
	}
	if !private || !subnet.Contains(source) {
		return path, errors.New("wake source and subnet must share one private IPv4 block")
	}
	network := subnet.Addr().As4()
	broadcast := network
	binary.BigEndian.PutUint32(broadcast[:], binary.BigEndian.Uint32(network[:])|(^uint32(0)>>subnet.Bits()))
	destination := netip.AddrFrom4(broadcast)
	if source == subnet.Addr() || source == destination {
		return path, errors.New("wake source must be a subnet host")
	}
	if len(target.MAC) != 17 {
		return path, errors.New("wake MAC must contain six colon-separated hex octets")
	}
	for _, position := range [...]int{2, 5, 8, 11, 14} {
		if target.MAC[position] != ':' {
			return path, errors.New("wake MAC must contain six colon-separated hex octets")
		}
	}
	mac, err := hex.DecodeString(strings.ReplaceAll(target.MAC, ":", ""))
	if err != nil || len(mac) != 6 || mac[0]&1 != 0 || string(mac) == "\x00\x00\x00\x00\x00\x00" {
		return path, errors.New("wake MAC must be nonzero unicast")
	}
	path = localPath{name: site.InterfaceName, source: source, subnet: subnet, destination: netip.AddrPortFrom(destination, 9)}
	for i := 0; i < 6; i++ {
		path.packet[i] = 0xff
	}
	for i := 6; i < len(path.packet); i += 6 {
		copy(path.packet[i:i+6], mac)
	}
	return path, nil
}

func checkInterface(state interfaceState, path localPath) error {
	if state.index <= 0 || state.name != path.name || state.flags&(net.FlagUp|net.FlagBroadcast) != net.FlagUp|net.FlagBroadcast || state.flags&(net.FlagLoopback|net.FlagPointToPoint) != 0 {
		return errors.New("wake interface is not an active broadcast interface")
	}
	for _, address := range state.addresses {
		if address.Addr() == path.source && address.Bits() == path.subnet.Bits() {
			return nil
		}
	}
	return errors.New("wake source and prefix are absent from selected interface")
}

func lookupInterface(name string) (interfaceState, error) {
	iface, err := net.InterfaceByName(name)
	if err != nil {
		return interfaceState{}, err
	}
	addresses, err := iface.Addrs()
	if err != nil {
		return interfaceState{}, err
	}
	state := interfaceState{index: iface.Index, name: iface.Name, flags: iface.Flags}
	for _, address := range addresses {
		if prefix, err := netip.ParsePrefix(address.String()); err == nil {
			state.addresses = append(state.addresses, prefix)
		}
	}
	return state, nil
}

func dial(ctx context.Context, path localPath) (connection, error) {
	dialer := net.Dialer{LocalAddr: &net.UDPAddr{IP: net.IP(path.source.AsSlice())}}
	return dialer.DialContext(ctx, "udp4", path.destination.String())
}
