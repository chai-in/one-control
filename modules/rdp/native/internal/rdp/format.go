// Package rdp formats target metadata for an installed RDP client.
// Successful formatting does not authorize a target or a session.
package rdp

import (
	"errors"
	"net/netip"
	"strconv"
	"strings"
)

// Descriptor is untrusted target input. Port is validated before narrowing.
type Descriptor struct {
	Host string
	Port int
}

// ManualTarget contains validated metadata for manual client setup.
type ManualTarget struct {
	Host string
	Port uint16
}

// ErrInvalidDescriptor reports rejected input without including target data.
var ErrInvalidDescriptor = errors.New("invalid RDP descriptor")

// FormatWindowsFile returns four fixed CRLF-terminated .rdp properties.
// It neither writes a file nor starts a client.
func FormatWindowsFile(descriptor Descriptor) ([]byte, error) {
	target, err := validate(descriptor)
	if err != nil {
		return nil, err
	}
	return []byte("full address:s:" + target.Host + ":" + strconv.Itoa(int(target.Port)) + "\r\n" +
		"authentication level:i:1\r\n" +
		"enablecredsspsupport:i:1\r\n" +
		"redirectclipboard:i:0\r\n"), nil
}

// FormatManualTarget returns host and port for manual setup, including macOS.
// It makes no URI, file-import, client-security, or connectivity guarantee.
func FormatManualTarget(descriptor Descriptor) (ManualTarget, error) {
	return validate(descriptor)
}

func validate(descriptor Descriptor) (ManualTarget, error) {
	host := descriptor.Host
	if descriptor.Port < 1 || descriptor.Port > 65535 || len(host) == 0 || len(host) > 253 {
		return ManualTarget{}, ErrInvalidDescriptor
	}
	if address, err := netip.ParseAddr(host); err == nil {
		if !address.Is4() || address.String() != host {
			return ManualTarget{}, ErrInvalidDescriptor
		}
		return ManualTarget{Host: host, Port: uint16(descriptor.Port)}, nil
	}
	labels := strings.Split(host, ".")
	for _, label := range labels {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return ManualTarget{}, ErrInvalidDescriptor
		}
		for i := range len(label) {
			c := label[i]
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-') {
				return ManualTarget{}, ErrInvalidDescriptor
			}
		}
	}
	// Numeric final labels can be interpreted as alternative IPv4 spellings.
	last := labels[len(labels)-1][0]
	if !(last >= 'a' && last <= 'z' || last >= 'A' && last <= 'Z') {
		return ManualTarget{}, ErrInvalidDescriptor
	}
	return ManualTarget{Host: strings.ToLower(host), Port: uint16(descriptor.Port)}, nil
}
