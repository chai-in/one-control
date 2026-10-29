package rdp_test

import (
	"bytes"
	"strconv"
	"strings"
	"testing"

	"onecontrol/native/modules/rdp/internal/rdp"
)

func TestFormatTargets(t *testing.T) {
	maxHost := strings.Repeat("a", 63) + "." + strings.Repeat("b", 63) + "." + strings.Repeat("c", 63) + "." + strings.Repeat("d", 61)
	tests := []struct {
		name  string
		input rdp.Descriptor
		host  string
	}{
		{"hostname", rdp.Descriptor{Host: "office-pc.example.com", Port: 3389}, "office-pc.example.com"},
		{"case", rdp.Descriptor{Host: "OFFICE-PC.Example.COM", Port: 3390}, "office-pc.example.com"},
		{"IPv4", rdp.Descriptor{Host: "192.0.2.14", Port: 3389}, "192.0.2.14"},
		{"single label", rdp.Descriptor{Host: "PC7", Port: 1}, "pc7"},
		{"numeric nonfinal label", rdp.Descriptor{Host: "123.example", Port: 65535}, "123.example"},
		{"alphanumeric final label", rdp.Descriptor{Host: "pc.example7", Port: 3389}, "pc.example7"},
		{"label bound", rdp.Descriptor{Host: strings.Repeat("a", 63), Port: 3389}, strings.Repeat("a", 63)},
		{"host bound", rdp.Descriptor{Host: maxHost, Port: 3389}, maxHost},
		{"zero IPv4", rdp.Descriptor{Host: "0.0.0.0", Port: 3389}, "0.0.0.0"},
		{"upper IPv4", rdp.Descriptor{Host: "255.255.255.255", Port: 65535}, "255.255.255.255"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			manual, err := rdp.FormatManualTarget(tt.input)
			if err != nil || manual.Host != tt.host || int(manual.Port) != tt.input.Port {
				t.Fatalf("manual target = %#v, %v", manual, err)
			}
			file, err := rdp.FormatWindowsFile(tt.input)
			if err != nil {
				t.Fatal(err)
			}
			want := "full address:s:" + tt.host + ":" + strconv.Itoa(tt.input.Port) + "\r\n" +
				"authentication level:i:1\r\n" +
				"enablecredsspsupport:i:1\r\n" +
				"redirectclipboard:i:0\r\n"
			if string(file) != want {
				t.Fatalf("file = %q, want %q", file, want)
			}
		})
	}
}

func TestRejectDescriptors(t *testing.T) {
	hosts := []string{
		"", ".", "pc.", ".pc", "pc..example", "-pc.example", "pc-.example", "pc.ex-ample-",
		strings.Repeat("a", 64), strings.Repeat("a", 63) + "." + strings.Repeat("b", 63) + "." + strings.Repeat("c", 63) + "." + strings.Repeat("d", 62),
		" pc", "pc ", "pc\t", "pc\n", "pc\r", "pc\x00", "pc\x1b", "pc\x7f", "pc\u00a0", "p\u0430c", "münchen.example", "pc\u2028example",
		"pc\r\nauthentication level:i:0", "pc\nredirectclipboard:i:1", "pc:3389", "192.0.2.1:3389",
		"::1", "2001:db8::1", "[::1]", "fe80::1%eth0", "[fe80::1%25eth0]",
		"user@pc", "user:password@pc", "rdp://pc", "https://pc", "pc/path", "pc\\path", "pc?x=y", "pc#x", "pc%0d%0a",
		"pc /admin", "pc;calc", "pc&calc", "pc|calc", "$(calc)", "`calc`", "\"pc\"", "'pc'", "pc=setting", "pc,other", "pc_name",
		"127.1", "127.0.0.01", "0177.0.0.1", "0x7f000001", "2130706433", "256.0.0.1", "1.2.3.4.5", "pc.123", "pc.1example",
	}
	for _, host := range hosts {
		t.Run(strconv.Quote(host), func(t *testing.T) {
			assertRejected(t, rdp.Descriptor{Host: host, Port: 3389})
		})
	}
	for _, port := range []int{-1, 0, 65536, int(^uint(0) >> 1), -int(^uint(0)>>1) - 1} {
		t.Run("port "+strconv.Itoa(port), func(t *testing.T) {
			assertRejected(t, rdp.Descriptor{Host: "pc.example", Port: port})
		})
	}
	t.Run("zero value", func(t *testing.T) { assertRejected(t, rdp.Descriptor{}) })
}

func assertRejected(t *testing.T, input rdp.Descriptor) {
	t.Helper()
	file, err := rdp.FormatWindowsFile(input)
	if err != rdp.ErrInvalidDescriptor || file != nil {
		t.Fatalf("Windows rejection = %q, %v", file, err)
	}
	manual, err := rdp.FormatManualTarget(input)
	if err != rdp.ErrInvalidDescriptor || manual != (rdp.ManualTarget{}) {
		t.Fatalf("manual rejection = %#v, %v", manual, err)
	}
	if err.Error() != "invalid RDP descriptor" {
		t.Fatalf("error includes unexpected data: %q", err.Error())
	}
}

func TestIndependentOutputsAndRevalidation(t *testing.T) {
	input := rdp.Descriptor{Host: "PC.example", Port: 3389}
	first, err := rdp.FormatWindowsFile(input)
	if err != nil {
		t.Fatal(err)
	}
	second, err := rdp.FormatWindowsFile(input)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first, second) {
		t.Fatal("repeated formatting differs")
	}
	first[0] = '!'
	third, err := rdp.FormatWindowsFile(input)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(second, third) || second[0] != 'f' {
		t.Fatal("returned bytes share mutable state")
	}
	manual, err := rdp.FormatManualTarget(input)
	if err != nil {
		t.Fatal(err)
	}
	manual.Host = "changed.example"
	manual.Port = 1
	again, err := rdp.FormatManualTarget(input)
	if err != nil || again != (rdp.ManualTarget{Host: "pc.example", Port: 3389}) {
		t.Fatalf("manual result retained caller mutation: %#v, %v", again, err)
	}
	input.Host = "pc\r\nredirectclipboard:i:1"
	assertRejected(t, input)
	input = rdp.Descriptor{Host: "pc.example", Port: 65536}
	assertRejected(t, input)
}

func FuzzFormat(f *testing.F) {
	for _, host := range []string{"pc.example", "PC.Example", "192.0.2.1", "127.0.0.01", "pc\r\nauthentication level:i:0", "::1", "", strings.Repeat("a", 254)} {
		f.Add(host, int32(3389))
	}
	f.Add("pc", int32(0))
	f.Add("pc", int32(65536))
	f.Fuzz(func(t *testing.T, host string, port int32) {
		if len(host) > 512 {
			t.Skip()
		}
		input := rdp.Descriptor{Host: host, Port: int(port)}
		file, fileErr := rdp.FormatWindowsFile(input)
		manual, manualErr := rdp.FormatManualTarget(input)
		if fileErr != nil || manualErr != nil {
			assertRejected(t, input)
			return
		}
		if port < 1 || port > 65535 || manual.Host == "" || int32(manual.Port) != port {
			t.Fatal("accepted an invalid target or port")
		}
		for _, c := range manual.Host {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '.') {
				t.Fatal("accepted target delimiter or non-ASCII data")
			}
		}
		if manual.Host != strings.ToLower(host) {
			t.Fatal("formatter repaired input beyond case normalization")
		}
		lines := strings.Split(string(file), "\r\n")
		if len(lines) != 5 || lines[4] != "" || lines[0] != "full address:s:"+manual.Host+":"+strconv.Itoa(int(port)) ||
			lines[1] != "authentication level:i:1" || lines[2] != "enablecredsspsupport:i:1" || lines[3] != "redirectclipboard:i:0" {
			t.Fatalf("injected, omitted, or altered properties: %q", file)
		}
	})
}
