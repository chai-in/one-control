package packages

import (
	"bytes"
	"compress/flate"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"hash/crc32"
	"io"
	"strings"

	"onecontrol/native/internal/contracts"
)

type packageFile struct {
	name string
	data []byte
}

func portablePath(name string) bool {
	if len(name) == 0 || len(name) > 240 {
		return false
	}
	parts := strings.Split(name, "/")
	if len(parts) > 8 {
		return false
	}
	for _, part := range parts {
		if part == "" || part == "." || part == ".." || strings.HasSuffix(part, ".") || strings.HasSuffix(part, " ") {
			return false
		}
		for _, c := range []byte(part) {
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '.' || c == '_' || c == '-') {
				return false
			}
		}
		base := strings.ToUpper(strings.SplitN(part, ".", 2)[0])
		if base == "CON" || base == "PRN" || base == "AUX" || base == "NUL" || base == "CLOCK$" || base == "CONIN$" || base == "CONOUT$" {
			return false
		}
		if len(base) == 4 && (strings.HasPrefix(base, "COM") || strings.HasPrefix(base, "LPT")) && base[3] >= '0' && base[3] <= '9' {
			return false
		}
	}
	return true
}
func inventory(p contracts.PackageAttestation, l Limits) error {
	if len(p.Files) < 1 || len(p.Files) > l.Entries {
		return errors.New("inventory_limit")
	}
	seen := map[string]bool{}
	prefixes := map[string]string{}
	var total int64
	host := false
	for _, f := range p.Files {
		if !portablePath(f.Path) || f.Size < 1 || f.Size > l.FileBytes {
			return errors.New("invalid_inventory")
		}
		lower := strings.ToLower(f.Path)
		if seen[lower] {
			return errors.New("path_collision")
		}
		seen[lower] = true
		parts := strings.Split(f.Path, "/")
		for i := 1; i <= len(parts); i++ {
			prefix := strings.Join(parts[:i], "/")
			folded := strings.ToLower(prefix)
			if previous, ok := prefixes[folded]; ok && previous != prefix {
				return errors.New("path_collision")
			}
			prefixes[folded] = prefix
		}
		total += f.Size
		if total > l.InflatedBytes {
			return errors.New("inflation_limit")
		}
		switch p.Layout {
		case "passive-v1":
			if !strings.HasPrefix(f.Path, "data/") {
				return errors.New("invalid_layout")
			}
		case "native-host-v1":
			target := "bin/host"
			if strings.HasPrefix(p.Platform, "win-") {
				target += ".exe"
			}
			if f.Path == target {
				host = true
			} else if !strings.HasPrefix(f.Path, "data/") {
				return errors.New("invalid_layout")
			}
		default:
			return errors.New("invalid_layout")
		}
	}
	for name := range seen {
		parts := strings.Split(name, "/")
		for i := 1; i < len(parts); i++ {
			if seen[strings.Join(parts[:i], "/")] {
				return errors.New("path_collision")
			}
		}
	}
	if p.Layout == "native-host-v1" && !host {
		return errors.New("invalid_layout")
	}
	return nil
}
func u16(b []byte, i int) uint16 { return binary.LittleEndian.Uint16(b[i : i+2]) }
func u32(b []byte, i int) uint32 { return binary.LittleEndian.Uint32(b[i : i+4]) }
func validateZIP(b []byte, p contracts.PackageAttestation, l Limits) ([]packageFile, error) {
	fail := func() ([]packageFile, error) { return nil, errors.New("invalid_zip") }
	if len(b) < 22 || int64(len(b)) > l.ArchiveBytes {
		return fail()
	}
	end := len(b) - 22
	if u32(b, end) != 0x06054b50 || u16(b, end+4) != 0 || u16(b, end+6) != 0 || u16(b, end+8) != u16(b, end+10) || u16(b, end+20) != 0 {
		return fail()
	}
	count := int(u16(b, end+10))
	central := int(u32(b, end+16))
	size := int(u32(b, end+12))
	if count < 1 || count > l.Entries || count != len(p.Files) || central < 0 || size < 0 || uint64(central)+uint64(size) != uint64(end) {
		return fail()
	}
	expected := map[string]contracts.PackageFile{}
	for _, f := range p.Files {
		expected[f.Path] = f
	}
	files := make([]packageFile, 0, count)
	at := central
	nextLocal := 0
	var total int64
	for i := 0; i < count; i++ {
		if at > end-46 || u32(b, at) != 0x02014b50 {
			return fail()
		}
		// This product subset has no descriptors, extras, comments, attributes, or ZIP64.
		if u16(b, at+4) != 20 || u16(b, at+6) != 20 || u16(b, at+8) != 0 || u16(b, at+30) != 0 || u16(b, at+32) != 0 || u16(b, at+34) != 0 || u16(b, at+36) != 0 || u32(b, at+38) != 0 {
			return fail()
		}
		method := u16(b, at+10)
		if method != 0 && method != 8 {
			return fail()
		}
		compressed := int64(u32(b, at+20))
		expanded := int64(u32(b, at+24))
		nameLen := int(u16(b, at+28))
		local := int(u32(b, at+42))
		if nameLen < 1 || at+46+nameLen > end || local != nextLocal || local > central-30 || compressed < 1 || expanded < 1 || expanded > l.FileBytes || expanded > compressed*100 {
			return fail()
		}
		name := string(b[at+46 : at+46+nameLen])
		f, ok := expected[name]
		if !ok || expanded != f.Size {
			return fail()
		}
		delete(expected, name)
		if u32(b, local) != 0x04034b50 || !bytes.Equal(b[local+4:local+26], b[at+6:at+28]) || u16(b, local+26) != uint16(nameLen) || u16(b, local+28) != 0 {
			return fail()
		}
		start := local + 30 + nameLen
		finish := int64(start) + compressed
		if start > central || finish > int64(central) || !bytes.Equal(b[local+30:start], []byte(name)) {
			return fail()
		}
		data := b[start:int(finish)]
		var inflated []byte
		if method == 0 {
			if compressed != expanded {
				return fail()
			}
			inflated = append([]byte(nil), data...)
		} else {
			source := bytes.NewReader(data)
			r := flate.NewReader(source)
			var err error
			inflated, err = io.ReadAll(io.LimitReader(r, expanded+1))
			closeErr := r.Close()
			if err != nil || closeErr != nil || source.Len() != 0 {
				return fail()
			}
		}
		total += int64(len(inflated))
		if int64(len(inflated)) != expanded || total > l.InflatedBytes || crc32.ChecksumIEEE(inflated) != u32(b, at+16) {
			return fail()
		}
		digest := sha256.Sum256(inflated)
		if hex.EncodeToString(digest[:]) != f.SHA256 {
			return nil, errors.New("file_hash")
		}
		files = append(files, packageFile{name, inflated})
		nextLocal = int(finish)
		at += 46 + nameLen
	}
	if at != end || nextLocal != central || len(expected) != 0 {
		return fail()
	}
	return files, nil
}
