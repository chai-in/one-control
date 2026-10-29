package contracts

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"
)

var ErrWire = errors.New("invalid_wire")

type specification struct {
	Types     map[string]map[string]string `json:"types"`
	Patterns  map[string]string            `json:"patterns"`
	Domains   []string                     `json:"domains"`
	Platforms []string                     `json:"platforms"`
}

var spec specification

func init() {
	if err := json.Unmarshal([]byte(SchemaJSON), &spec); err != nil {
		panic(err)
	}
}

// Decode rejects malformed Unicode, duplicate members, unknown fields and
// noncanonical integer spellings before unmarshalling generated wire types.
// Orders retains JSON member order for the existing installed-graph oracle.
func Decode(data []byte, model string, out any) (map[string][]string, error) {
	if len(data) > 6291456 || !utf8.Valid(data) {
		return nil, ErrWire
	}
	// encoding/json replaces unpaired UTF-16 surrogate escapes. Reject them before
	// that replacement can make distinct signed identities compare equal.
	if !validEscapes(data) {
		return nil, ErrWire
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	orders := map[string][]string{}
	value, err := readValue(dec, "", orders, 0)
	if err != nil {
		return nil, ErrWire
	}
	if _, err = dec.Token(); err != io.EOF {
		return nil, ErrWire
	}
	if err = validate(model, value, ""); err != nil {
		return nil, fmt.Errorf("%w: %s", ErrWire, err)
	}
	if err = json.Unmarshal(data, out); err != nil {
		return nil, ErrWire
	}
	return orders, nil
}
func readValue(d *json.Decoder, path string, orders map[string][]string, depth int) (any, error) {
	if depth > 64 {
		return nil, ErrWire
	}
	t, err := d.Token()
	if err != nil {
		return nil, err
	}
	delim, ok := t.(json.Delim)
	if !ok {
		return t, nil
	}
	switch delim {
	case '{':
		obj := map[string]any{}
		for d.More() {
			keyToken, e := d.Token()
			if e != nil {
				return nil, e
			}
			key, ok := keyToken.(string)
			if !ok {
				return nil, ErrWire
			}
			if _, exists := obj[key]; exists {
				return nil, ErrWire
			}
			orders[path] = append(orders[path], key)
			value, e := readValue(d, path+"/"+key, orders, depth+1)
			if e != nil {
				return nil, e
			}
			obj[key] = value
		}
		if t, e := d.Token(); e != nil || t != json.Delim('}') {
			return nil, ErrWire
		}
		return obj, nil
	case '[':
		arr := []any{}
		for d.More() {
			v, e := readValue(d, fmt.Sprintf("%s/%d", path, len(arr)), orders, depth+1)
			if e != nil {
				return nil, e
			}
			arr = append(arr, v)
		}
		if t, e := d.Token(); e != nil || t != json.Delim(']') {
			return nil, ErrWire
		}
		return arr, nil
	}
	return nil, ErrWire
}
func validEscapes(data []byte) bool {
	for i := 0; i < len(data); i++ {
		if data[i] != '\\' {
			continue
		}
		i++
		if i >= len(data) {
			return false
		}
		if data[i] != 'u' {
			continue
		}
		if i+4 >= len(data) {
			return false
		}
		n, e := strconv.ParseUint(string(data[i+1:i+5]), 16, 16)
		if e != nil {
			return false
		}
		i += 4
		if n >= 0xdc00 && n <= 0xdfff {
			return false
		}
		if n >= 0xd800 && n <= 0xdbff {
			if i+6 >= len(data) || data[i+1] != '\\' || data[i+2] != 'u' {
				return false
			}
			low, e := strconv.ParseUint(string(data[i+3:i+7]), 16, 16)
			if e != nil || low < 0xdc00 || low > 0xdfff {
				return false
			}
			i += 6
		}
	}
	return true
}
func has(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}
func validate(kind string, v any, path string) error {
	fail := func() error { return fmt.Errorf("%s (%s)", path, kind) }
	if fields, ok := spec.Types[kind]; ok {
		obj, ok := v.(map[string]any)
		if !ok {
			return fail()
		}
		for key := range obj {
			if _, ok := fields[key]; !ok {
				if _, ok = fields[key+"?"]; !ok {
					return fail()
				}
			}
		}
		for raw, k := range fields {
			key := strings.TrimSuffix(raw, "?")
			value, exists := obj[key]
			if !exists {
				if !strings.HasSuffix(raw, "?") {
					return fail()
				}
				continue
			}
			if e := validate(k, value, path+"/"+key); e != nil {
				return e
			}
		}
		if kind == "Scope" {
			user := obj["kind"] == "user"
			for _, key := range []string{"principal", "sessionId", "sessionIncarnation", "localNonce"} {
				_, exists := obj[key]
				if user != exists {
					return fail()
				}
			}
		}
		if kind == "Manifest" {
			if len(obj["permissions"].([]any)) > 32 {
				return fail()
			}
			seen := map[string]bool{}
			for _, p := range obj["permissions"].([]any) {
				s := p.(string)
				if seen[s] {
					return fail()
				}
				seen[s] = true
			}
		}
		return nil
	}
	if strings.HasPrefix(kind, "array:") {
		arr, ok := v.([]any)
		if !ok {
			return fail()
		}
		max := 512
		if strings.HasSuffix(path, "/permissions") {
			max = 32
		}
		if len(arr) > max {
			return fail()
		}
		for i, item := range arr {
			if e := validate(kind[6:], item, fmt.Sprintf("%s/%d", path, i)); e != nil {
				return e
			}
		}
		return nil
	}
	if strings.HasPrefix(kind, "map:") || strings.HasPrefix(kind, "platformmap:") {
		obj, ok := v.(map[string]any)
		if !ok {
			return fail()
		}
		if strings.HasSuffix(path, "/dependencies") && len(obj) > 32 {
			return fail()
		}
		if len(obj) > 512 {
			return fail()
		}
		inner := kind[strings.IndexByte(kind, ':')+1:]
		for key, item := range obj {
			if strings.HasPrefix(kind, "platformmap:") {
				if !has(spec.Platforms, key) {
					return fail()
				}
			} else if e := validate("id", key, path); e != nil {
				return e
			}
			if e := validate(inner, item, path+"/"+key); e != nil {
				return e
			}
		}
		return nil
	}
	if kind == "boolean" {
		if _, ok := v.(bool); !ok {
			return fail()
		}
		return nil
	}
	if kind == "timestamp" || kind == "size" || kind == "literal:1" || kind == "literal:2" {
		num, ok := v.(json.Number)
		if !ok {
			return fail()
		}
		s := num.String()
		n, e := strconv.ParseInt(s, 10, 64)
		if e != nil || strconv.FormatInt(n, 10) != s {
			return fail()
		}
		if strings.HasPrefix(kind, "literal:") && strconv.FormatInt(n, 10) != kind[8:] {
			return fail()
		}
		if kind == "timestamp" && (n < 1 || n > 9007199254740991) {
			return fail()
		}
		if kind == "size" && (n < 1 || n > 2147483648) {
			return fail()
		}
		return nil
	}
	s, ok := v.(string)
	if !ok {
		return fail()
	}
	if len(s) > 6291456 {
		return fail()
	}
	if kind == "string" {
		return nil
	}
	if strings.HasPrefix(kind, "literal:") {
		if s != kind[8:] {
			return fail()
		}
		return nil
	}
	if strings.HasPrefix(kind, "enum:") {
		if !has(strings.Split(kind[5:], ","), s) {
			return fail()
		}
		return nil
	}
	switch kind {
	case "platform":
		if !has(spec.Platforms, s) {
			return fail()
		}
	case "domain":
		if !has(spec.Domains, s) {
			return fail()
		}
	case "identity":
		if len(s) < 1 || len(s) > 256 || strings.ContainsAny(s, "\x00\r\n") {
			return fail()
		}
	case "https":
		if !validArtifactURL(s) {
			return fail()
		}
	default:
		p, ok := spec.Patterns[kind]
		if !ok || !regexp.MustCompile(p).MatchString(s) {
			return fail()
		}
		if kind == "id" && len(s) > 96 {
			return fail()
		}
		if kind == "decimal" {
			if _, e := strconv.ParseUint(s, 10, 64); e != nil {
				return fail()
			}
		}
		if kind == "nonce" {
			b, e := base64.RawURLEncoding.Strict().DecodeString(s)
			if e != nil || len(b) != 32 || base64.RawURLEncoding.EncodeToString(b) != s {
				return fail()
			}
		}
	}
	return nil
}

var artifactURL = regexp.MustCompile(`(?i)^https://(\[[0-9a-f:.]+\]|[a-z0-9.-]+)(?::([0-9]{1,5}))?(/[a-z0-9._~!$&'()*+,;=:@%/-]*)?(\?[a-z0-9._~!$&'()*+,;=:@%/?-]*)?$`)
var dnsLabel = regexp.MustCompile(`(?i)^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)
var ipv4Ending = regexp.MustCompile(`(?i)^(?:[0-9]+|0x[0-9a-f]*)$`)
var ipv4Part = regexp.MustCompile(`^(?:0|[1-9][0-9]{0,2})$`)

func validArtifactURL(value string) bool {
	for i := 0; i < len(value); i++ {
		if value[i] > 127 {
			return false
		}
	}
	parts := artifactURL.FindStringSubmatch(value)
	if parts == nil {
		return false
	}
	for i := 0; i < len(value); i++ {
		if value[i] == '%' {
			if i+2 >= len(value) {
				return false
			}
			if _, err := strconv.ParseUint(value[i+1:i+3], 16, 8); err != nil {
				return false
			}
			i += 2
		}
	}
	if parts[2] != "" {
		_, err := strconv.ParseUint(parts[2], 10, 16)
		if err != nil {
			return false
		}
	}
	host := parts[1]
	if strings.HasPrefix(host, "[") {
		ip, err := netip.ParseAddr(host[1 : len(host)-1])
		return err == nil && ip.Is6()
	}
	dns := strings.TrimSuffix(host, ".")
	labels := strings.Split(dns, ".")
	if len(dns) > 253 {
		return false
	}
	for _, label := range labels {
		if !dnsLabel.MatchString(label) {
			return false
		}
	}
	if ipv4Ending.MatchString(labels[len(labels)-1]) {
		if dns != host || len(labels) != 4 {
			return false
		}
		for _, label := range labels {
			if !ipv4Part.MatchString(label) {
				return false
			}
			n, _ := strconv.Atoi(label)
			if n > 255 {
				return false
			}
		}
	}
	return true
}
