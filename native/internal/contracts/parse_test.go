package contracts

import (
	"strings"
	"testing"
)

func TestStrictWireParsing(t *testing.T) {
	valid := `{"schemaVersion":1,"domain":"device-policy.v1","alg":"PS256","rootVersion":"1","keyId":"policy"}`
	for name, raw := range map[string][]byte{
		"duplicate":          []byte(strings.Replace(valid, `"keyId":"policy"`, `"keyId":"policy","keyId":"policy"`, 1)),
		"unknown":            []byte(strings.Replace(valid, `"keyId":"policy"`, `"keyId":"policy","command":"bad"`, 1)),
		"fraction":           []byte(strings.Replace(valid, `"schemaVersion":1`, `"schemaVersion":1.0`, 1)),
		"exponent":           []byte(strings.Replace(valid, `"schemaVersion":1`, `"schemaVersion":1e0`, 1)),
		"overflow":           []byte(strings.Replace(valid, `"rootVersion":"1"`, `"rootVersion":"18446744073709551616"`, 1)),
		"leading zero":       []byte(strings.Replace(valid, `"rootVersion":"1"`, `"rootVersion":"01"`, 1)),
		"invalid UTF8":       append([]byte(valid), 0xff),
		"unpaired surrogate": []byte(strings.Replace(valid, `"keyId":"policy"`, `"keyId":"\ud800"`, 1)),
		"null":               []byte(strings.Replace(valid, `"keyId":"policy"`, `"keyId":null`, 1)),
		"second document":    []byte(valid + `{}`),
	} {
		t.Run(name, func(t *testing.T) {
			var out Protected
			if _, e := Decode(raw, "Protected", &out); e == nil {
				t.Fatal("accepted malformed signed wire")
			}
		})
	}
	var out Protected
	if _, e := Decode([]byte(valid), "Protected", &out); e != nil {
		t.Fatal(e)
	}
}
