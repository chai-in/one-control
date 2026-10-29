package processhost

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestBoundedCanonicalFrames(t *testing.T) {
	m := Message{Version: 1, Type: "ready", Instance: "instance"}
	var b bytes.Buffer
	if err := WriteMessage(&b, m); err != nil {
		t.Fatal(err)
	}
	if got, err := ReadMessage(&b); err != nil || got != m {
		t.Fatalf("round trip %v %v", got, err)
	}
	for _, body := range []string{`{"version":1,"type":"ready","instance":"x","sequence":0,"extra":true}`, `{"version":1,"type":"ready","type":"active","instance":"x","sequence":0}`, `{"version":2,"type":"ready","instance":"x","sequence":0}`, `{`, ``} {
		frame := binary.BigEndian.AppendUint32(nil, uint32(len(body)))
		frame = append(frame, body...)
		if _, err := ReadMessage(bytes.NewReader(frame)); err == nil {
			t.Fatalf("accepted %q", body)
		}
	}
	for _, n := range []uint32{MaxFrame + 1, ^uint32(0)} {
		if _, err := ReadMessage(bytes.NewReader(binary.BigEndian.AppendUint32(nil, n))); err == nil {
			t.Fatal("accepted oversized frame")
		}
	}
}
