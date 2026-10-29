package processhost

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
)

const MaxFrame = 16384
const MaxPayload = 8192

type Message struct {
	Version  int    `json:"version"`
	Type     string `json:"type"`
	Instance string `json:"instance"`
	Sequence uint64 `json:"sequence"`
	Payload  string `json:"payload,omitempty"`
}

func WriteMessage(w io.Writer, m Message) error {
	b, err := json.Marshal(m)
	if err != nil {
		return err
	}
	if len(b) == 0 || len(b) > MaxFrame {
		return errors.New("invalid host frame length")
	}
	frame := binary.BigEndian.AppendUint32(nil, uint32(len(b)))
	frame = append(frame, b...)
	for len(frame) > 0 {
		n, err := w.Write(frame)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		frame = frame[n:]
	}
	return nil
}

func ReadMessage(r io.Reader) (Message, error) {
	var m Message
	var size [4]byte
	if _, err := io.ReadFull(r, size[:]); err != nil {
		return m, err
	}
	n := binary.BigEndian.Uint32(size[:])
	if n == 0 || n > MaxFrame {
		return m, errors.New("invalid host frame length")
	}
	b := make([]byte, n)
	if _, err := io.ReadFull(r, b); err != nil {
		return m, err
	}
	if err := json.Unmarshal(b, &m); err != nil {
		return m, err
	}
	canonical, err := json.Marshal(m)
	if err != nil || !bytes.Equal(b, canonical) || m.Version != 1 || m.Type == "" || m.Instance == "" {
		return Message{}, errors.New("invalid canonical host message")
	}
	return m, nil
}
