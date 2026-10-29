// Package featurehost serves inherited-pipe requests for optional feature
// executables. It owns no enrollment credential or control-plane connection.
package featurehost

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
	"onecontrol/native/internal/processhost"
	"strings"
	"time"
)

type Handler func(context.Context, string, []byte) ([]byte, error)

func Serve(input io.Reader, output io.Writer, instance string, handle Handler) error {
	nonce, err := hex.DecodeString(instance)
	if err != nil || len(nonce) != 32 || hex.EncodeToString(nonce) != instance {
		return errors.New("invalid host instance")
	}
	if err = processhost.WriteMessage(output, processhost.Message{Version: 1, Type: "ready", Instance: instance}); err != nil {
		return err
	}
	active := false
	var sequence uint64
	for {
		request, err := processhost.ReadMessage(input)
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		if sequence == ^uint64(0) || request.Sequence != sequence+1 || request.Instance != instance {
			return errors.New("invalid host request sequence")
		}
		sequence = request.Sequence
		response := processhost.Message{Version: 1, Instance: instance, Sequence: sequence}
		switch request.Type {
		case "activate":
			if active || request.Payload != "" {
				return errors.New("invalid activation")
			}
			active = true
			response.Type = "active"
		case "health":
			if !active || request.Payload != "" {
				return errors.New("inactive host")
			}
			response.Type = "healthy"
		case "stop":
			if request.Payload != "" {
				return errors.New("invalid stop")
			}
			response.Type = "stopped"
			return processhost.WriteMessage(output, response)
		default:
			if !active || !strings.HasPrefix(request.Type, "request:") {
				return errors.New("unsupported host request")
			}
			operation := strings.TrimPrefix(request.Type, "request:")
			payload, err := base64.RawURLEncoding.Strict().DecodeString(request.Payload)
			if err != nil || len(payload) > processhost.MaxPayload || base64.RawURLEncoding.EncodeToString(payload) != request.Payload {
				return errors.New("invalid feature payload")
			}
			ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
			result, err := handle(ctx, operation, payload)
			cancel()
			if err != nil {
				return err
			}
			if len(result) > processhost.MaxPayload {
				return errors.New("feature response too large")
			}
			response.Type = "result:" + operation
			response.Payload = base64.RawURLEncoding.EncodeToString(result)
		}
		if err = processhost.WriteMessage(output, response); err != nil {
			return err
		}
	}
}
