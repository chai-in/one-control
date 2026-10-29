package main

import (
	"context"
	"encoding/json"
	"errors"
	"onecontrol/native/internal/featurehost"
	"onecontrol/native/modules/inventory/internal/inventory"
	"os"
)

func main() {
	if len(os.Args) != 3 || os.Args[1] != "--one-control-host-v1" {
		os.Exit(2)
	}
	err := featurehost.Serve(os.Stdin, os.Stdout, os.Args[2], func(ctx context.Context, operation string, payload []byte) ([]byte, error) {
		if operation != "inventory.scan" || len(payload) != 0 {
			return nil, errors.New("unsupported inventory operation")
		}
		report, err := inventory.Collect(ctx)
		if err != nil {
			return nil, err
		}
		return json.Marshal(report)
	})
	if err != nil {
		os.Exit(1)
	}
}
