package main

import (
	"encoding/json"
	"onecontrol/native/internal/processhost"
	"os"
	"path/filepath"
)

func main() {
	if len(os.Args) != 3 || os.Args[1] != "--one-control-host-v1" {
		os.Exit(2)
	}
	instance := os.Args[2]
	exe, err := os.Executable()
	if err != nil {
		os.Exit(3)
	}
	observer, err := os.ReadFile(filepath.Join(filepath.Dir(exe), "..", "data", "observer"))
	if err != nil {
		os.Exit(3)
	}
	write := func(state string) {
		b, _ := json.Marshal(map[string]any{"pid": os.Getpid(), "state": state})
		if os.WriteFile(filepath.Join(string(observer), instance+".json"), b, 0600) != nil {
			os.Exit(3)
		}
	}
	write("ready")
	if processhost.WriteMessage(os.Stdout, processhost.Message{Version: 1, Type: "ready", Instance: instance}) != nil {
		os.Exit(3)
	}
	active := false
	for {
		m, e := processhost.ReadMessage(os.Stdin)
		if e != nil {
			select {}
		}
		if m.Instance != instance {
			os.Exit(3)
		}
		reply := ""
		switch m.Type {
		case "activate":
			active = true
			reply = "active"
		case "health":
			if !active {
				os.Exit(3)
			}
			reply = "healthy"
		case "stop":
			reply = "stopped"
		default:
			os.Exit(3)
		}
		write(reply)
		if processhost.WriteMessage(os.Stdout, processhost.Message{Version: 1, Type: reply, Instance: instance, Sequence: m.Sequence}) != nil {
			os.Exit(3)
		}
		if reply == "stopped" {
			return
		}
	}
}
