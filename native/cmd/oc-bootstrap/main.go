package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"onecontrol/native/internal/bootstrap"
	"onecontrol/native/internal/protectedstore"
	"onecontrol/native/internal/selection"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"time"
)

func main() {
	observe := flag.Duration("observe-for", 0, "Keep the empty process alive for external observation, at most 30s")
	configuration := flag.String("config", "", "Protected installation configuration file")
	invitation := flag.String("enroll", "", "Protected single-use invitation file; reconcile an existing submission without replay")
	run := flag.Bool("run", false, "Run the enrolled native bootstrap in the foreground")
	service := flag.Bool("service", false, "Run the enrolled native Windows service")
	identity := flag.Bool("identity", false, "Print the local machine identity and platform for invitation binding")
	status := flag.Bool("status", false, "Print the protected service status without credential material")
	prepare := flag.String("prepare-root", "", "Create an administrator and SYSTEM-only installation directory")
	flag.Parse()
	if flag.NArg() != 0 || *observe < 0 || *observe > 30*time.Second {
		fmt.Fprintln(os.Stderr, "invalid observation duration or arguments")
		os.Exit(2)
	}
	modeCount := 0
	for _, selected := range []bool{*invitation != "", *run, *service, *identity, *status, *prepare != ""} {
		if selected {
			modeCount++
		}
	}
	if modeCount > 1 || (modeCount > 0 && *observe != 0) || (modeCount == 0 && *configuration != "") {
		fmt.Fprintln(os.Stderr, "choose one bootstrap mode")
		os.Exit(2)
	}
	if *identity {
		machine, err := bootstrap.MachineID()
		if err != nil {
			fail(err)
		}
		if err = json.NewEncoder(os.Stdout).Encode(map[string]string{"machineId": machine, "platform": bootstrap.Platform(), "version": bootstrap.Version}); err != nil {
			fail(err)
		}
		return
	}
	if *prepare != "" {
		if err := protectedstore.Create(*prepare); err != nil {
			fail(err)
		}
		return
	}
	if modeCount > 0 {
		installation, err := bootstrap.Load(*configuration)
		if err != nil {
			fail(err)
		}
		ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
		defer cancel()
		switch {
		case *invitation != "":
			binding, e := installation.Enroll(ctx, *invitation)
			if e != nil {
				fail(e)
			}
			if e = json.NewEncoder(os.Stdout).Encode(binding); e != nil {
				fail(e)
			}
		case *run:
			if err = installation.Run(ctx, nil); err != nil {
				fail(err)
			}
		case *service:
			if err = installation.Service(); err != nil {
				fail(err)
			}
		case *status:
			raw, e := protectedstore.Read(filepath.Join(installation.Root, "status.json"), 16384)
			if e != nil {
				fail(e)
			}
			if _, e = os.Stdout.Write(append(raw, '\n')); e != nil {
				fail(e)
			}
		}
		return
	}
	platform := map[string]string{"windows": "win", "darwin": "osx", "linux": "linux"}[runtime.GOOS] + "-" + map[string]string{"amd64": "x64", "arm64": "arm64"}[runtime.GOARCH]
	input, _ := json.Marshal(map[string]any{"catalog": []any{}, "enabled": map[string]string{}, "platform": platform, "bootstrapVersion": "0.1.0", "allowedPermissions": []string{}})
	plan, e := selection.Resolve(input)
	if e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(1)
	}
	output := struct {
		Mode                string `json:"mode"`
		PID                 int    `json:"pid"`
		SelectedPackages    int    `json:"selectedPackages"`
		AuthorityConfigured bool   `json:"authorityConfigured"`
		Plan                any    `json:"plan"`
		Platform            string `json:"platform"`
	}{"empty-selection-foundation", os.Getpid(), len(plan.Packages), false, plan, platform}
	if e = json.NewEncoder(os.Stdout).Encode(output); e != nil {
		os.Exit(1)
	}
	if *observe > 0 {
		time.Sleep(*observe)
	}
}

func fail(err error) { fmt.Fprintln(os.Stderr, err); os.Exit(1) }
