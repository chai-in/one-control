package main

import (
	"onecontrol/native/internal/featurehost"
	"onecontrol/native/modules/application-updates/internal/applications"
	"os"
)

func main() {
	if len(os.Args) != 3 || os.Args[1] != "--one-control-host-v1" {
		os.Exit(2)
	}
	tasks := featurehost.NewTasks(applications.Execute)
	err := featurehost.Serve(os.Stdin, os.Stdout, os.Args[2], tasks.Handle)
	tasks.Close()
	if err != nil {
		os.Exit(1)
	}
}
