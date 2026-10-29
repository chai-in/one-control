package main

import (
	"debug/pe"
	"encoding/json"
	"fmt"
	"os"
	"sort"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "expected PE binary path")
		os.Exit(2)
	}
	f, e := pe.Open(os.Args[1])
	if e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(1)
	}
	defer f.Close()
	symbols, e := f.ImportedSymbols()
	if e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(1)
	}
	sort.Strings(symbols)
	var subsystem uint16
	switch header := f.OptionalHeader.(type) {
	case *pe.OptionalHeader32:
		subsystem = header.Subsystem
	case *pe.OptionalHeader64:
		subsystem = header.Subsystem
	}
	if e = json.NewEncoder(os.Stdout).Encode(map[string]any{"machine": f.Machine, "subsystem": subsystem, "importedSymbols": symbols}); e != nil {
		os.Exit(1)
	}
}
