package main

import (
	"encoding/binary"
	"encoding/json"
	"io"
	"onecontrol/native/internal/processhost"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

func inert() {
	for {
		time.Sleep(time.Hour)
	}
}
func fail(err error) {
	if err != nil {
		os.Exit(4)
	}
}
func write(path string, v any) {
	b, err := json.Marshal(v)
	fail(err)
	fail(os.WriteFile(path, b, 0600))
}

func main() {
	exe, err := os.Executable()
	fail(err)
	dir := filepath.Dir(exe)
	if len(os.Args) == 2 && os.Args[1] == "--one-control-fixture-leaf" {
		inert()
		return
	}
	if len(os.Args) != 3 || os.Args[1] != "--one-control-host-v1" {
		os.Exit(2)
	}
	instance := os.Args[2]
	mode := strings.TrimSuffix(filepath.Base(exe), ".exe")
	leaf := exec.Command(exe, "--one-control-fixture-leaf")
	fail(leaf.Start())
	keys := []string{}
	for _, value := range os.Environ() {
		keys = append(keys, strings.SplitN(value, "=", 2)[0])
	}
	sort.Strings(keys)
	k := syscall.NewLazyDLL("kernel32.dll")
	var member int32
	r, _, _ := k.NewProc("IsProcessInJob").Call(^uintptr(0), 0, uintptr(unsafe.Pointer(&member)))
	app, err := syscall.UTF16PtrFromString(exe)
	fail(err)
	line, err := syscall.UTF16PtrFromString(syscall.EscapeArg(exe) + " --one-control-fixture-leaf")
	fail(err)
	si := syscall.StartupInfo{Cb: uint32(unsafe.Sizeof(syscall.StartupInfo{}))}
	var pi syscall.ProcessInformation
	breakawayErr := syscall.CreateProcess(app, line, nil, nil, false, 0x1000000|0x4|0x8000000, nil, nil, &si, &pi)
	denied := breakawayErr == syscall.Errno(5)
	if breakawayErr == nil {
		syscall.TerminateProcess(pi.Process, 1)
		syscall.WaitForSingleObject(pi.Process, 5000)
		syscall.CloseHandle(pi.Thread)
		syscall.CloseHandle(pi.Process)
	}
	observation := map[string]any{"hostPID": os.Getpid(), "leafPID": leaf.Process.Pid, "environment": keys, "inJobAtEntry": r != 0 && member != 0, "breakawayDenied": denied}
	var decoy struct {
		Handle uintptr
		Name   string
	}
	if b, e := os.ReadFile(filepath.Join(dir, "decoy.json")); e == nil {
		fail(json.Unmarshal(b, &decoy))
		var flags uint32
		valid, _, handleErr := k.NewProc("GetHandleInformation").Call(decoy.Handle, uintptr(unsafe.Pointer(&flags)))
		excluded := valid == 0 && handleErr == syscall.Errno(6)
		if valid == 0 && !excluded {
			os.Exit(5)
		}
		if valid != 0 {
			name, e := syscall.UTF16PtrFromString(decoy.Name)
			fail(e)
			known, _, _ := k.NewProc("OpenEventW").Call(0x100000, 0, uintptr(unsafe.Pointer(name)))
			if known == 0 {
				os.Exit(5)
			}
			same, _, _ := syscall.NewLazyDLL("kernelbase.dll").NewProc("CompareObjectHandles").Call(decoy.Handle, known)
			syscall.CloseHandle(syscall.Handle(known))
			excluded = same == 0
		}
		observation["decoyExcluded"] = excluded
	}
	write(filepath.Join(dir, "observation.json"), observation)
	if mode == "no-ready" {
		inert()
	}
	if mode == "oversized" {
		var b [4]byte
		binary.BigEndian.PutUint32(b[:], processhost.MaxFrame+1)
		os.Stdout.Write(b[:])
		inert()
	}
	if mode == "malformed" {
		os.Stdout.Write([]byte{0, 0, 0, 1, '{'})
		inert()
	}
	if mode == "wrong-instance" {
		instance = strings.Repeat("a", 64)
	}
	fail(processhost.WriteMessage(os.Stdout, processhost.Message{Version: 1, Type: "ready", Instance: instance}))
	active := false
	sequence := uint64(0)
	for {
		m, err := processhost.ReadMessage(os.Stdin)
		if err == io.EOF || err == io.ErrUnexpectedEOF {
			inert()
		}
		fail(err)
		if m.Instance != instance {
			os.Exit(3)
		}
		sequence++
		if m.Sequence != sequence {
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
			if mode == "health-hang" {
				inert()
			}
			reply = "healthy"
		case "stop":
			if mode == "stop-hang" {
				inert()
			}
			reply = "stopped"
		default:
			os.Exit(3)
		}
		if mode == "stale-health" && m.Type == "health" {
			m.Sequence--
		}
		fail(processhost.WriteMessage(os.Stdout, processhost.Message{Version: 1, Type: reply, Instance: instance, Sequence: m.Sequence}))
		if m.Type == "stop" {
			if mode != "orphan-on-stop" {
				fail(leaf.Process.Kill())
				leaf.Wait()
			}
			return
		}
	}
}
