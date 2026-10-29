package processhost

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"
	"unicode/utf16"
	"unsafe"
)

var kernel = syscall.NewLazyDLL("kernel32.dll")
var createJob = kernel.NewProc("CreateJobObjectW")
var setJob = kernel.NewProc("SetInformationJobObject")
var queryJob = kernel.NewProc("QueryInformationJobObject")
var inJob = kernel.NewProc("IsProcessInJob")
var resumeThread = kernel.NewProc("ResumeThread")
var terminateJob = kernel.NewProc("TerminateJobObject")
var initAttrs = kernel.NewProc("InitializeProcThreadAttributeList")
var updateAttrs = kernel.NewProc("UpdateProcThreadAttribute")
var deleteAttrs = kernel.NewProc("DeleteProcThreadAttributeList")

const (
	jobObjectBasicAccountingInformation = 1
	jobObjectExtendedLimitInformation   = 9
	jobObjectLimitKillOnJobClose        = 0x2000
	procThreadAttributeHandleList       = 0x20002
	procThreadAttributeJobList          = 0x2000d
	createSuspendedFlag                 = 0x4
	extendedStartupInfoPresent          = 0x80000
	createNoWindow                      = 0x8000000
)

type startupEx struct {
	syscall.StartupInfo
	Attrs unsafe.Pointer
}
type basicLimits struct {
	ProcessTime, JobTime int64
	Flags                uint32
	Min, Max             uintptr
	Active               uint32
	Affinity             uintptr
	Priority, Scheduling uint32
}
type ioCounters struct{ ReadOps, WriteOps, OtherOps, ReadBytes, WriteBytes, OtherBytes uint64 }
type extendedLimits struct {
	Basic                                          basicLimits
	IO                                             ioCounters
	ProcessMemory, JobMemory, PeakProcess, PeakJob uintptr
}
type accounting struct {
	User, Kernel, PeriodUser, PeriodKernel int64
	Faults, Total, Active, Terminated      uint32
}
type windowsProcess struct {
	pi          syscall.ProcessInformation
	job         syscall.Handle
	write, read *os.File
}

func checked(ok uintptr, err error, api string) error {
	if ok != 0 {
		return nil
	}
	if err == syscall.Errno(0) {
		err = errors.New("zero result without last error")
	}
	return fmt.Errorf("%s: %w", api, err)
}

func launch(config Config) (owned process, err error) {
	p, err := createSuspended(config)
	if err != nil {
		return nil, err
	}
	if err = p.verifyAndResume(); err != nil {
		return nil, errors.Join(err, p.abort())
	}
	return p, nil
}

func createSuspended(config Config) (created *windowsProcess, err error) {
	app, err := syscall.UTF16PtrFromString(config.Executable)
	if err != nil {
		return nil, err
	}
	line, err := syscall.UTF16PtrFromString(syscall.EscapeArg(config.Executable) + " --one-control-host-v1 " + config.Instance)
	if err != nil {
		return nil, err
	}
	dir, err := syscall.UTF16PtrFromString(filepath.Dir(config.Executable))
	if err != nil {
		return nil, err
	}
	root := os.Getenv("SystemRoot")
	if root == "" || strings.ContainsRune(root, 0) {
		return nil, errors.New("SystemRoot is required for the fixed host environment")
	}
	env := utf16.Encode([]rune("SystemRoot=" + root + "\x00\x00"))
	p := &windowsProcess{}
	defer func() {
		if err == nil {
			return
		}
		err = errors.Join(err, p.abort())
	}()
	h, _, e := createJob.Call(0, 0)
	if err = checked(h, e, "CreateJobObjectW"); err != nil {
		return nil, err
	}
	p.job = syscall.Handle(h)
	limits := extendedLimits{}
	limits.Basic.Flags = jobObjectLimitKillOnJobClose
	r, _, e := setJob.Call(h, jobObjectExtendedLimitInformation, uintptr(unsafe.Pointer(&limits)), unsafe.Sizeof(limits))
	if err = checked(r, e, "SetInformationJobObject(KILL_ON_JOB_CLOSE)"); err != nil {
		return nil, err
	}
	sa := syscall.SecurityAttributes{Length: uint32(unsafe.Sizeof(syscall.SecurityAttributes{})), InheritHandle: 1}
	var ir, iw, or, ow syscall.Handle
	if err = syscall.CreatePipe(&ir, &iw, &sa, 0); err != nil {
		return nil, err
	}
	defer syscall.CloseHandle(ir)
	p.write = os.NewFile(uintptr(iw), "host-control-write")
	if err = syscall.CreatePipe(&or, &ow, &sa, 0); err != nil {
		return nil, err
	}
	defer syscall.CloseHandle(ow)
	p.read = os.NewFile(uintptr(or), "host-control-read")
	if err = syscall.SetHandleInformation(iw, syscall.HANDLE_FLAG_INHERIT, 0); err != nil {
		return nil, err
	}
	if err = syscall.SetHandleInformation(or, syscall.HANDLE_FLAG_INHERIT, 0); err != nil {
		return nil, err
	}
	var size uintptr
	initAttrs.Call(0, 2, 0, uintptr(unsafe.Pointer(&size)))
	if size == 0 {
		return nil, errors.New("missing process attribute size")
	}
	storage := make([]byte, size)
	attrs := unsafe.Pointer(&storage[0])
	r, _, e = initAttrs.Call(uintptr(attrs), 2, 0, uintptr(unsafe.Pointer(&size)))
	if err = checked(r, e, "InitializeProcThreadAttributeList"); err != nil {
		return nil, err
	}
	defer deleteAttrs.Call(uintptr(attrs))
	handles := []syscall.Handle{ir, ow}
	r, _, e = updateAttrs.Call(uintptr(attrs), 0, procThreadAttributeHandleList, uintptr(unsafe.Pointer(&handles[0])), uintptr(len(handles))*unsafe.Sizeof(handles[0]), 0, 0)
	if err = checked(r, e, "UpdateProcThreadAttribute(HANDLE_LIST)"); err != nil {
		return nil, err
	}
	jobs := []syscall.Handle{p.job}
	r, _, e = updateAttrs.Call(uintptr(attrs), 0, procThreadAttributeJobList, uintptr(unsafe.Pointer(&jobs[0])), unsafe.Sizeof(jobs[0]), 0, 0)
	if err = checked(r, e, "UpdateProcThreadAttribute(JOB_LIST)"); err != nil {
		return nil, err
	}
	si := startupEx{}
	si.Cb = uint32(unsafe.Sizeof(si))
	si.Flags = syscall.STARTF_USESTDHANDLES
	si.StdInput = ir
	si.StdOutput = ow
	si.StdErr = ow
	si.Attrs = attrs
	err = syscall.CreateProcess(app, line, nil, nil, true, createSuspendedFlag|syscall.CREATE_UNICODE_ENVIRONMENT|extendedStartupInfoPresent|createNoWindow, &env[0], dir, &si.StartupInfo, &p.pi)
	runtime.KeepAlive(storage)
	runtime.KeepAlive(handles)
	runtime.KeepAlive(jobs)
	runtime.KeepAlive(env)
	if err != nil {
		return nil, err
	}
	return p, nil
}

func (p *windowsProcess) verifyAndResume() error {
	var member int32
	r, _, e := inJob.Call(uintptr(p.pi.Process), uintptr(p.job), uintptr(unsafe.Pointer(&member)))
	if err := checked(r, e, "IsProcessInJob"); err != nil {
		return err
	}
	if member == 0 {
		return ErrContainment
	}
	r, _, e = resumeThread.Call(uintptr(p.pi.Thread))
	if r == 0xffffffff {
		return fmt.Errorf("ResumeThread: %w", e)
	}
	if r != 1 {
		return fmt.Errorf("unexpected suspension count %d", r)
	}
	return nil
}

func (p *windowsProcess) abort() error {
	var result error
	if p.pi.Process != 0 {
		syscall.TerminateProcess(p.pi.Process, 1)
		p.terminate()
		wait, err := syscall.WaitForSingleObject(p.pi.Process, 5000)
		if err != nil || wait != 0 {
			result = errors.Join(ErrContainment, err, fmt.Errorf("aborted process wait result %d", wait))
		}
		deadline := time.Now().Add(5 * time.Second)
		for {
			empty, err := p.empty()
			if err != nil {
				result = errors.Join(result, ErrContainment, err)
				break
			}
			if empty {
				break
			}
			if !time.Now().Before(deadline) {
				result = errors.Join(result, ErrContainment)
				break
			}
			time.Sleep(5 * time.Millisecond)
		}
	}
	return errors.Join(result, p.close())
}

func (p *windowsProcess) input() io.Writer  { return p.write }
func (p *windowsProcess) output() io.Reader { return p.read }

func (p *windowsProcess) terminate() error {
	r, _, err := terminateJob.Call(uintptr(p.job), 1)
	return checked(r, err, "TerminateJobObject")
}

func (p *windowsProcess) empty() (bool, error) {
	var info accounting
	r, _, err := queryJob.Call(uintptr(p.job), jobObjectBasicAccountingInformation, uintptr(unsafe.Pointer(&info)), unsafe.Sizeof(info), 0)
	if err = checked(r, err, "QueryInformationJobObject(Accounting)"); err != nil {
		return false, err
	}
	if info.Active != 0 {
		return false, nil
	}
	result, err := syscall.WaitForSingleObject(p.pi.Process, 0)
	if err != nil {
		return false, err
	}
	if result != 0 {
		if result == syscall.WAIT_TIMEOUT {
			return false, nil
		}
		return false, fmt.Errorf("unexpected process wait result %d", result)
	}
	return true, nil
}

func (p *windowsProcess) close() error {
	var errs []error
	if p.write != nil {
		errs = append(errs, p.write.Close())
		p.write = nil
	}
	if p.read != nil {
		errs = append(errs, p.read.Close())
		p.read = nil
	}
	for _, handle := range []*syscall.Handle{&p.pi.Thread, &p.pi.Process, &p.job} {
		if *handle != 0 {
			errs = append(errs, syscall.CloseHandle(*handle))
			*handle = 0
		}
	}
	return errors.Join(errs...)
}
