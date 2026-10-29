package session

import (
	"context"
	"errors"
	"golang.org/x/sys/windows"
	"path/filepath"
	"strings"
	"syscall"
	"unsafe"
)

type ProcessResult struct {
	ExitCode uint32
	Started  bool
	Err      error
}
type accounting struct {
	User, Kernel, PeriodUser, PeriodKernel int64
	Faults, Total, Active, Terminated      uint32
}

// RunWinGet never inherits SYSTEM credentials, handles, or environment. The
// user process is suspended until it belongs to a kill-on-close job and its
// selected logon is checked again. All descendants retain that containment.
func RunWinGet(ctx context.Context, target Target, args []string) (result ProcessResult) {
	fail := func(err error) ProcessResult { return ProcessResult{Started: result.Started, Err: err} }
	if err := ctx.Err(); err != nil {
		return fail(err)
	}
	token, err := Bind(target)
	if err != nil {
		return fail(err)
	}
	defer token.Close()
	var elevated uint32
	var elevationBytes uint32
	if err = windows.GetTokenInformation(token, windows.TokenElevation, (*byte)(unsafe.Pointer(&elevated)), uint32(unsafe.Sizeof(elevated)), &elevationBytes); err != nil {
		return fail(err)
	}
	if elevated != 0 {
		return fail(errors.New("standard_user_session_required"))
	}
	environment, err := token.Environ(false)
	if err != nil {
		return fail(err)
	}
	localAppData := ""
	for _, entry := range environment {
		key, value, ok := strings.Cut(entry, "=")
		if ok && strings.EqualFold(key, "LOCALAPPDATA") {
			localAppData = value
		}
	}
	if localAppData == "" || !filepath.IsAbs(localAppData) {
		return fail(errors.New("user_profile_unavailable"))
	}
	executable := filepath.Join(localAppData, "Microsoft", "WindowsApps", "winget.exe")
	app, _ := windows.UTF16PtrFromString(executable)
	line := syscall.EscapeArg(executable)
	for _, argument := range args {
		line += " " + syscall.EscapeArg(argument)
	}
	command, err := windows.UTF16PtrFromString(line)
	if err != nil {
		return fail(err)
	}
	directory, _ := windows.UTF16PtrFromString(localAppData)
	var env *uint16
	if err = windows.CreateEnvironmentBlock(&env, token, false); err != nil {
		return fail(err)
	}
	defer windows.DestroyEnvironmentBlock(env)
	job, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		return fail(err)
	}
	defer windows.CloseHandle(job)
	limits := windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION{}
	limits.BasicLimitInformation.LimitFlags = windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
	if _, err = windows.SetInformationJobObject(job, windows.JobObjectExtendedLimitInformation, uintptr(unsafe.Pointer(&limits)), uint32(unsafe.Sizeof(limits))); err != nil {
		return fail(err)
	}
	desktop, _ := windows.UTF16PtrFromString(`winsta0\default`)
	startup := windows.StartupInfo{Cb: uint32(unsafe.Sizeof(windows.StartupInfo{})), Desktop: desktop}
	var process windows.ProcessInformation
	if err = ctx.Err(); err != nil {
		return fail(err)
	}
	if err = windows.CreateProcessAsUser(token, app, command, nil, nil, false, windows.CREATE_SUSPENDED|windows.CREATE_UNICODE_ENVIRONMENT|windows.CREATE_NO_WINDOW, env, directory, &startup, &process); err != nil {
		return fail(err)
	}
	defer windows.CloseHandle(process.Process)
	defer windows.CloseHandle(process.Thread)
	defer func() {
		// Killing cannot undo effects already performed by an installer service.
		// Errors after resume are therefore always reported as indeterminate.
		windows.TerminateJobObject(job, 1)
		windows.TerminateProcess(process.Process, 1)
		wait, waitErr := windows.WaitForSingleObject(process.Process, 5000)
		if waitErr != nil || wait != windows.WAIT_OBJECT_0 {
			result.Err = errors.New("user_process_cleanup_unresolved")
		}
	}()
	if err = windows.AssignProcessToJobObject(job, process.Process); err != nil {
		return fail(err)
	}
	current, err := Bind(target)
	if err != nil {
		return fail(err)
	}
	current.Close()
	if err = ctx.Err(); err != nil {
		return fail(err)
	}
	result.Started = true
	if _, err = windows.ResumeThread(process.Thread); err != nil {
		return fail(err)
	}
	for {
		wait, err := windows.WaitForSingleObject(process.Process, 500)
		if err != nil {
			return fail(err)
		}
		if wait == windows.WAIT_OBJECT_0 {
			if err = windows.GetExitCodeProcess(process.Process, &result.ExitCode); err != nil {
				return fail(err)
			}
			var state accounting
			if err = windows.QueryInformationJobObject(job, windows.JobObjectBasicAccountingInformation, uintptr(unsafe.Pointer(&state)), uint32(unsafe.Sizeof(state)), nil); err != nil {
				return fail(err)
			}
			if state.Active != 0 {
				return fail(errors.New("user_provider_descendants_unresolved"))
			}
			return result
		}
		if wait != uint32(windows.WAIT_TIMEOUT) {
			return fail(errors.New("user_process_wait_unresolved"))
		}
		if err = ctx.Err(); err != nil {
			return fail(err)
		}
		current, err = Bind(target)
		if err != nil {
			return fail(err)
		}
		current.Close()
	}
}
