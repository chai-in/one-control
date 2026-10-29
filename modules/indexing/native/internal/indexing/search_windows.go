package indexing

import (
	"context"
	"errors"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
	"time"
)

type searchService struct {
	manager *mgr.Mgr
	service *mgr.Service
}

func openSearch(write bool) (provider, error) {
	handle, err := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_CONNECT)
	if err != nil {
		return nil, err
	}
	manager := &mgr.Mgr{Handle: handle}
	name, _ := windows.UTF16PtrFromString("WSearch")
	access := uint32(windows.SERVICE_QUERY_CONFIG | windows.SERVICE_QUERY_STATUS)
	if write {
		access |= windows.SERVICE_CHANGE_CONFIG | windows.SERVICE_START | windows.SERVICE_STOP
	}
	serviceHandle, err := windows.OpenService(handle, name, access)
	if err != nil && !errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
		manager.Disconnect()
		return nil, err
	}
	var service *mgr.Service
	if err == nil {
		service = &mgr.Service{Name: "WSearch", Handle: serviceHandle}
	}
	return &searchService{manager, service}, nil
}
func (s *searchService) Close() {
	if s.service != nil {
		s.service.Close()
	}
	s.manager.Disconnect()
}
func (s *searchService) Snapshot() (Snapshot, error) {
	snapshot := Snapshot{Supported: s.service != nil, Service: "not-installed", Startup: "unavailable", Catalog: Catalog{Status: "unavailable"}, PauseMechanism: "service-stop-fallback", LocationScope: "unavailable"}
	if s.service == nil {
		return snapshot, nil
	}
	config, err := s.service.Config()
	if err != nil {
		return snapshot, err
	}
	snapshot.Startup = map[uint32]string{mgr.StartAutomatic: "automatic", mgr.StartManual: "manual", mgr.StartDisabled: "disabled"}[config.StartType]
	if config.StartType == mgr.StartAutomatic && config.DelayedAutoStart {
		snapshot.Startup = "automatic-delayed"
	}
	status, err := s.service.Query()
	if err != nil {
		return snapshot, err
	}
	snapshot.Service = map[svc.State]string{svc.Stopped: "stopped", svc.StartPending: "starting", svc.StopPending: "stopping", svc.Running: "running", svc.ContinuePending: "resuming", svc.PausePending: "pausing", svc.Paused: "paused"}[status.State]
	if status.State == svc.Running {
		readCatalog(&snapshot)
	}
	return snapshot, nil
}
func (s *searchService) Configure(startup string) error {
	config, err := s.service.Config()
	if err != nil {
		return err
	}
	config.StartType = map[string]uint32{"automatic": mgr.StartAutomatic, "automatic-delayed": mgr.StartAutomatic, "manual": mgr.StartManual, "disabled": mgr.StartDisabled}[startup]
	config.DelayedAutoStart = startup == "automatic-delayed"
	return s.service.UpdateConfig(config)
}
func (s *searchService) Start(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	status, err := s.service.Query()
	if err != nil {
		return err
	}
	if status.State == svc.Running {
		return nil
	}
	if err = s.service.Start(); err != nil && !errors.Is(err, windows.ERROR_SERVICE_ALREADY_RUNNING) {
		return err
	}
	return s.wait(ctx, svc.Running)
}
func (s *searchService) Stop(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	status, err := s.service.Query()
	if err != nil {
		return err
	}
	if status.State == svc.Stopped {
		return nil
	}
	if _, err = s.service.Control(svc.Stop); err != nil && !errors.Is(err, windows.ERROR_SERVICE_NOT_ACTIVE) {
		return err
	}
	return s.wait(ctx, svc.Stopped)
}
func (s *searchService) wait(ctx context.Context, wanted svc.State) error {
	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()
	for {
		status, err := s.service.Query()
		if err != nil {
			return err
		}
		if status.State == wanted {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}
