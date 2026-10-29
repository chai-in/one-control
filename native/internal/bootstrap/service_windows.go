package bootstrap

import (
	"context"
	"golang.org/x/sys/windows/svc"
	"time"
)

const ServiceName = "OneControlNative"

type service struct{ installation *Installation }

func (s *service) Execute(_ []string, requests <-chan svc.ChangeRequest, status chan<- svc.Status) (bool, uint32) {
	status <- svc.Status{State: svc.StartPending, WaitHint: 30000}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ready := make(chan struct{})
	done := make(chan error, 1)
	go func() { done <- s.installation.Run(ctx, func() { close(ready) }) }()
	current := svc.Status{State: svc.StartPending, WaitHint: 30000}
	var stopping <-chan time.Time
	for {
		select {
		case <-ready:
			ready = nil
			if ctx.Err() == nil {
				current = svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
				status <- current
			}
		case request := <-requests:
			switch request.Cmd {
			case svc.Interrogate:
				status <- current
			case svc.Stop, svc.Shutdown:
				cancel()
				current = svc.Status{State: svc.StopPending, WaitHint: 60000}
				status <- current
				stopping = time.After(55 * time.Second)
			}
		case err := <-done:
			if err != nil {
				return true, 1
			}
			return false, 0
		case <-stopping:
			// Returning terminates this owner. The lifecycle journal retains any
			// unproved process custody; restart cannot replay those attempts.
			return true, 2
		}
	}
}
func (installation *Installation) Service() error {
	return svc.Run(ServiceName, &service{installation})
}
