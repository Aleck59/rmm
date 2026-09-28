//go:build windows

package winservice

import (
	"context"
	"fmt"
	"time"

	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/eventlog"
	"golang.org/x/sys/windows/svc/mgr"
)

// IsService reports whether the current process was started by the Windows
// Service Control Manager (as opposed to an interactive console).
func IsService() (bool, error) {
	return svc.IsWindowsService()
}

// Install registers the service with the SCM: automatic delayed start,
// restart-on-failure recovery actions, and an event-log source.
func Install(c Config, exePath string) error {
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("connect to service manager: %w", err)
	}
	defer m.Disconnect()

	if s, err := m.OpenService(c.Name); err == nil {
		s.Close()
		return fmt.Errorf("service %q already exists", c.Name)
	}

	s, err := m.CreateService(c.Name, exePath, mgr.Config{
		DisplayName:      c.DisplayName,
		Description:      c.Description,
		StartType:        mgr.StartAutomatic,
		DelayedAutoStart: true,
	}, c.Arguments...)
	if err != nil {
		return fmt.Errorf("create service: %w", err)
	}
	defer s.Close()

	// Restart after 1 min, 1 min, then 5 min; reset the counter after a day.
	if err := s.SetRecoveryActions([]mgr.RecoveryAction{
		{Type: mgr.ServiceRestart, Delay: 1 * time.Minute},
		{Type: mgr.ServiceRestart, Delay: 1 * time.Minute},
		{Type: mgr.ServiceRestart, Delay: 5 * time.Minute},
	}, uint32((24 * time.Hour).Seconds())); err != nil {
		// Non-fatal: the service is installed, only recovery tuning failed.
		fmt.Printf("warning: could not set recovery actions: %v\n", err)
	}

	// Event-log source; ignore "already exists" style errors.
	if err := eventlog.InstallAsEventCreate(c.Name, eventlog.Error|eventlog.Warning|eventlog.Info); err != nil {
		fmt.Printf("warning: could not register event-log source: %v\n", err)
	}
	return nil
}

// Remove stops (best-effort) and deletes the service and its event-log source.
func Remove(name string) error {
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("connect to service manager: %w", err)
	}
	defer m.Disconnect()

	s, err := m.OpenService(name)
	if err != nil {
		return fmt.Errorf("service %q is not installed: %w", name, err)
	}
	defer s.Close()

	_, _ = s.Control(svc.Stop) // best-effort; ignore if already stopped
	if err := s.Delete(); err != nil {
		return fmt.Errorf("delete service: %w", err)
	}
	_ = eventlog.Remove(name)
	return nil
}

// Start launches an installed service.
func Start(name string) error {
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("connect to service manager: %w", err)
	}
	defer m.Disconnect()

	s, err := m.OpenService(name)
	if err != nil {
		return fmt.Errorf("service %q is not installed: %w", name, err)
	}
	defer s.Close()

	if err := s.Start(); err != nil {
		return fmt.Errorf("start service: %w", err)
	}
	return nil
}

// Stop requests a service to stop and waits up to 30s for it to do so.
func Stop(name string) error {
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("connect to service manager: %w", err)
	}
	defer m.Disconnect()

	s, err := m.OpenService(name)
	if err != nil {
		return fmt.Errorf("service %q is not installed: %w", name, err)
	}
	defer s.Close()

	status, err := s.Control(svc.Stop)
	if err != nil {
		return fmt.Errorf("stop service: %w", err)
	}
	deadline := time.Now().Add(30 * time.Second)
	for status.State != svc.Stopped {
		if time.Now().After(deadline) {
			return fmt.Errorf("timed out waiting for service %q to stop", name)
		}
		time.Sleep(300 * time.Millisecond)
		if status, err = s.Query(); err != nil {
			return fmt.Errorf("query service status: %w", err)
		}
	}
	return nil
}

// RunAsService runs the payload under SCM supervision, translating a Stop or
// Shutdown request into cancellation of the context passed to run.
func RunAsService(name string, run RunFunc) error {
	return svc.Run(name, &program{run: run})
}

type program struct {
	run RunFunc
}

func (p *program) Execute(_ []string, r <-chan svc.ChangeRequest, changes chan<- svc.Status) (bool, uint32) {
	const accepted = svc.AcceptStop | svc.AcceptShutdown
	changes <- svc.Status{State: svc.StartPending}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errc := make(chan error, 1)
	go func() { errc <- p.run(ctx) }()

	changes <- svc.Status{State: svc.Running, Accepts: accepted}
	for {
		select {
		case c := <-r:
			switch c.Cmd {
			case svc.Interrogate:
				changes <- c.CurrentStatus
			case svc.Stop, svc.Shutdown:
				changes <- svc.Status{State: svc.StopPending}
				cancel()
				<-errc
				return false, 0
			default:
			}
		case <-errc:
			// Payload exited on its own (e.g. fatal startup error).
			return false, 0
		}
	}
}
