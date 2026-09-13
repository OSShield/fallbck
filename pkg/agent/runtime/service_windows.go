//go:build windows

package runtime

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

// IsWindowsService reports whether the process was started by the service
// control manager
func IsWindowsService() bool {
	ok, _ := svc.IsWindowsService()
	return ok
}

// RunAsService runs body under the service control manager: the service reports
// Running once body is going and stops it (closing stop) on a stop or shutdown
// request. body's error ends the service.
func RunAsService(name string, body func(stop <-chan struct{}) error) error {
	return svc.Run(name, &serviceHandler{body: body})
}

type serviceHandler struct {
	body func(stop <-chan struct{}) error
}

func (h *serviceHandler) Execute(_ []string, requests <-chan svc.ChangeRequest, status chan<- svc.Status) (bool, uint32) {
	status <- svc.Status{State: svc.StartPending}
	stop := make(chan struct{})
	done := make(chan error, 1)
	go func() { done <- h.body(stop) }()
	status <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
	for {
		select {
		case err := <-done:
			if err != nil {
				slog.Error("Service body failed", "error", err)
				status <- svc.Status{State: svc.StopPending}
				return true, 1
			}
			status <- svc.Status{State: svc.StopPending}
			return false, 0
		case req := <-requests:
			switch req.Cmd {
			case svc.Interrogate:
				status <- req.CurrentStatus
			case svc.Stop, svc.Shutdown:
				status <- svc.Status{State: svc.StopPending}
				close(stop)
				select {
				case <-done:
				case <-time.After(30 * time.Second):
					slog.Warn("Service body did not stop in time")
				}
				return false, 0
			}
		}
	}
}

// ServiceCommand implements "<agent> service install|uninstall|start|stop|status":
// the service runs "<exe> run --config <configPath>" as LocalSystem, starts
// automatically, and restarts after failures.
func ServiceCommand(name, displayName, description, action, configPath string) error {
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("connecting to the service manager (run as administrator): %w", err)
	}
	defer m.Disconnect()

	switch action {
	case "install":
		exe, err := os.Executable()
		if err != nil {
			return err
		}
		if exe, err = filepath.Abs(exe); err != nil {
			return err
		}
		if s, err := m.OpenService(name); err == nil {
			s.Close()
			return fmt.Errorf("service %s already exists", name)
		}
		args := []string{"run"}
		if configPath != "" {
			if configPath, err = filepath.Abs(configPath); err != nil {
				return err
			}
			args = append(args, "--config", configPath)
		}
		s, err := m.CreateService(name, exe, mgr.Config{
			DisplayName:  displayName,
			Description:  description,
			StartType:    mgr.StartAutomatic,
			ErrorControl: mgr.ErrorNormal,
		}, args...)
		if err != nil {
			return fmt.Errorf("creating service: %w", err)
		}
		defer s.Close()
		_ = s.SetRecoveryActions([]mgr.RecoveryAction{
			{Type: mgr.ServiceRestart, Delay: 15 * time.Second},
			{Type: mgr.ServiceRestart, Delay: 60 * time.Second},
			{Type: mgr.ServiceRestart, Delay: 5 * time.Minute},
		}, 86400)
		fmt.Printf("Service %s installed: %s %s\n", name, exe, strings.Join(args, " "))
		return nil
	case "uninstall":
		s, err := m.OpenService(name)
		if err != nil {
			return fmt.Errorf("service %s is not installed", name)
		}
		defer s.Close()
		if st, err := s.Query(); err == nil && st.State != svc.Stopped {
			_, _ = s.Control(svc.Stop)
			waitState(s, svc.Stopped, 30*time.Second)
		}
		if err := s.Delete(); err != nil {
			return fmt.Errorf("deleting service: %w", err)
		}
		fmt.Printf("Service %s removed\n", name)
		return nil
	case "start":
		s, err := m.OpenService(name)
		if err != nil {
			return fmt.Errorf("service %s is not installed", name)
		}
		defer s.Close()
		if err := s.Start(); err != nil {
			return fmt.Errorf("starting service: %w", err)
		}
		fmt.Printf("Service %s started\n", name)
		return nil
	case "stop":
		s, err := m.OpenService(name)
		if err != nil {
			return fmt.Errorf("service %s is not installed", name)
		}
		defer s.Close()
		if _, err := s.Control(svc.Stop); err != nil {
			return fmt.Errorf("stopping service: %w", err)
		}
		waitState(s, svc.Stopped, 30*time.Second)
		fmt.Printf("Service %s stopped\n", name)
		return nil
	case "status":
		s, err := m.OpenService(name)
		if err != nil {
			fmt.Printf("Service %s is not installed\n", name)
			return nil
		}
		defer s.Close()
		st, err := s.Query()
		if err != nil {
			return err
		}
		fmt.Printf("Service %s: %s\n", name, stateName(st.State))
		return nil
	}
	return fmt.Errorf("unknown service action %q (install, uninstall, start, stop, status)", action)
}

func waitState(s *mgr.Service, want svc.State, timeout time.Duration) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	for {
		if st, err := s.Query(); err != nil || st.State == want {
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(500 * time.Millisecond):
		}
	}
}

func stateName(s svc.State) string {
	switch s {
	case svc.Stopped:
		return "stopped"
	case svc.StartPending:
		return "starting"
	case svc.StopPending:
		return "stopping"
	case svc.Running:
		return "running"
	case svc.PausePending, svc.Paused, svc.ContinuePending:
		return "paused"
	}
	return fmt.Sprintf("state %d", s)
}
