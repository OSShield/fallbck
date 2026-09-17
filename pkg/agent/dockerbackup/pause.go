package dockerbackup

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"time"

	dockerspec "github.com/osshield/fallbck/pkg/dockerbackup"
)

// unpauseTimeout bounds the thaw of a container after its volumes were read
const unpauseTimeout = 30 * time.Second

// wantsPause reports whether a running container is paused while its volumes are
// read: label fallbck.io/pause=true or a match in the job's pause list
func wantsPause(spec *dockerspec.Spec, ci *ContainerInspect) bool {
	if ci == nil || !ci.State.Running || ci.State.Paused {
		return false
	}
	if strings.EqualFold(ci.Config.Labels[dockerspec.LabelPause], "true") {
		return true
	}
	return dockerspec.MatchesAny(ci.CleanName(), spec.PauseContainers)
}

// pauser pauses containers for the duration of a volume copy and always unpauses
// them, with a fresh context so a cancelled run never leaves a container frozen
type pauser struct {
	client *Client
}

// pause freezes the containers and returns the names actually paused plus the thaw
// function; a container that cannot be paused is reported as a warning, not an error
func (p *pauser) pause(ctx context.Context, containers []*ContainerInspect) (paused []string, thaw func() []string) {
	var ids []string
	var warnings []string
	for _, ci := range containers {
		if err := p.client.Pause(ctx, ci.ID); err != nil {
			warnings = append(warnings, fmt.Sprintf("pausing %s: %v", ci.CleanName(), err))
			continue
		}
		slog.Info("Paused container for volume backup", "container", ci.CleanName())
		ids = append(ids, ci.ID)
		paused = append(paused, ci.CleanName())
	}
	thaw = func() []string {
		out := warnings
		for i, id := range ids {
			tctx, cancel := context.WithTimeout(context.Background(), unpauseTimeout)
			err := p.client.Unpause(tctx, id)
			cancel()
			if err != nil {
				out = append(out, fmt.Sprintf("unpausing %s failed: %v (run: docker unpause %s)", paused[i], err, paused[i]))
				slog.Error("Unpausing container failed", "container", paused[i], "error", err)
				continue
			}
			slog.Info("Unpaused container", "container", paused[i])
		}
		return out
	}
	return paused, thaw
}
