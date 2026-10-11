// Package agenthealth derives the alerts the agent status page shows from what the
// server already knows: heartbeats, the inventory summary, the agent's jobs and
// their newest runs, and the server version. It never talks to the agent.
package agenthealth

import (
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/osshield/fallbck/pkg/db"
	"github.com/osshield/fallbck/pkg/dbbackup"
	"github.com/osshield/fallbck/pkg/inventory"
)

// StaleAfter is how long without a heartbeat (sent every 30 s) an agent counts as
// stale; three missed beats so a single slow request does not flap the status
const StaleAfter = 90 * time.Second

// Level orders alerts: danger first, then warning, then info
type Level string

const (
	LevelDanger  Level = "danger"
	LevelWarning Level = "warning"
	LevelInfo    Level = "info"
)

// Alert is one finding about an agent
type Alert struct {
	Level  Level  `json:"level"`
	Title  string `json:"title"`
	Detail string `json:"detail,omitempty"`
	// JobID links the alert to a job when it is about one
	JobID *uuid.UUID `json:"job_id,omitempty"`
}

// Input is everything Evaluate looks at
type Input struct {
	Agent *db.Agent
	// Jobs are the agent's jobs (jobs for other agents are ignored)
	Jobs []*db.BackupJob
	// LastRuns maps job id → newest run (from DB.LatestRunByJob); nil = unknown
	LastRuns map[uuid.UUID]*db.JobLastRun
	// ServerVersion is compared with the agent's version ("dev" disables the check)
	ServerVersion string
	Now           time.Time
}

// Stale reports whether the agent's last heartbeat is older than StaleAfter (or
// it never sent one)
func Stale(a *db.Agent, now time.Time) bool {
	return a.LastSeenAt == nil || now.Sub(*a.LastSeenAt) > StaleAfter
}

// EffectiveStatus is the status to display: the stored status unless the
// heartbeat has gone stale, which makes an "online" agent "offline"
func EffectiveStatus(a *db.Agent, now time.Time) db.AgentStatus {
	if Stale(a, now) {
		return db.AgentStatusOffline
	}
	return a.Status
}

// Summary decodes the agent's stored inventory summary; nil when it has none
func Summary(a *db.Agent) *inventory.Summary {
	if len(a.Inventory) == 0 {
		return nil
	}
	var s inventory.Summary
	if err := json.Unmarshal(a.Inventory, &s); err != nil {
		return nil
	}
	return &s
}

// Detail decodes the agent's stored full inventory; nil when it has none
func Detail(a *db.Agent) *inventory.Detail {
	if len(a.InventoryDetail) == 0 {
		return nil
	}
	var d inventory.Detail
	if err := json.Unmarshal(a.InventoryDetail, &d); err != nil {
		return nil
	}
	return &d
}

// Evaluate computes the alerts, most severe first
func Evaluate(in Input) []Alert {
	a := in.Agent
	if a == nil {
		return nil
	}
	now := in.Now
	if now.IsZero() {
		now = time.Now()
	}
	var out []Alert
	add := func(level Level, title, detail string, job *db.BackupJob) {
		al := Alert{Level: level, Title: title, Detail: detail}
		if job != nil {
			id := job.ID
			al.JobID = &id
		}
		out = append(out, al)
	}

	// Connectivity
	switch {
	case a.LastSeenAt == nil:
		add(LevelDanger, "Agent has never checked in", "No heartbeat has been received since enrollment.", nil)
	case Stale(a, now):
		add(LevelDanger, "Agent is offline", fmt.Sprintf("Last heartbeat %s ago; scheduled jobs on this agent will not run until it reconnects.", humanDuration(now.Sub(*a.LastSeenAt))), nil)
	}

	summary := Summary(a)

	// Version
	if behind, ok := VersionBehind(a.Version, in.ServerVersion); ok && behind {
		add(LevelWarning, "Agent version is behind the server", fmt.Sprintf("Agent runs %s, server is %s. Update the agent to keep the API and workflows in step.", a.Version, in.ServerVersion), nil)
	}

	// Disk
	if summary != nil {
		if d := summary.Spool; d != nil && d.MinFreeBytes > 0 && d.FreeBytes < uint64(d.MinFreeBytes) {
			add(LevelDanger, "Spool directory is low on space", fmt.Sprintf("%s has %s free, below the configured minimum of %s; database runs will refuse to start.", d.Path, formatBytes(d.FreeBytes), formatBytes(uint64(d.MinFreeBytes))), nil)
		}
		for _, w := range summary.Warnings {
			add(LevelWarning, w, "", nil)
		}
	}

	// Jobs the agent cannot run, and jobs whose newest run failed
	for _, j := range in.Jobs {
		if j == nil || j.AgentID != a.ID {
			continue
		}
		if !j.Enabled {
			continue
		}
		if reason := cannotRun(a, summary, j); reason != "" {
			add(LevelDanger, fmt.Sprintf("Job %q cannot run on this agent", j.Name), reason, j)
		}
		if lr := in.LastRuns[j.ID]; lr != nil && lr.Status == db.RunStatusFailed {
			add(LevelWarning, fmt.Sprintf("Last run of %q failed", j.Name), fmt.Sprintf("Failed %s.", lr.At.Format("2006-01-02 15:04")), j)
		}
	}

	sort.SliceStable(out, func(i, k int) bool { return rank(out[i].Level) < rank(out[k].Level) })
	return out
}

func rank(l Level) int {
	switch l {
	case LevelDanger:
		return 0
	case LevelWarning:
		return 1
	}
	return 2
}

// cannotRun explains why the agent cannot execute the job, or "" when it can
func cannotRun(a *db.Agent, summary *inventory.Summary, j *db.BackupJob) string {
	jobType, _ := db.NormalizeJobType(j.JobType)
	if !a.CanRunJob(jobType) {
		switch jobType {
		case db.JobTypePVE:
			return "The agent did not detect a Proxmox VE node on its host."
		case db.JobTypeDocker:
			return "The agent did not find a Docker daemon on its host."
		case db.JobTypeDatabase:
			return "The agent found no database client tools."
		}
		return fmt.Sprintf("A %s agent cannot run %s jobs.", a.AgentType, jobType)
	}
	if jobType != db.JobTypeDatabase || j.DBConfig == nil {
		return ""
	}
	engine := j.DBConfig.Engine
	if e, ok := dbbackup.NormalizeEngine(engine); ok {
		engine = e
	}
	if !a.CanRunDBEngine(engine) {
		return fmt.Sprintf("The %s client tools were not found on the agent host.", engine)
	}
	if name := j.DBConfig.Profile; name != "" && summary != nil {
		found := false
		for _, p := range summary.Profiles {
			if p.Name == name {
				found = true
				pe := p.Engine
				if e, ok := dbbackup.NormalizeEngine(pe); ok {
					pe = e
				}
				if pe != "" && engine != "" && pe != engine {
					return fmt.Sprintf("Credential profile %q is for %s, but the job backs up %s.", name, p.Engine, engine)
				}
				break
			}
		}
		if !found {
			return fmt.Sprintf("Credential profile %q is not configured on the agent (fallbck-agent database profile create --name %s ...); runs fall back to passwordless local access only when the agent runs as root on the database host.", name, name)
		}
	}
	return ""
}

// VersionBehind compares two "v1.2.3"-style versions; ok is false when either is
// not a version (dev builds, empty)
func VersionBehind(agent, server string) (behind, ok bool) {
	av, aok := parseVersion(agent)
	sv, sok := parseVersion(server)
	if !aok || !sok {
		return false, false
	}
	for i := range 3 {
		if av[i] != sv[i] {
			return av[i] < sv[i], true
		}
	}
	return false, true
}

func parseVersion(s string) ([3]int, bool) {
	var v [3]int
	s = strings.TrimPrefix(strings.TrimSpace(s), "v")
	if i := strings.IndexAny(s, "-+"); i >= 0 {
		s = s[:i]
	}
	parts := strings.Split(s, ".")
	if len(parts) < 2 || len(parts) > 3 {
		return v, false
	}
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 {
			return v, false
		}
		v[i] = n
	}
	return v, true
}

func humanDuration(d time.Duration) string {
	switch {
	case d < time.Minute:
		return fmt.Sprintf("%ds", int(d.Seconds()))
	case d < time.Hour:
		return fmt.Sprintf("%dm", int(d.Minutes()))
	case d < 48*time.Hour:
		return fmt.Sprintf("%dh %dm", int(d.Hours()), int(d.Minutes())%60)
	}
	return fmt.Sprintf("%dd", int(d.Hours()/24))
}

func formatBytes(b uint64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := uint64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %s", float64(b)/float64(div), []string{"KiB", "MiB", "GiB", "TiB", "PiB"}[exp])
}
