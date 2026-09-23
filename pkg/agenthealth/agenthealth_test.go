package agenthealth

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/osshield/fallbck/pkg/db"
	"github.com/osshield/fallbck/pkg/dbbackup"
	"github.com/osshield/fallbck/pkg/inventory"
)

func agentWith(t *testing.T, s *inventory.Summary) *db.Agent {
	t.Helper()
	now := time.Now()
	a := &db.Agent{ID: uuid.New(), Hostname: "db1", AgentType: db.AgentTypeFilesystem, Version: "1.2.0", Status: db.AgentStatusOnline, LastSeenAt: &now, DBTools: true, DBEngines: []string{"postgres"}}
	if s != nil {
		raw, err := json.Marshal(s)
		if err != nil {
			t.Fatal(err)
		}
		a.Inventory = raw
	}
	return a
}

func titles(al []Alert) string {
	var b []string
	for _, a := range al {
		b = append(b, string(a.Level)+":"+a.Title)
	}
	return strings.Join(b, "\n")
}

func TestHealthyAgentHasNoAlerts(t *testing.T) {
	a := agentWith(t, &inventory.Summary{Profiles: []dbspecProfile{{Name: "pg", Engine: "postgresql"}}, Spool: &inventory.Disk{Path: "/var/spool", FreeBytes: 10 << 30, MinFreeBytes: 1 << 30}})
	job := &db.BackupJob{ID: uuid.New(), AgentID: a.ID, Name: "nightly", Enabled: true, JobType: db.JobTypeDatabase, DBConfig: &dbbackup.Spec{Engine: "postgresql", Profile: "pg"}}
	got := Evaluate(Input{Agent: a, Jobs: []*db.BackupJob{job}, ServerVersion: "1.2.0", LastRuns: map[uuid.UUID]*db.JobLastRun{job.ID: {Status: db.RunStatusCompleted}}})
	if len(got) != 0 {
		t.Fatalf("expected no alerts, got:\n%s", titles(got))
	}
}

type dbspecProfile = dbbackup.ProfileSummary

func TestOfflineStaleAndNever(t *testing.T) {
	a := agentWith(t, nil)
	old := time.Now().Add(-10 * time.Minute)
	a.LastSeenAt = &old
	got := Evaluate(Input{Agent: a})
	if len(got) != 1 || got[0].Level != LevelDanger || !strings.Contains(got[0].Title, "offline") {
		t.Fatalf("stale agent: %s", titles(got))
	}
	if EffectiveStatus(a, time.Now()) != db.AgentStatusOffline {
		t.Fatal("stale agent should display as offline")
	}
	a.LastSeenAt = nil
	got = Evaluate(Input{Agent: a})
	if len(got) != 1 || !strings.Contains(got[0].Title, "never") {
		t.Fatalf("never seen: %s", titles(got))
	}
}

func TestJobsTheAgentCannotRun(t *testing.T) {
	a := agentWith(t, &inventory.Summary{Profiles: []dbspecProfile{{Name: "pg", Engine: "postgresql"}}})
	jobs := []*db.BackupJob{
		{ID: uuid.New(), AgentID: a.ID, Name: "missing-profile", Enabled: true, JobType: db.JobTypeDatabase, DBConfig: &dbbackup.Spec{Engine: "postgresql", Profile: "nope"}},
		{ID: uuid.New(), AgentID: a.ID, Name: "wrong-engine", Enabled: true, JobType: db.JobTypeDatabase, DBConfig: &dbbackup.Spec{Engine: "mysql", Profile: "pg"}},
		{ID: uuid.New(), AgentID: a.ID, Name: "no-pve", Enabled: true, JobType: db.JobTypePVE},
		{ID: uuid.New(), AgentID: a.ID, Name: "disabled", Enabled: false, JobType: db.JobTypeDocker},
		{ID: uuid.New(), AgentID: uuid.New(), Name: "other-agent", Enabled: true, JobType: db.JobTypeDocker},
	}
	got := Evaluate(Input{Agent: a, Jobs: jobs})
	want := []string{"missing-profile", "wrong-engine", "no-pve"}
	if len(got) != len(want) {
		t.Fatalf("want %d alerts, got:\n%s", len(want), titles(got))
	}
	for i, w := range want {
		if !strings.Contains(got[i].Title, w) || got[i].JobID == nil || *got[i].JobID != jobs[i].ID {
			t.Errorf("alert %d: %+v", i, got[i])
		}
	}
	if !strings.Contains(got[0].Detail, "profile create --name nope") {
		t.Errorf("missing profile hint: %s", got[0].Detail)
	}
}

func TestSpoolFailedRunAndVersion(t *testing.T) {
	a := agentWith(t, &inventory.Summary{Spool: &inventory.Disk{Path: "/spool", FreeBytes: 100 << 20, MinFreeBytes: 1 << 30}, Warnings: []string{"profile x is for mysql but its client tools were not found"}})
	a.Version = "v1.1.9"
	job := &db.BackupJob{ID: uuid.New(), AgentID: a.ID, Name: "fs", Enabled: true, JobType: db.JobTypeFilesystem}
	got := Evaluate(Input{Agent: a, Jobs: []*db.BackupJob{job}, ServerVersion: "1.2.0", LastRuns: map[uuid.UUID]*db.JobLastRun{job.ID: {Status: db.RunStatusFailed, At: time.Now()}}})
	s := titles(got)
	for _, w := range []string{"danger:Spool directory is low on space", "warning:Agent version is behind the server", "warning:profile x is for mysql", `warning:Last run of "fs" failed`} {
		if !strings.Contains(s, w) {
			t.Errorf("missing %q in:\n%s", w, s)
		}
	}
	if got[0].Level != LevelDanger {
		t.Errorf("danger alerts should sort first: %s", s)
	}
}

func TestVersionCompare(t *testing.T) {
	cases := []struct {
		agent, server string
		behind, ok    bool
	}{
		{"1.2.0", "1.2.0", false, true},
		{"v1.1.9", "1.2.0", true, true},
		{"1.3.0", "1.2.9", false, true},
		{"1.2.0-rc1", "1.2.0", false, true},
		{"dev", "1.2.0", false, false},
		{"1.2.0", "", false, false},
	}
	for _, c := range cases {
		b, ok := versionBehind(c.agent, c.server)
		if b != c.behind || ok != c.ok {
			t.Errorf("%s vs %s: behind=%v ok=%v", c.agent, c.server, b, ok)
		}
	}
}
