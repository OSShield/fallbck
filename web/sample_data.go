package web

import (
	"time"

	"github.com/google/uuid"
	"github.com/osshield/fallbck/pkg/db"
)

var (
	sampleAgentID1  = uuid.MustParse("11111111-1111-1111-1111-111111111111")
	sampleAgentID2  = uuid.MustParse("22222222-2222-2222-2222-222222222222")
	sampleAgentID3  = uuid.MustParse("33333333-3333-3333-3333-333333333333")
	sampleTargetID1 = uuid.MustParse("44444444-4444-4444-4444-444444444444")
	sampleTargetID2 = uuid.MustParse("55555555-5555-5555-5555-555555555555")
	sampleJobID1    = uuid.MustParse("66666666-6666-6666-6666-666666666666")
	sampleJobID2    = uuid.MustParse("77777777-7777-7777-7777-777777777777")
)

func getSampleAgents() []*db.Agent {
	now := time.Now().UTC()
	seen1 := now.Add(-2 * time.Minute)
	seen2 := now.Add(-15 * time.Second)
	seen3 := now.Add(-4 * time.Hour)

	return []*db.Agent{
		{
			ID:         sampleAgentID1,
			Hostname:   "web-prod-01.internal",
			IPAddress:  "192.168.10.15",
			OS:         "linux",
			Arch:       "amd64",
			Version:    "0.1.0",
			TaskQueue:  "fallbck-agent-11111111",
			Status:     db.AgentStatusOnline,
			LastSeenAt: &seen1,
			CreatedAt:  now.Add(-48 * time.Hour),
		},
		{
			ID:         sampleAgentID2,
			Hostname:   "db-postgres-master.internal",
			IPAddress:  "192.168.10.20",
			OS:         "linux",
			Arch:       "amd64",
			Version:    "0.1.0",
			TaskQueue:  "fallbck-agent-22222222",
			Status:     db.AgentStatusBusy,
			LastSeenAt: &seen2,
			CreatedAt:  now.Add(-24 * time.Hour),
		},
		{
			ID:         sampleAgentID3,
			Hostname:   "storage-node-backup",
			IPAddress:  "192.168.10.50",
			OS:         "linux",
			Arch:       "arm64",
			Version:    "0.1.0",
			TaskQueue:  "fallbck-agent-33333333",
			Status:     db.AgentStatusOffline,
			LastSeenAt: &seen3,
			CreatedAt:  now.Add(-72 * time.Hour),
		},
	}
}

func getSampleTargets() []*db.BackupTarget {
	now := time.Now().UTC()
	return []*db.BackupTarget{
		{
			ID:          sampleTargetID1,
			Name:        "Primary Proxmox Backup Server",
			TargetType:  "pbs",
			Endpoint:    "https://pbs.homelab.local:8007",
			Datastore:   "backup-store-nvme",
			Namespace:   "production",
			PxarFormat:  db.PxarFormatV2,
			HasToken:    true,
			Fingerprint: "SHA256:4a:2b:8c:9d:1e:3f:5a:6b:7c:8d:9e:0f:1a:2b:3c:4d:5e:6f:7a:8b:9c:0d:1e:2f:3a:4b:5c:6d:7e:8f:9a:0b",
			TLSVerify:   true,
			CreatedAt:   now.Add(-10 * 24 * time.Hour),
		},
		{
			ID:         sampleTargetID2,
			Name:       "Secondary PBS Offsite",
			TargetType: "pbs",
			Endpoint:   "https://pbs-remote.backup.net:8007",
			Datastore:  "hdd-archive-pool",
			Namespace:  "offsite-cold",
			TLSVerify:  true,
			CreatedAt:  now.Add(-5 * 24 * time.Hour),
		},
	}
}

func getSampleJobs(agents []*db.Agent, targets []*db.BackupTarget) []*db.BackupJob {
	now := time.Now().UTC()
	return []*db.BackupJob{
		{
			ID:           sampleJobID1,
			Name:         "Daily Nginx & Web App Filesystem",
			AgentID:      sampleAgentID1,
			TargetID:     sampleTargetID1,
			AgentName:    "web-prod-01.internal",
			TargetName:   "Primary Proxmox Backup Server",
			ScheduleCron: "0 2 * * *",
			BackupPaths:  []string{"/var/www/html", "/etc/nginx", "/etc/ssl"},
			ExcludePaths: []string{"*.log", "/var/www/html/cache/*"},
			Enabled:      true,
			CreatedAt:    now.Add(-5 * 24 * time.Hour),
		},
		{
			ID:           sampleJobID2,
			Name:         "Hourly Database Dumps & Configs",
			AgentID:      sampleAgentID2,
			TargetID:     sampleTargetID1,
			AgentName:    "db-postgres-master.internal",
			TargetName:   "Primary Proxmox Backup Server",
			ScheduleCron: "0 * * * *",
			BackupPaths:  []string{"/var/lib/postgresql/data", "/etc/postgresql"},
			Enabled:      true,
			CreatedAt:    now.Add(-3 * 24 * time.Hour),
		},
	}
}

func getSampleRuns(jobs []*db.BackupJob, agents []*db.Agent) []*db.BackupRun {
	now := time.Now().UTC()
	start1 := now.Add(-45 * time.Minute)
	end1 := now.Add(-42 * time.Minute)

	start2 := now.Add(-10 * time.Minute)

	start3 := now.Add(-3 * time.Hour)
	end3 := now.Add(-2*time.Hour - 55*time.Minute)

	return []*db.BackupRun{
		{
			ID:            uuid.New(),
			JobID:         sampleJobID1,
			JobName:       "Daily Nginx & Web App Filesystem",
			AgentID:       sampleAgentID1,
			AgentName:     "web-prod-01.internal",
			TargetID:      sampleTargetID1,
			WorkflowID:    "backup-job-daily-web-10492",
			RunID:         "e10adc39-49ba-42e5-a35c-7d9a8c1f9b3a",
			Status:        db.RunStatusCompleted,
			StartTime:     &start1,
			EndTime:       &end1,
			BytesScanned:  18454938240, // ~18.45 GB
			BytesUploaded: 142084920,   // ~142 MB (due to PBS chunk dedup)
			DedupRatio:    129.88,
			ChunkCount:    1842,
			PBSSnapshotID: "host/web-prod-01/2026-08-24T14:30:00Z",
			CreatedAt:     start1,
		},
		{
			ID:            uuid.New(),
			JobID:         sampleJobID2,
			JobName:       "Hourly Database Dumps & Configs",
			AgentID:       sampleAgentID2,
			AgentName:     "db-postgres-master.internal",
			TargetID:      sampleTargetID1,
			WorkflowID:    "backup-job-hourly-db-10493",
			RunID:         "f29bd084-67fa-42e1-a71d-9e8c7b6a5d4e",
			Status:        db.RunStatusRunning,
			StartTime:     &start2,
			BytesScanned:  8589934592, // ~8 GB
			BytesUploaded: 2147483648, // ~2 GB
			DedupRatio:    4.00,
			ChunkCount:    850,
			CreatedAt:     start2,
		},
		{
			ID:            uuid.New(),
			JobID:         sampleJobID1,
			JobName:       "Daily Nginx & Web App Filesystem",
			AgentID:       sampleAgentID1,
			AgentName:     "web-prod-01.internal",
			TargetID:      sampleTargetID1,
			WorkflowID:    "backup-job-daily-web-10480",
			RunID:         "a394c8b2-10f8-4e89-8d76-1a2b3c4d5e6f",
			Status:        db.RunStatusCompleted,
			StartTime:     &start3,
			EndTime:       &end3,
			BytesScanned:  18420000000,
			BytesUploaded: 320000000,
			DedupRatio:    57.56,
			ChunkCount:    1839,
			PBSSnapshotID: "host/web-prod-01/2026-08-24T12:00:00Z",
			CreatedAt:     start3,
		},
	}
}

func getSampleTokens() []*db.EnrollmentToken {
	now := time.Now().UTC()
	return []*db.EnrollmentToken{
		{
			ID:        uuid.New(),
			Name:      "Production Host Onboarding Key",
			MaxUses:   5,
			UsesCount: 2,
			ExpiresAt: now.Add(7 * 24 * time.Hour),
			CreatedAt: now.Add(-2 * 24 * time.Hour),
		},
		{
			ID:        uuid.New(),
			Name:      "Database Worker Node Token",
			MaxUses:   1,
			UsesCount: 1,
			ExpiresAt: now.Add(24 * time.Hour),
			CreatedAt: now.Add(-6 * time.Hour),
		},
	}
}
