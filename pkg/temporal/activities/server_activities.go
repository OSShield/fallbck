package activities

import (
	"context"
	"fmt"
	"github.com/osshield/fallbck/pkg/dbbackup"
	"github.com/osshield/fallbck/pkg/dockerbackup"
	"github.com/osshield/fallbck/pkg/k8sbackup"
	"github.com/osshield/fallbck/pkg/m365"
	"github.com/osshield/fallbck/pkg/pvebackup"
	sdktemporal "go.temporal.io/sdk/temporal"
	"log/slog"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/osshield/fallbck/pkg/auth"
	"github.com/osshield/fallbck/pkg/config"
	"github.com/osshield/fallbck/pkg/db"
	"github.com/osshield/fallbck/pkg/temporal"
	"go.temporal.io/sdk/activity"
)

// ServerActivities provides activities executed on the central FallBCK server
type ServerActivities struct {
	DB           *db.DB
	Config       *config.ServerConfig
	TokenManager *auth.TokenManager
}

// NewServerActivities creates a new ServerActivities instance
func NewServerActivities(database *db.DB, cfg *config.ServerConfig, tm *auth.TokenManager) *ServerActivities {
	return &ServerActivities{
		DB:           database,
		Config:       cfg,
		TokenManager: tm,
	}
}

// PrepareBackupSession validates job parameters and generates a short-lived backup ticket
func (s *ServerActivities) PrepareBackupSession(ctx context.Context, jobID uuid.UUID) (*temporal.BackupSessionInfo, error) {
	info := activity.GetInfo(ctx)
	slog.Info("Preparing backup session for job", "job_id", jobID, "workflow_id", info.WorkflowExecution.ID)

	if s.DB == nil {
		// Mock session for dev/test mode
		return &temporal.BackupSessionInfo{
			JobID:          jobID,
			AgentID:        uuid.New(),
			TargetID:       uuid.New(),
			AgentTaskQueue: "fallbck-agent-dev",
			ProxyURL:       s.Config.ProxyURL(),
			Ticket:         "dev-mock-ticket",
			Datastore:      "backup-store",
			BackupType:     "host",
			BackupID:       "dev-host",
			BackupTime:     time.Now().Unix(),
			PxarFormat:     db.PxarFormatV1,
			BackupPaths:    []string{"/var/data"},
			WorkflowID:     info.WorkflowExecution.ID,
			RunID:          info.WorkflowExecution.RunID,
			BackupRunID:    uuid.New(),
		}, nil
	}

	job, err := s.DB.GetJobByID(ctx, jobID)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch job: %w", err)
	}

	agent, err := s.DB.GetAgentByID(ctx, job.AgentID)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch agent: %w", err)
	}

	target, err := s.DB.GetTargetByID(ctx, job.TargetID)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch backup target: %w", err)
	}

	// Generate short-lived backup ticket (2 hours TTL)
	now := time.Now().UTC()
	claims := auth.BackupTicketClaims{
		JobID:      job.ID,
		AgentID:    agent.ID,
		TargetID:   target.ID,
		Datastore:  target.Datastore,
		Namespace:  target.Namespace,
		BackupType: "host",
		BackupID:   job.EffectiveBackupID(),
		BackupTime: now.Unix(),
	}
	jobType, _ := db.NormalizeJobType(job.JobType)
	agentType, _ := db.NormalizeAgentType(agent.AgentType)
	if !db.JobAllowedOnAgent(jobType, agentType) {
		return nil, sdktemporal.NewNonRetryableApplicationError(
			fmt.Sprintf("job type %q cannot run on agent %s of type %q", jobType, agent.Hostname, agentType), "job_agent_mismatch", nil)
	}
	// The retired standalone database agent predates client-side encryption and would
	// upload plaintext to an encrypted target; refuse rather than silently downgrade
	if target.Encrypted() && agentType == db.AgentTypeDatabase {
		return nil, sdktemporal.NewNonRetryableApplicationError(
			fmt.Sprintf("target %s is encrypted but agent %s runs the retired database agent, which cannot encrypt; migrate it to fallbck-agent", target.Name, agent.Hostname), "job_agent_mismatch", nil)
	}
	var sessionSpec *dbbackup.Spec
	var k8sSpec *k8sbackup.Spec
	var pveSpec *pvebackup.Spec
	var dockerSpec *dockerbackup.Spec
	var m365Spec *m365.Spec
	passwordOnServer := false
	if jobType == db.JobTypeM365 {
		if job.M365Config == nil {
			return nil, sdktemporal.NewNonRetryableApplicationError("Microsoft 365 job has no configuration", "job_invalid", nil)
		}
		m365Spec = job.M365Config
		tenant, err := s.DB.GetTenantByID(ctx, m365Spec.TenantID)
		if err != nil {
			return nil, sdktemporal.NewNonRetryableApplicationError(
				fmt.Sprintf("the Microsoft 365 tenant of job %s no longer exists", job.Name), "job_invalid", nil)
		}
		// The job's own group holds the directory archive and the run manifest and is
		// the prefix every unit group (user, site, team) must extend (sub-tickets)
		claims.BackupID = m365Spec.BackupID
		if claims.BackupID == "" {
			claims.BackupID = m365.DefaultBackupID(tenant.Name)
		}
	}
	if jobType == db.JobTypeDocker {
		dockerSpec = job.DockerConfig
		if dockerSpec == nil {
			dockerSpec = &dockerbackup.Spec{}
		}
		// Definitions and volumes live in their own group next to the host's
		// filesystem backups (job.EffectiveBackupID adds the -docker suffix)
	}
	if jobType == db.JobTypePVE {
		pveSpec = job.PVEConfig
		if pveSpec == nil {
			pveSpec = &pvebackup.Spec{}
		}
		// The host configuration lives in its own group next to the host's filesystem
		// backups (job.EffectiveBackupID adds the -pve suffix)
	}
	if jobType == db.JobTypeKubernetes {
		if job.K8sConfig == nil {
			return nil, sdktemporal.NewNonRetryableApplicationError("kubernetes job has no configuration", "job_invalid", nil)
		}
		k8sSpec = job.K8sConfig
		// Kubernetes snapshots use the PBS "ct" (container) backup type; the group id
		// is the job's backup_id, volumes append -pvc-<ns>-<name>
		claims.BackupType = "ct"
	}
	if jobType == db.JobTypeDatabase {
		if job.DBConfig == nil {
			return nil, sdktemporal.NewNonRetryableApplicationError("database job has no database configuration", "job_invalid", nil)
		}
		claims.BackupID = dbbackup.DefaultBackupID(job.DBConfig)
		// The spec travels through Temporal history without the password; the agent
		// fetches it with its ticket when one is stored
		sessionSpec = job.DBConfig.Redacted()
		passwordOnServer = job.DBConfig.Password != ""
	}

	ticket, err := s.TokenManager.CreateBackupTicket(claims, 2*time.Hour)
	if err != nil {
		return nil, fmt.Errorf("failed to generate backup ticket: %w", err)
	}

	// Run record: the API creates a pending row when it starts the workflow; adopt it
	// (so cancellation and finalisation update the row the user sees), otherwise create one.
	var runID uuid.UUID
	if existing, err := s.DB.GetRunByWorkflowID(ctx, info.WorkflowExecution.ID); err == nil {
		runID = existing.ID
		if err := s.DB.MarkRunStarted(ctx, runID, info.WorkflowExecution.RunID, now); err != nil {
			slog.Warn("Failed to mark run as started", "error", err, "run_id", runID)
		}
	} else {
		runID = uuid.New()
		run := &db.BackupRun{
			ID:         runID,
			JobID:      job.ID,
			AgentID:    agent.ID,
			TargetID:   target.ID,
			WorkflowID: info.WorkflowExecution.ID,
			RunID:      info.WorkflowExecution.RunID,
			Status:     db.RunStatusRunning,
			StartTime:  &now,
		}
		if err := s.DB.CreateRun(ctx, run); err != nil {
			slog.Warn("Failed to create run record in database", "error", err)
		}
	}

	proxyURL := s.Config.ProxyURL()

	return &temporal.BackupSessionInfo{
		JobID:              job.ID,
		AgentID:            agent.ID,
		TargetID:           target.ID,
		AgentTaskQueue:     agent.TaskQueue,
		ProxyURL:           proxyURL,
		Ticket:             ticket,
		Datastore:          target.Datastore,
		Namespace:          target.Namespace,
		BackupType:         claims.BackupType,
		BackupID:           claims.BackupID,
		BackupTime:         claims.BackupTime,
		PxarFormat:         target.PxarFormat,
		DirectPBS:          job.DirectPBS,
		Encrypted:          target.Encrypted(),
		KeyFingerprint:     target.KeyFingerprint,
		JobType:            jobType,
		AgentType:          agentType,
		JobName:            job.Name,
		AgentHostname:      agent.Hostname,
		DBConfig:           sessionSpec,
		DBPasswordOnServer: passwordOnServer,
		K8sConfig:          k8sSpec,
		PVEConfig:          pveSpec,
		DockerConfig:       dockerSpec,
		M365Config:         m365Spec,
		BackupPaths:        job.BackupPaths,
		ExcludePaths:       job.ExcludePaths,
		WorkflowID:         info.WorkflowExecution.ID,
		RunID:              info.WorkflowExecution.RunID,
		BackupRunID:        runID,
	}, nil
}

// FinalizeBackupRun updates the backup run record in the database with results and deduplication metrics
func (s *ServerActivities) FinalizeBackupRun(ctx context.Context, session *temporal.BackupSessionInfo, result *temporal.BackupExecutionResult) error {
	slog.Info("Finalizing backup run", "run_id", session.BackupRunID, "status", result.Status, "dedup_ratio", result.DedupRatio)

	if s.DB == nil {
		return nil
	}

	now := time.Now().UTC()
	run := &db.BackupRun{
		ID:             session.BackupRunID,
		Status:         result.Status,
		EndTime:        &now,
		BytesScanned:   result.BytesScanned,
		BytesUploaded:  result.BytesUploaded,
		DedupRatio:     result.DedupRatio,
		ChunkCount:     result.ChunkCount,
		ErrorMessage:   result.ErrorMessage,
		PBSSnapshotID:  result.SnapshotID,
		LogTail:        truncateTail(result.LogTail, 16*1024),
		Details:        result.Details,
		KeyFingerprint: result.KeyFingerprint,
	}

	if err := s.DB.UpdateRun(ctx, run); err != nil {
		return fmt.Errorf("failed to update run status in database: %w", err)
	}

	return nil
}

// truncateTail keeps the last max bytes of a log tail (the newest lines matter most)
func truncateTail(s string, max int) string {
	if len(s) <= max {
		return s
	}
	cut := s[len(s)-max:]
	if i := strings.IndexByte(cut, '\n'); i >= 0 && i < len(cut)-1 {
		cut = cut[i+1:]
	}
	return cut
}
