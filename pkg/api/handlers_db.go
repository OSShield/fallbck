package api

import (
	"context"
	"errors"
	"log/slog"
	"net/http"

	"github.com/google/uuid"
	"github.com/osshield/fallbck/pkg/auth"
	"github.com/osshield/fallbck/pkg/db"
	"github.com/osshield/fallbck/pkg/dbbackup"
	"github.com/osshield/fallbck/pkg/dockerbackup"
	"github.com/osshield/fallbck/pkg/pvebackup"
)

// DBCredentials hands an agent the server-stored database password for a run
type DBCredentials struct {
	Password string `json:"password"`
}

// validateJob checks a job create/update request: required fields, the agent and
// target exist, the job type matches the agent type, and the type-specific
// configuration is valid. existing (updates only) supplies the stored password when
// the request leaves it blank. It returns the message to show the client.
func (s *ServerAPI) validateJob(ctx context.Context, job *db.BackupJob, existing *db.BackupJob) (string, error) {
	if job.Name == "" || job.AgentID == uuid.Nil || job.TargetID == uuid.Nil {
		return "Name, AgentID, and TargetID are required", errors.New("missing fields")
	}
	jobType, ok := db.NormalizeJobType(job.JobType)
	if !ok {
		return "Unknown job type " + job.JobType, errors.New("bad job type")
	}
	job.JobType = jobType
	if err := db.ValidateCron(job.ScheduleCron); err != nil {
		return err.Error(), err
	}

	// The agent type decides which shape a database job may take (a kubernetes agent
	// needs the in-cluster target settings), so look it up before the per-type checks
	agentType := jobType
	var agent *db.Agent
	if s.DB != nil {
		a, err := s.DB.GetAgentByID(ctx, job.AgentID)
		if err != nil {
			return "Agent not found", err
		}
		agent = a
		agentType, _ = db.NormalizeAgentType(agent.AgentType)
	}

	switch jobType {
	case db.JobTypeM365:
		if len(job.BackupPaths) > 0 {
			return "Microsoft 365 jobs do not take backup paths", errors.New("paths on m365 job")
		}
		if job.DBConfig != nil || job.K8sConfig != nil || job.PVEConfig != nil || job.DockerConfig != nil {
			return "Microsoft 365 jobs take m365_config only", errors.New("foreign config on m365 job")
		}
		if job.M365Config == nil {
			return "Microsoft 365 jobs require m365_config", errors.New("missing m365_config")
		}
		if err := job.M365Config.Validate(); err != nil {
			return err.Error(), err
		}
		if s.DB != nil {
			if _, err := s.DB.GetTenantByID(ctx, job.M365Config.TenantID); err != nil {
				return "Microsoft 365 tenant not found", err
			}
		}
	case db.JobTypeDocker:
		if len(job.BackupPaths) > 0 {
			return "Docker host jobs do not take backup paths", errors.New("paths on docker job")
		}
		if job.DBConfig != nil || job.K8sConfig != nil || job.PVEConfig != nil {
			return "Docker host jobs do not take db_config, k8s_config or pve_config", errors.New("foreign config on docker job")
		}
		if job.DockerConfig == nil {
			job.DockerConfig = &dockerbackup.Spec{}
		}
		if err := job.DockerConfig.Validate(); err != nil {
			return err.Error(), err
		}
		if agent != nil && !agent.DockerHost {
			return "Agent " + agent.Hostname + " has not reported a reachable Docker daemon (install the agent on the Docker host, as root or with the socket mounted, and wait for its next heartbeat)", errors.New("agent not a docker host")
		}
	case db.JobTypePVE:
		if len(job.BackupPaths) > 0 {
			return "Proxmox VE jobs do not take backup paths (add data paths in the PVE settings)", errors.New("paths on pve job")
		}
		if job.DBConfig != nil || job.K8sConfig != nil {
			return "Proxmox VE jobs do not take db_config or k8s_config", errors.New("foreign config on pve job")
		}
		if job.PVEConfig == nil {
			job.PVEConfig = &pvebackup.Spec{}
		}
		if err := job.PVEConfig.Validate(); err != nil {
			return err.Error(), err
		}
		if agent != nil && !agent.PVEHost {
			return "Agent " + agent.Hostname + " has not reported itself as a Proxmox VE host (install the agent on the PVE node and wait for its next heartbeat)", errors.New("agent not a pve host")
		}
	case db.JobTypeKubernetes:
		if len(job.BackupPaths) > 0 {
			return "Kubernetes jobs do not take backup paths", errors.New("paths on k8s job")
		}
		if job.DBConfig != nil {
			return "Kubernetes jobs do not take db_config", errors.New("db_config on k8s job")
		}
		if job.K8sConfig == nil {
			return "Kubernetes jobs require k8s_config", errors.New("missing k8s_config")
		}
		if err := job.K8sConfig.Validate(); err != nil {
			return err.Error(), err
		}
	case db.JobTypeDatabase:
		if len(job.BackupPaths) > 0 {
			return "Database jobs do not take backup paths", errors.New("paths on db job")
		}
		if job.DBConfig == nil {
			return "Database jobs require db_config", errors.New("missing db_config")
		}
		if job.DBConfig.ClearPassword {
			job.DBConfig.Password = ""
		} else if job.DBConfig.Password == "" && existing != nil && existing.DBConfig != nil {
			job.DBConfig.Password = existing.DBConfig.Password
		}
		job.DBConfig.ClearPassword = false
		job.DBConfig.HasPassword = false
		if agent != nil {
			if engine, ok := dbbackup.NormalizeEngine(job.DBConfig.Engine); ok && !agent.CanRunDBEngine(engine) {
				if engine == dbbackup.EngineMSSQL {
					return "Agent " + agent.Hostname + " cannot run SQL Server jobs: they need fallbck-agent (not a kubernetes or legacy database agent) in a version that reports the mssql engine", errors.New("agent without mssql engine")
				}
				return "Agent " + agent.Hostname + " has not reported the " + engine + " client tools (install them on the host and wait for its next heartbeat, or run fallbck-agent tools)", errors.New("agent without db engine")
			}
		}
		if agentType == db.AgentTypeKubernetes && job.DBConfig.Kubernetes == nil {
			return "Database jobs on a kubernetes agent need the kubernetes target settings (namespace and service)", errors.New("missing kubernetes target")
		}
		if agentType != db.AgentTypeKubernetes && job.DBConfig.Kubernetes != nil {
			return "Kubernetes target settings require a kubernetes agent", errors.New("kubernetes target on non-k8s agent")
		}
		if err := job.DBConfig.Validate(); err != nil {
			return err.Error(), err
		}
	default:
		if job.DBConfig != nil {
			return "Filesystem jobs do not take db_config", errors.New("db_config on filesystem job")
		}
		if job.K8sConfig != nil {
			return "Filesystem jobs do not take k8s_config", errors.New("k8s_config on filesystem job")
		}
		if job.PVEConfig != nil {
			return "Filesystem jobs do not take pve_config", errors.New("pve_config on filesystem job")
		}
		if job.DockerConfig != nil {
			return "Filesystem jobs do not take docker_config", errors.New("docker_config on filesystem job")
		}
		if job.M365Config != nil {
			return "Filesystem jobs do not take m365_config", errors.New("m365_config on filesystem job")
		}
		agentOS := ""
		if agent != nil {
			agentOS = agent.OS
		}
		paths, err := db.ValidateBackupPathsFor(agentOS, job.BackupPaths)
		if err != nil {
			return err.Error(), err
		}
		job.BackupPaths = paths
		if err := db.ValidateExcludePatterns(job.ExcludePaths); err != nil {
			return err.Error(), err
		}
	}

	if s.DB == nil {
		return "", nil
	}
	if !db.JobAllowedOnAgent(jobType, agentType) {
		return "Agent " + agent.Hostname + " is a " + agentType + " agent and cannot run " + jobType + " jobs", errors.New("agent type mismatch")
	}
	if _, err := s.DB.GetTargetByID(ctx, job.TargetID); err != nil {
		return "Backup target not found", err
	}
	return "", nil
}

// HandleDBCredentials hands a database agent the password stored on a database job for
// the run identified by its backup ticket. Like HandlePBSCredentials, the ticket must
// have been issued to the calling agent.
func (s *ServerAPI) HandleDBCredentials(w http.ResponseWriter, r *http.Request) {
	agent := auth.AgentFrom(r.Context())
	if agent == nil {
		s.writeError(w, http.StatusUnauthorized, "agent token required")
		return
	}
	ticket := r.Header.Get(BackupTicketHeader)
	if ticket == "" {
		s.writeError(w, http.StatusBadRequest, "backup ticket header required")
		return
	}
	claims, err := s.TokenManager.ValidateBackupTicket(ticket)
	if err != nil {
		s.writeError(w, http.StatusUnauthorized, "invalid or expired backup ticket")
		return
	}
	if claims.AgentID != agent.AgentID {
		slog.Warn("Database credential request with another agent's ticket", "agent_id", agent.AgentID, "ticket_agent_id", claims.AgentID)
		s.writeError(w, http.StatusForbidden, "backup ticket was not issued to this agent")
		return
	}
	job, err := s.DB.GetJobByID(r.Context(), claims.JobID)
	if err != nil {
		s.writeError(w, http.StatusNotFound, "job not found")
		return
	}
	if !job.IsDatabase() || job.DBConfig == nil {
		s.writeError(w, http.StatusForbidden, "job is not a database job")
		return
	}
	if job.DBConfig.Password == "" {
		s.writeError(w, http.StatusNotFound, "job stores no password; the agent must use a credential profile")
		return
	}
	slog.Info("Handing database credentials to agent", "agent_id", agent.AgentID, "job_id", job.ID, "engine", job.DBConfig.Engine, "user", job.DBConfig.User)
	s.writeJSON(w, http.StatusOK, DBCredentials{Password: job.DBConfig.Password})
}

// syncJobSchedule aligns the job's Temporal Schedule after a create/update; failures
// only warn — the job is saved and the startup reconcile repairs the schedule.
func (s *ServerAPI) syncJobSchedule(ctx context.Context, job *db.BackupJob) {
	if s.Scheduler == nil {
		return
	}
	if err := s.Scheduler.Sync(ctx, job); err != nil {
		slog.Warn("Backup schedule could not be synced; the startup reconcile will retry", "job_id", job.ID, "error", err)
	}
}
