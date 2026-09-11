package activities

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"sync"
	"time"

	"github.com/osshield/fallbck/pkg/agent/backup"
	k8sagent "github.com/osshield/fallbck/pkg/agent/k8sbackup"
	"github.com/osshield/fallbck/pkg/config"
	"github.com/osshield/fallbck/pkg/db"
	spec "github.com/osshield/fallbck/pkg/k8sbackup"
	"github.com/osshield/fallbck/pkg/proxy"
	"github.com/osshield/fallbck/pkg/rundetail"
	"github.com/osshield/fallbck/pkg/temporal"
	"github.com/osshield/gopbs"
	"github.com/osshield/gopbs/pbs"
	corev1 "k8s.io/api/core/v1"
	"log/slog"

	sdktemporal "go.temporal.io/sdk/temporal"
	"google.golang.org/grpc"
)

// K8sAgentActivities are the activities of fallbck-k8s-agent
type K8sAgentActivities struct {
	// Tunnel is the agent's gRPC connection to the FallBCK server (resources upload)
	Tunnel grpc.ClientConnInterface
	// Clients are the in-cluster API clients
	Clients *k8sagent.Clients
	// Config supplies the server URL / TLS settings handed to worker pods
	Config      *config.AgentConfig
	ClusterName string
	// AgentNamespace is the namespace the agent pod runs in
	AgentNamespace string
	Version        string
	// Worker pod parameters (from the Helm chart)
	WorkerImage               string
	WorkerImagePullPolicy     string
	WorkerResourcesJSON       string
	WorkerSecurityContextJSON string
	// WorkerMaxProcs bounds gopbs concurrency (GOMAXPROCS) inside worker pods; 0 = 2
	WorkerMaxProcs int
	// Credentials fetches PBS connection details for jobs in direct mode
	Credentials func(ctx context.Context, ticket string) (*backup.DirectOptions, error)
	// VolumeTicket mints a per-volume backup ticket from the session ticket; the
	// returned snapshot timestamp is the one embedded in the ticket (fresh per attempt)
	VolumeTicket func(ctx context.Context, sessionTicket, volumeBackupID string) (ticket string, backupTime int64, err error)
	// WorkerToken mints a short-lived agent bearer for worker pods
	WorkerToken func(ctx context.Context, sessionTicket string) (string, time.Time, error)
	// RefreshTicket re-issues the session ticket with a fresh snapshot timestamp when
	// the resources upload is retried; nil keeps the session's timestamp
	RefreshTicket TicketRefreshFunc
	// Database jobs assigned to this agent (dump pods): DBPassword fetches the job's
	// server-stored password; the per-engine image templates, pod resources/security
	// context and spool size come from the Helm chart; StateSecretName holds the
	// per-job chain state in the agent namespace
	DBPassword                  func(ctx context.Context, ticket string) (string, error)
	DBWorkerImages              map[string]string
	DBWorkerResourcesJSON       string
	DBWorkerSecurityContextJSON string
	DBWorkerSpoolSize           string
	StateSecretName             string
	// SpoolDir stages the resource dump (default <data dir>/spool)
	SpoolDir string
	// LogTail returns the agent's recent log output, attached to failures
	LogTail func() string
	// ReportProgress posts live phase / per-PVC updates to the server (best-effort)
	ReportProgress ProgressFunc

	// Runs tracks in-flight run ids for the orphan sweep. It lives in a named field:
	// worker.RegisterActivity(struct) validates every exported *method* of the struct,
	// so helpers must not be methods on K8sAgentActivities.
	Runs *RunTracker

	mu           sync.Mutex
	workerTokens map[string]workerToken // run id -> cached token
}

type workerToken struct {
	token   string
	expires time.Time
}

// RunTracker counts in-flight backup runs (consulted by the orphan sweep)
type RunTracker struct {
	mu   sync.Mutex
	runs map[string]int
}

// Active reports whether a run currently executes on this agent
func (t *RunTracker) Active(runID string) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.runs[runID] > 0
}

func (t *RunTracker) track(runID string) func() {
	t.mu.Lock()
	t.runs[runID]++
	t.mu.Unlock()
	return func() {
		t.mu.Lock()
		t.runs[runID]--
		if t.runs[runID] <= 0 {
			delete(t.runs, runID)
		}
		t.mu.Unlock()
	}
}

// NewK8sAgentActivities creates a new K8sAgentActivities instance
func NewK8sAgentActivities() *K8sAgentActivities {
	return &K8sAgentActivities{workerTokens: map[string]workerToken{}, Runs: &RunTracker{runs: map[string]int{}}}
}

func (a *K8sAgentActivities) k8sSpec(session *temporal.BackupSessionInfo) (*spec.Spec, error) {
	if session.JobType != db.JobTypeKubernetes || session.K8sConfig == nil {
		return nil, errors.New("session is not a kubernetes backup")
	}
	s := session.K8sConfig
	if err := s.Validate(); err != nil {
		return nil, err
	}
	return s, nil
}

// DiscoverKubernetesBackup plans the run: which volumes, snapshot or live per volume
func (a *K8sAgentActivities) DiscoverKubernetesBackup(ctx context.Context, session *temporal.BackupSessionInfo) (*spec.Plan, error) {
	pt := newPhaseTracker()
	stop := startHeartbeats(ctx, pt)
	defer stop()
	s, err := a.k8sSpec(session)
	if err != nil {
		return nil, sdktemporal.NewNonRetryableApplicationError(err.Error(), ErrTypeDBPrecheckFailed, err)
	}
	pt.Set("discovering volumes")
	plans, warnings, crd, err := k8sagent.PlanVolumes(ctx, a.Clients, s, session.BackupID)
	if err != nil {
		return nil, backupFailure(ctx, err, pt, a.LogTail)
	}
	plan := &spec.Plan{ClusterName: a.ClusterName, SnapshotCRD: crd, AgentNamespace: a.AgentNamespace, Volumes: plans, Warnings: warnings}
	if v, err := a.Clients.Discovery.ServerVersion(); err == nil && v != nil {
		plan.ServerVersion = v.GitVersion
	}
	// Seed the live per-PVC table so the detail page shows the plan immediately
	if len(plans) > 0 {
		items := make(map[string]rundetail.ProgressItem, len(plans))
		for _, v := range plans {
			it := rundetail.ProgressItem{Name: v.Namespace + "/" + v.PVCName, Kind: "pvc", Mode: v.Mode, Status: "pending"}
			if v.Mode == spec.ModeSkipped {
				it.Status, it.Note = "skipped", v.SkipReason
			}
			items[v.GroupID] = it
		}
		reportItems(a.ReportProgress, ctx, session.Ticket, session.BackupRunID, items)
	}
	reportPhase(a.ReportProgress, ctx, session.Ticket, session.BackupRunID, fmt.Sprintf("backing up %d volume(s)", len(plans)))
	slog.Info("Kubernetes backup planned", "cluster", a.ClusterName, "volumes", len(plans), "snapshot_crd", crd)
	return plan, nil
}

// cachedWorkerToken fetches (or reuses) the run's worker-pod bearer token
func (a *K8sAgentActivities) cachedWorkerToken(ctx context.Context, session *temporal.BackupSessionInfo) (string, error) {
	key := session.BackupRunID.String()
	a.mu.Lock()
	cached, ok := a.workerTokens[key]
	a.mu.Unlock()
	if ok && time.Until(cached.expires) > 30*time.Minute {
		return cached.token, nil
	}
	if a.WorkerToken == nil {
		return "", errors.New("agent has no worker-token fetcher")
	}
	token, expires, err := a.WorkerToken(ctx, session.Ticket)
	if err != nil {
		return "", fmt.Errorf("fetching worker token: %w", err)
	}
	a.mu.Lock()
	a.workerTokens[key] = workerToken{token: token, expires: expires}
	// Drop stale entries so long-lived agents do not accumulate them
	for k, v := range a.workerTokens {
		if time.Now().After(v.expires) {
			delete(a.workerTokens, k)
		}
	}
	a.mu.Unlock()
	return token, nil
}

// workerEnv assembles the worker pod's environment: credentials, session identity and
// transport settings. Everything is short-lived (2h ticket, 6h worker token).
func (a *K8sAgentActivities) workerEnv(ctx context.Context, session *temporal.BackupSessionInfo, groupID, volumeTicket string, backupTime int64) ([]corev1.EnvVar, error) {
	workerSession := *session
	workerSession.BackupID = groupID
	workerSession.Ticket = ""
	if backupTime > 0 {
		// The snapshot time the worker reports must match the ticket the tunnel opens
		// the PBS session with
		workerSession.BackupTime = backupTime
	}
	workerSession.K8sConfig = nil
	workerSession.BackupPaths = nil
	sessionJSON, err := jsonMarshal(workerSession)
	if err != nil {
		return nil, err
	}
	env := []corev1.EnvVar{
		{Name: k8sagent.EnvWorkerTicket, Value: volumeTicket},
		{Name: k8sagent.EnvWorkerSession, Value: sessionJSON},
	}
	// Bound gopbs upload concurrency so peak memory does not scale with the node's CPU
	// count (a common cause of worker OOMKills on large volumes)
	maxProcs := a.WorkerMaxProcs
	if maxProcs <= 0 {
		maxProcs = 2
	}
	env = append(env, corev1.EnvVar{Name: "GOMAXPROCS", Value: fmt.Sprintf("%d", maxProcs)})
	// Give workers the agent's log level (configured, or DEBUG env) so operators can
	// see gopbs connect/upload detail in the worker pod logs
	if lvl := a.Config.LogLevel; lvl != "" {
		env = append(env, corev1.EnvVar{Name: "FALLBCK_LOG_LEVEL", Value: lvl})
	}
	if dbg := os.Getenv("DEBUG"); dbg != "" {
		env = append(env, corev1.EnvVar{Name: "DEBUG", Value: dbg})
	}
	if session.DirectPBS {
		if a.Credentials == nil {
			return nil, errors.New("job requires direct PBS access but the agent has no credentials fetcher")
		}
		direct, err := a.Credentials(ctx, volumeTicket)
		if err != nil {
			return nil, fmt.Errorf("fetching PBS credentials for worker: %w", err)
		}
		directJSON, err := jsonMarshal(direct)
		if err != nil {
			return nil, err
		}
		env = append(env, corev1.EnvVar{Name: k8sagent.EnvWorkerPBSDirect, Value: directJSON})
		return env, nil
	}
	token, err := a.cachedWorkerToken(ctx, session)
	if err != nil {
		return nil, err
	}
	env = append(env,
		corev1.EnvVar{Name: k8sagent.EnvWorkerServerURL, Value: a.Config.ServerURL},
		corev1.EnvVar{Name: k8sagent.EnvWorkerToken, Value: token},
	)
	if a.Config.InsecureSkipVerify {
		env = append(env, corev1.EnvVar{Name: k8sagent.EnvWorkerInsecure, Value: "true"})
	}
	if a.Config.ServerCACertPath != "" {
		pem, err := os.ReadFile(a.Config.ServerCACertPath)
		if err != nil {
			return nil, fmt.Errorf("reading server CA for worker: %w", err)
		}
		env = append(env, corev1.EnvVar{Name: k8sagent.EnvWorkerServerCA, Value: string(pem)})
	}
	return env, nil
}

// BackupKubernetesVolume snapshots/mounts one PVC and uploads it from a worker pod
func (a *K8sAgentActivities) BackupKubernetesVolume(ctx context.Context, session *temporal.BackupSessionInfo, plan spec.VolumePlan) (*spec.VolumeResult, error) {
	pt := newPhaseTracker()
	stop := startHeartbeats(ctx, pt)
	defer stop()
	s, err := a.k8sSpec(session)
	if err != nil {
		return nil, sdktemporal.NewNonRetryableApplicationError(err.Error(), ErrTypeDBPrecheckFailed, err)
	}
	if plan.Mode == spec.ModeSkipped {
		return &spec.VolumeResult{Namespace: plan.Namespace, PVCName: plan.PVCName, GroupID: plan.GroupID, Mode: plan.Mode, Status: "skipped", Error: plan.SkipReason}, nil
	}
	untrack := a.Runs.track(session.BackupRunID.String())
	defer untrack()

	pvcName := plan.Namespace + "/" + plan.PVCName
	setItem := func(it rundetail.ProgressItem) {
		reportItems(a.ReportProgress, ctx, session.Ticket, session.BackupRunID, map[string]rundetail.ProgressItem{plan.GroupID: it})
	}
	setItem(rundetail.ProgressItem{Name: pvcName, Kind: "pvc", Mode: plan.Mode, Status: "running", Note: "starting"})
	stopVolProgress := startProgress(ctx, pt, 5*time.Second, func(phase string) {
		setItem(rundetail.ProgressItem{Name: pvcName, Kind: "pvc", Mode: plan.Mode, Status: "running", Note: phase})
	})
	reportResult := func(res *spec.VolumeResult) {
		stopVolProgress()
		if res == nil {
			return
		}
		setItem(rundetail.ProgressItem{Name: pvcName, Kind: "pvc", Mode: res.Mode, Consistency: res.Consistency,
			Status: res.Status, BytesUploaded: res.BytesUploaded, SnapshotID: res.SnapshotID, Error: res.Error})
	}
	defer stopVolProgress()

	pt.Set("preparing volume " + plan.Namespace + "/" + plan.PVCName)
	if a.VolumeTicket == nil {
		return nil, errors.New("agent has no volume-ticket fetcher")
	}
	ticket, backupTime, err := a.VolumeTicket(ctx, session.Ticket, plan.GroupID)
	if err != nil {
		return nil, backupFailure(ctx, fmt.Errorf("fetching volume ticket: %w", err), pt, a.LogTail)
	}
	env, err := a.workerEnv(ctx, session, plan.GroupID, ticket, backupTime)
	if err != nil {
		return nil, backupFailure(ctx, err, pt, a.LogTail)
	}

	res, err := k8sagent.BackupVolume(ctx, a.Clients, k8sagent.VolumeBackupRequest{
		Plan:              plan,
		RunID:             session.BackupRunID.String(),
		AgentID:           session.AgentID.String(),
		SnapshotTimeout:   s.Volumes.EffSnapshotTimeout(),
		VolumeTimeout:     s.Volumes.EffVolumeTimeout(),
		AllowLiveFallback: s.Volumes.EffAllowLiveFallback(),
		Worker: k8sagent.WorkerConfig{
			Image:               a.WorkerImage,
			ImagePullPolicy:     a.WorkerImagePullPolicy,
			ResourcesJSON:       a.WorkerResourcesJSON,
			SecurityContextJSON: a.WorkerSecurityContextJSON,
			Env:                 env,
		},
		Progress: pt.Set,
	})
	if err != nil {
		if res == nil {
			res = &spec.VolumeResult{Namespace: plan.Namespace, PVCName: plan.PVCName, GroupID: plan.GroupID, Mode: plan.Mode, Status: "failed", Error: err.Error()}
		}
		reportResult(res)
		slog.Error("Kubernetes volume backup failed", "pvc", plan.Namespace+"/"+plan.PVCName, "error", err, "phase", pt.Current())
		return res, backupFailure(ctx, err, pt, a.LogTail)
	}
	reportResult(res)
	return res, nil
}

// BackupKubernetesResources dumps every selected API resource and uploads it together
// with the run manifest (which embeds the per-volume outcomes; it runs last).
func (a *K8sAgentActivities) BackupKubernetesResources(ctx context.Context, session *temporal.BackupSessionInfo, plan *spec.Plan, volumes []spec.VolumeResult) (*temporal.BackupExecutionResult, error) {
	session = sessionForAttempt(ctx, session, a.RefreshTicket)
	pt := newPhaseTracker()
	stop := startHeartbeats(ctx, pt)
	defer stop()
	s, err := a.k8sSpec(session)
	if err != nil {
		return nil, sdktemporal.NewNonRetryableApplicationError(err.Error(), ErrTypeDBPrecheckFailed, err)
	}
	untrack := a.Runs.track(session.BackupRunID.String())
	defer untrack()
	reportResPhase := func() { reportPhase(a.ReportProgress, ctx, session.Ticket, session.BackupRunID, pt.Current()) }
	stopProgress := startProgress(ctx, pt, 5*time.Second, func(string) { reportResPhase() })
	defer stopProgress()

	spoolRoot := a.SpoolDir
	if spoolRoot == "" {
		spoolRoot = os.TempDir()
	}
	runDir := fmt.Sprintf("%s/%s", spoolRoot, session.BackupRunID)
	resourcesDir := runDir + "/" + spec.ResourcesArchiveName
	_ = os.RemoveAll(runDir)
	if err := os.MkdirAll(resourcesDir, 0o700); err != nil {
		return nil, fmt.Errorf("creating spool: %w", err)
	}
	defer os.RemoveAll(runDir)

	dumpedAt := time.Now().UTC()
	stats, err := k8sagent.DumpResources(ctx, a.Clients, s, resourcesDir, pt.Set)
	if err != nil {
		return nil, backupFailure(ctx, err, pt, a.LogTail)
	}

	manifest := &spec.Manifest{
		SchemaVersion: spec.ManifestSchemaVersion,
		Generator:     spec.ManifestGenerator{Agent: "fallbck-k8s-agent", Version: a.Version, Cluster: a.ClusterName},
		Job:           spec.ManifestJob{ID: session.JobID.String(), Name: session.JobName, RunID: session.RunID, BackupRunID: session.BackupRunID.String()},
		Snapshot: spec.ManifestSnapshot{
			Type: session.BackupType, ID: session.BackupID,
			Time: time.Unix(session.BackupTime, 0).UTC(), Archive: spec.ResourcesArchiveName + ".pxar.didx",
		},
		Kubernetes: spec.ManifestCluster{ServerVersion: plan.ServerVersion, SnapshotCRD: plan.SnapshotCRD},
		Spec:       s,
		Resources: spec.ManifestResources{
			DumpedAt: dumpedAt, Counts: stats.Counts, Excluded: stats.Excluded,
			FailedGroups: stats.FailedGroups, SecretsIncluded: s.IncludeSecrets(), Namespaces: stats.Namespaces,
		},
		Volumes:  volumes,
		Warnings: append(append([]string{}, plan.Warnings...), stats.Warnings...),
		Restore: spec.ManifestRestore{
			Summary: "Restore resources with kubectl apply in order: cluster/core/v1/namespaces, apiextensions.k8s.io CRDs, remaining cluster-scoped, then per namespace (secrets/configmaps/PVCs before workloads). Restore each volume's pvc.pxar from the group named per volume into a pod mounting the recreated PVC.",
			Commands: []string{
				fmt.Sprintf("proxmox-backup-client restore %s/%s/<time> %s.pxar ./resources", session.BackupType, session.BackupID, spec.ResourcesArchiveName),
				fmt.Sprintf("proxmox-backup-client restore %s/<volume group>/<time> %s.pxar ./pvc-data   # groups listed under volumes[]", session.BackupType, spec.VolumeArchiveName),
			},
		},
	}
	if manifest.Volumes == nil {
		manifest.Volumes = []spec.VolumeResult{}
	}
	data, err := manifest.Marshal()
	if err != nil {
		return nil, fmt.Errorf("encoding manifest: %w", err)
	}
	if err := os.WriteFile(resourcesDir+"/"+spec.ManifestFileName, data, 0o600); err != nil {
		return nil, fmt.Errorf("writing manifest: %w", err)
	}

	uploadSession := *session
	uploadSession.BackupPaths = []string{resourcesDir}
	uploadSession.ExcludePaths = nil
	opts := backup.Options{Session: &uploadSession, ArchiveName: spec.ResourcesArchiveName, OnPhase: pt.Set,
		Blobs: []gopbs.Blob{{Name: spec.ManifestBlobName, Data: data}}}
	if session.DirectPBS {
		if a.Credentials == nil {
			return nil, errors.New("job requires direct PBS access but the agent has no credentials fetcher")
		}
		direct, err := a.Credentials(ctx, session.Ticket)
		if err != nil {
			return nil, backupFailure(ctx, err, pt, a.LogTail)
		}
		opts.Direct = direct
	} else {
		if a.Tunnel == nil {
			return nil, errors.New("agent tunnel connection is not configured")
		}
		opts.Dial = func(ctx context.Context, _ pbs.SnapshotRef) (net.Conn, error) {
			return proxy.Dial(ctx, a.Tunnel, session.Ticket)
		}
	}
	result, err := backup.Run(ctx, opts)
	if err != nil {
		slog.Error("Kubernetes resource backup failed", "error", err, "phase", pt.Current())
		return nil, backupFailure(ctx, err, pt, a.LogTail)
	}
	// The manifest already carries per-volume results, resource counts, warnings and
	// the restore runbook — surface all of it on the run detail page.
	result.Details = rundetail.WrapManifest(rundetail.TypeKubernetes, data)
	return result, nil
}

func jsonMarshal(v any) (string, error) {
	data, err := jsonEncode(v)
	return string(data), err
}
