package k8sbackup

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	dbspec "github.com/osshield/fallbck/pkg/dbbackup"
	"github.com/osshield/fallbck/pkg/temporal"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// DBWorkerConfig describes the dump pod the agent spawns for a database job
type DBWorkerConfig struct {
	// Image is the engine's client-tools image (postgres:17, mariadb:11, mongo:7, …)
	Image string
	// AgentImage supplies the fallbck-k8s-agent binary through an init container
	AgentImage      string
	ImagePullPolicy string
	// Resources / SecurityContext are corev1 JSON blobs from the Helm chart (optional)
	ResourcesJSON       string
	SecurityContextJSON string
	// SpoolSizeLimit bounds the spool emptyDir (Kubernetes quantity; "" = unbounded)
	SpoolSizeLimit string
	// Env carries the worker credentials, session and previous state
	Env []corev1.EnvVar
}

// DBBackupRequest is one database job's dump order
type DBBackupRequest struct {
	Namespace string
	// BackupID is the PBS group (used for the deterministic pod name)
	BackupID string
	RunID    string
	AgentID  string
	Timeout  time.Duration
	Worker   DBWorkerConfig
	Progress func(phase string)
}

// DBBackupOutcome is what the dump pod reported
type DBBackupOutcome struct {
	Result *temporal.BackupExecutionResult
	// State is the chain state to persist for the next run (nil when unchanged)
	State *dbspec.JobState
	// Precheck marks a configuration/environment failure a retry cannot fix
	Precheck bool
}

// binaryMount is where the init container places the agent binary for the main container
const (
	binaryMount = "/fallbck"
	spoolMount  = "/spool"
)

// BackupDatabase runs the dump pod and returns its outcome. The pod is labeled and
// deleted on every path.
func BackupDatabase(ctx context.Context, c *Clients, req DBBackupRequest) (*DBBackupOutcome, error) {
	progress := req.Progress
	if progress == nil {
		progress = func(string) {}
	}
	name := baseName(req.RunID, req.Namespace, "db:"+req.BackupID)
	labels := map[string]string{labelManagedBy: labelValue, labelRunID: req.RunID, labelAgentID: req.AgentID}
	cleanup := newCleanup(c, req.Namespace)
	defer cleanup.run()

	progress("dumping " + req.BackupID)
	if err := createEnvSecret(ctx, c, req.Namespace, name, labels, req.Worker.Env); err != nil {
		return nil, err
	}
	cleanup.secret = name
	pod := dbWorkerPod(name, req.Namespace, labels, req.Worker)
	if _, err := c.Core.CoreV1().Pods(req.Namespace).Create(ctx, pod, metav1.CreateOptions{}); err != nil {
		return nil, fmt.Errorf("creating dump pod for %s: %w", req.BackupID, err)
	}
	cleanup.pod = name

	outcome, err := superviseWorker(ctx, c, req.Namespace, name, req.Timeout)
	if err != nil {
		return nil, err
	}
	out := &DBBackupOutcome{Result: outcome.Result, State: outcome.State, Precheck: outcome.Precheck}
	if outcome.Error != "" || outcome.Result == nil {
		msg := outcome.Error
		if msg == "" {
			msg = "dump pod reported no result"
		}
		if outcome.Phase != "" {
			msg += " [phase: " + outcome.Phase + "]"
		}
		return out, fmt.Errorf("database %s: %s", req.BackupID, truncate(msg, maxVolumeErrorBytes))
	}
	return out, nil
}

// dbWorkerPod builds the dump pod: an init container copies this agent's binary into
// an emptyDir, the main container runs it in db-worker mode on the engine image.
func dbWorkerPod(name, ns string, labels map[string]string, w DBWorkerConfig) *corev1.Pod {
	no := false
	yes := true
	rootUser := int64(0)
	// The engine images expect root (or their own user); the dump only needs the
	// client tools and network, so drop every capability and keep the rootfs read-only
	secCtx := &corev1.SecurityContext{
		RunAsUser:                &rootUser,
		AllowPrivilegeEscalation: &no,
		ReadOnlyRootFilesystem:   &yes,
		Capabilities:             &corev1.Capabilities{Drop: []corev1.Capability{"ALL"}},
	}
	if w.SecurityContextJSON != "" {
		var override corev1.SecurityContext
		if err := json.Unmarshal([]byte(w.SecurityContextJSON), &override); err == nil {
			secCtx = &override
		}
	}
	var resources corev1.ResourceRequirements
	if w.ResourcesJSON != "" {
		_ = json.Unmarshal([]byte(w.ResourcesJSON), &resources)
	}
	spool := &corev1.EmptyDirVolumeSource{}
	if w.SpoolSizeLimit != "" {
		if q, err := resource.ParseQuantity(w.SpoolSizeLimit); err == nil {
			spool.SizeLimit = &q
		}
	}
	// Only the harmless fixed values live in Pod.spec; w.Env (credentials, ticket)
	// comes from the per-run Secret named like the pod
	env := []corev1.EnvVar{
		{Name: EnvWorkerSpool, Value: spoolMount},
		{Name: "HOME", Value: "/tmp"},
		{Name: "TMPDIR", Value: "/tmp"},
	}
	binary := binaryMount + "/fallbck-k8s-agent"
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns, Labels: labels},
		Spec: corev1.PodSpec{
			RestartPolicy:                corev1.RestartPolicyNever,
			AutomountServiceAccountToken: &no,
			InitContainers: []corev1.Container{{
				Name:            "fallbck-binary",
				Image:           w.AgentImage,
				ImagePullPolicy: pullPolicy(w.ImagePullPolicy),
				Command:         []string{"cp", "/usr/local/bin/fallbck-k8s-agent", binary},
				SecurityContext: &corev1.SecurityContext{AllowPrivilegeEscalation: &no, Capabilities: &corev1.Capabilities{Drop: []corev1.Capability{"ALL"}}},
				VolumeMounts:    []corev1.VolumeMount{{Name: "fallbck", MountPath: binaryMount}},
			}},
			Containers: []corev1.Container{{
				Name:                     "worker",
				Image:                    w.Image,
				ImagePullPolicy:          pullPolicy(w.ImagePullPolicy),
				Command:                  []string{binary},
				Args:                     []string{"db-worker"},
				Env:                      env,
				EnvFrom:                  envFromSecret(name),
				Resources:                resources,
				SecurityContext:          secCtx,
				TerminationMessagePolicy: corev1.TerminationMessageReadFile,
				VolumeMounts: []corev1.VolumeMount{
					{Name: "fallbck", MountPath: binaryMount, ReadOnly: true},
					{Name: "spool", MountPath: spoolMount},
					{Name: "tmp", MountPath: "/tmp"},
				},
			}},
			Volumes: []corev1.Volume{
				{Name: "fallbck", VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{}}},
				{Name: "spool", VolumeSource: corev1.VolumeSource{EmptyDir: spool}},
				{Name: "tmp", VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{}}},
			},
		},
	}
}

// DefaultDBWorkerImages are the per-engine image templates; {major} is replaced with
// the server's detected major version (or "latest" when unknown). MySQL jobs pick
// "mysql" or "mariadb" by the server flavor.
var DefaultDBWorkerImages = map[string]string{
	"postgres": "postgres:{major}",
	"mysql":    "mysql:{major}",
	"mariadb":  "mariadb:{major}",
	"mongodb":  "mongo:{major}",
}

// RenderDBWorkerImage picks the dump pod image for an engine: the job override, else
// the template for the engine (or flavor) with the major version filled in
func RenderDBWorkerImage(override string, templates map[string]string, engine, flavor string, major int) string {
	if override != "" {
		return override
	}
	key := engine
	if flavor != "" {
		if _, ok := templates[flavor]; ok {
			key = flavor
		} else if _, ok := DefaultDBWorkerImages[flavor]; ok {
			key = flavor
		}
	}
	tpl, ok := templates[key]
	if !ok || tpl == "" {
		tpl = DefaultDBWorkerImages[key]
	}
	if tpl == "" {
		tpl = DefaultDBWorkerImages[engine]
	}
	tag := "latest"
	if major > 0 {
		tag = fmt.Sprintf("%d", major)
	}
	return strings.ReplaceAll(tpl, "{major}", tag)
}
