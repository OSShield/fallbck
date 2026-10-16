package k8sbackup

import (
	"context"
	"encoding/json"
	"fmt"
	"hash/crc32"
	"io"
	"log/slog"
	"strings"
	"time"

	dbspec "github.com/osshield/fallbck/pkg/dbbackup"
	spec "github.com/osshield/fallbck/pkg/k8sbackup"
	"github.com/osshield/fallbck/pkg/temporal"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// Labels stamped on every object the agent creates (worker pods, clone PVCs, snapshots)
const (
	labelManagedBy = "app.kubernetes.io/managed-by"
	labelValue     = "fallbck"
	labelRunID     = "fallbck.io/run-id"
	labelAgentID   = "fallbck.io/agent-id"
)

// pollInterval paces pod/snapshot polling (overridden in tests)
var pollInterval = 5 * time.Second

// unschedulableGrace fails a worker pod that cannot be scheduled early
var unschedulableGrace = 5 * time.Minute

// WorkerConfig describes the worker pod the agent spawns per volume
type WorkerConfig struct {
	Image string
	// ImagePullPolicy for worker pods (default IfNotPresent; ":latest" would otherwise
	// imply Always and break air-gapped/preloaded images)
	ImagePullPolicy string
	// Resources / SecurityContext are corev1 JSON blobs from the Helm chart (optional)
	ResourcesJSON       string
	SecurityContextJSON string
	// Env carries the worker credentials and session (built by the activity)
	Env []corev1.EnvVar
}

// VolumeBackupRequest is one volume's backup order
type VolumeBackupRequest struct {
	Plan              spec.VolumePlan
	RunID             string
	AgentID           string
	SnapshotTimeout   time.Duration
	VolumeTimeout     time.Duration
	AllowLiveFallback bool
	Worker            WorkerConfig
	Progress          func(phase string)
}

// workerOutcome is the worker pod's termination message
type workerOutcome struct {
	Result *temporal.BackupExecutionResult `json:"result,omitempty"`
	Error  string                          `json:"error,omitempty"`
	Phase  string                          `json:"phase,omitempty"`
	// State is the database job's chain state after a successful dump (db-worker)
	State *dbspec.JobState `json:"state,omitempty"`
	// Precheck marks a configuration failure a retry cannot fix (db-worker)
	Precheck bool `json:"precheck,omitempty"`
	// DetailsInLog: the full outcome exceeded the termination-message cap and was
	// written to the pod log instead (see outcomeLogMarker)
	DetailsInLog bool `json:"details_in_log,omitempty"`
}

// baseName builds the deterministic per-volume object name: fb-<run8>-<crc32(ns/pvc)>
func baseName(runID, ns, pvc string) string {
	run := strings.ReplaceAll(runID, "-", "")
	if len(run) > 8 {
		run = run[:8]
	}
	return fmt.Sprintf("fb-%s-%08x", run, crc32.ChecksumIEEE([]byte(ns+"/"+pvc)))
}

// BackupVolume executes one volume backup: snapshot → clone → worker pod (or a live
// read-only mount), returning the worker's result. All created objects are labeled and
// cleaned up on every path.
func BackupVolume(ctx context.Context, c *Clients, req VolumeBackupRequest) (*spec.VolumeResult, error) {
	progress := req.Progress
	if progress == nil {
		progress = func(string) {}
	}
	plan := req.Plan
	start := time.Now()
	res := &spec.VolumeResult{Namespace: plan.Namespace, PVCName: plan.PVCName, GroupID: plan.GroupID, Mode: plan.Mode}
	if plan.Mode == spec.ModeSkipped {
		res.Status = "skipped"
		res.Error = plan.SkipReason
		return res, nil
	}

	name := baseName(req.RunID, plan.Namespace, plan.PVCName)
	labels := map[string]string{labelManagedBy: labelValue, labelRunID: req.RunID, labelAgentID: req.AgentID}
	cleanup := newCleanup(c, plan.Namespace)
	defer cleanup.run()

	mountPVC := plan.PVCName
	readOnlyMount := true
	nodeName := ""

	if plan.Mode == spec.ModeSnapshot {
		progress("snapshotting " + plan.Namespace + "/" + plan.PVCName)
		err := createSnapshot(ctx, c, plan, name, labels)
		if err == nil {
			cleanup.snapshot = name
			err = waitSnapshotReady(ctx, c, plan.Namespace, name, req.SnapshotTimeout)
		}
		if err != nil {
			if req.AllowLiveFallback {
				slog.Warn("Volume snapshot failed; falling back to a live mount", "pvc", plan.Namespace+"/"+plan.PVCName, "error", err)
				res.Mode = spec.ModeLive
				plan.Mode = spec.ModeLive
				cleanup.run() // remove the failed snapshot before continuing
				cleanup = newCleanup(c, plan.Namespace)
				defer cleanup.run()
			} else {
				res.Status = "failed"
				res.Error = err.Error()
				return res, fmt.Errorf("snapshotting %s/%s: %w", plan.Namespace, plan.PVCName, err)
			}
		} else {
			progress("cloning snapshot of " + plan.Namespace + "/" + plan.PVCName)
			if err := createClonePVC(ctx, c, plan, name, labels); err != nil {
				res.Status = "failed"
				res.Error = err.Error()
				return res, fmt.Errorf("cloning %s/%s: %w", plan.Namespace, plan.PVCName, err)
			}
			cleanup.pvc = name
			mountPVC = name
			readOnlyMount = false // freshly cloned, nothing else mounts it; RO remount quirks vary by driver
		}
	}

	if plan.Mode == spec.ModeLive {
		res.Consistency = "crash-consistent-live"
		// An attached RWO volume is only mountable on the node it is attached to, so the
		// worker must land there; a wrong node would fail with a multi-attach error.
		if isRWO(ctx, c, plan) {
			if node := attachedNode(ctx, c, plan.Namespace, plan.PVCName, plan.PVName); node != "" {
				nodeName = node
			} else {
				slog.Info("Could not determine the node of a live RWO volume; scheduling the worker unpinned (may fail if the volume is attached elsewhere)",
					"pvc", plan.Namespace+"/"+plan.PVCName)
			}
		}
	} else {
		res.Consistency = "csi-snapshot"
	}

	progress("uploading " + plan.Namespace + "/" + plan.PVCName)
	if err := createEnvSecret(ctx, c, plan.Namespace, name, labels, req.Worker.Env); err != nil {
		res.Status = "failed"
		res.Error = err.Error()
		return res, err
	}
	cleanup.secret = name
	pod := workerPod(name, plan.Namespace, mountPVC, readOnlyMount, nodeName, labels, req.Worker)
	if _, err := c.Core.CoreV1().Pods(plan.Namespace).Create(ctx, pod, metav1.CreateOptions{}); err != nil {
		res.Status = "failed"
		res.Error = err.Error()
		return res, fmt.Errorf("creating worker pod for %s/%s: %w", plan.Namespace, plan.PVCName, err)
	}
	cleanup.pod = name

	outcome, err := superviseWorker(ctx, c, plan.Namespace, name, req.VolumeTimeout)
	res.DurationMS = time.Since(start).Milliseconds()
	if err != nil {
		res.Status = "failed"
		res.Error = err.Error()
		return res, err
	}
	if outcome.Error != "" || outcome.Result == nil {
		res.Status = "failed"
		res.Error = outcome.Error
		if res.Error == "" {
			res.Error = "worker pod reported no result"
		}
		if outcome.Phase != "" {
			res.Error += " [phase: " + outcome.Phase + "]"
		}
		res.Error = truncate(res.Error, maxVolumeErrorBytes)
		return res, fmt.Errorf("volume %s/%s: %s", plan.Namespace, plan.PVCName, res.Error)
	}
	res.Status = "completed"
	res.SnapshotID = outcome.Result.SnapshotID
	res.BytesScanned = outcome.Result.BytesScanned
	res.BytesUploaded = outcome.Result.BytesUploaded
	res.ChunkCount = outcome.Result.ChunkCount
	res.DedupRatio = outcome.Result.DedupRatio
	return res, nil
}

// ---- snapshot / clone -------------------------------------------------------

func createSnapshot(ctx context.Context, c *Clients, plan spec.VolumePlan, name string, labels map[string]string) error {
	snap := &unstructured.Unstructured{Object: map[string]interface{}{
		"apiVersion": "snapshot.storage.k8s.io/v1",
		"kind":       "VolumeSnapshot",
		"metadata":   map[string]interface{}{"name": name, "namespace": plan.Namespace, "labels": toAny(labels)},
		"spec": map[string]interface{}{
			"volumeSnapshotClassName": plan.SnapshotClass,
			"source":                  map[string]interface{}{"persistentVolumeClaimName": plan.PVCName},
		},
	}}
	_, err := c.Dynamic.Resource(snapshotGVR).Namespace(plan.Namespace).Create(ctx, snap, metav1.CreateOptions{})
	return err
}

func waitSnapshotReady(ctx context.Context, c *Clients, ns, name string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for {
		snap, err := c.Dynamic.Resource(snapshotGVR).Namespace(ns).Get(ctx, name, metav1.GetOptions{})
		if err == nil {
			if ready, ok, _ := unstructuredBool(snap.Object, "status", "readyToUse"); ok && ready {
				return nil
			}
			if msg, ok, _ := unstructuredString(snap.Object, "status", "error", "message"); ok && msg != "" {
				return fmt.Errorf("snapshot error: %s", msg)
			}
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("snapshot not ready after %s (is the snapshot controller running?)", timeout)
		}
		select {
		case <-ctx.Done():
			return context.Cause(ctx)
		case <-time.After(pollInterval):
		}
	}
}

func createClonePVC(ctx context.Context, c *Clients, plan spec.VolumePlan, name string, labels map[string]string) error {
	apiGroup := "snapshot.storage.k8s.io"
	size := plan.CapacityBytes
	if size <= 0 {
		size = 1 << 30
	}
	// The clone must be at least the snapshot's restore size; the source capacity is
	// always sufficient
	if snap, err := c.Dynamic.Resource(snapshotGVR).Namespace(plan.Namespace).Get(ctx, name, metav1.GetOptions{}); err == nil {
		if rs, ok, _ := unstructuredString(snap.Object, "status", "restoreSize"); ok && rs != "" {
			if q, err := resource.ParseQuantity(rs); err == nil && q.Value() > size {
				size = q.Value()
			}
		}
	}
	sc := plan.StorageClass
	pvc := &corev1.PersistentVolumeClaim{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: plan.Namespace, Labels: labels},
		Spec: corev1.PersistentVolumeClaimSpec{
			AccessModes:      []corev1.PersistentVolumeAccessMode{corev1.ReadWriteOnce},
			StorageClassName: &sc,
			DataSource:       &corev1.TypedLocalObjectReference{APIGroup: &apiGroup, Kind: "VolumeSnapshot", Name: name},
			Resources: corev1.VolumeResourceRequirements{
				Requests: corev1.ResourceList{corev1.ResourceStorage: *resource.NewQuantity(size, resource.BinarySI)},
			},
		},
	}
	_, err := c.Core.CoreV1().PersistentVolumeClaims(plan.Namespace).Create(ctx, pvc, metav1.CreateOptions{})
	return err
}

// ---- live-mount placement ---------------------------------------------------

func isRWO(ctx context.Context, c *Clients, plan spec.VolumePlan) bool {
	pvc, err := c.Core.CoreV1().PersistentVolumeClaims(plan.Namespace).Get(ctx, plan.PVCName, metav1.GetOptions{})
	if err != nil {
		return true // safe default: pin if we can
	}
	for _, m := range pvc.Spec.AccessModes {
		if m == corev1.ReadWriteMany || m == corev1.ReadOnlyMany {
			return false
		}
	}
	return true
}

// attachedNode determines the node a live RWO volume is attached to: first the CSI
// VolumeAttachment for the PV (authoritative, independent of pod phase), then any
// non-terminated pod that mounts the PVC. Empty means undetermined.
func attachedNode(ctx context.Context, c *Clients, ns, pvcName, pvName string) string {
	if pvName != "" {
		if vas, err := c.Core.StorageV1().VolumeAttachments().List(ctx, metav1.ListOptions{}); err == nil {
			for i := range vas.Items {
				va := &vas.Items[i]
				if va.Status.Attached && va.Spec.Source.PersistentVolumeName != nil && *va.Spec.Source.PersistentVolumeName == pvName && va.Spec.NodeName != "" {
					return va.Spec.NodeName
				}
			}
		}
	}
	pods, err := c.Core.CoreV1().Pods(ns).List(ctx, metav1.ListOptions{})
	if err != nil {
		return ""
	}
	for i := range pods.Items {
		pod := &pods.Items[i]
		// Any scheduled pod that is not finished still holds the attachment
		if pod.Spec.NodeName == "" || pod.Status.Phase == corev1.PodSucceeded || pod.Status.Phase == corev1.PodFailed {
			continue
		}
		for _, v := range pod.Spec.Volumes {
			if v.PersistentVolumeClaim != nil && v.PersistentVolumeClaim.ClaimName == pvcName {
				return pod.Spec.NodeName
			}
		}
	}
	return ""
}

// ---- worker pod -------------------------------------------------------------

func workerPod(name, ns, claim string, readOnly bool, nodeName string, labels map[string]string, w WorkerConfig) *corev1.Pod {
	// Default: root with every capability dropped except DAC_OVERRIDE — PVC file
	// ownership is arbitrary and a non-root worker would fail on root-owned files.
	// DAC_OVERRIDE (not DAC_READ_SEARCH) because it is in the Pod Security "baseline"
	// allow-list, so the worker is admitted in baseline namespaces; the PVC is mounted
	// read-only, so the write bypass it also grants is moot. Overridable via the Helm
	// chart for "restricted" namespaces (run as the PVC owner's uid).
	rootUser := int64(0)
	no := false
	yes := true
	secCtx := &corev1.SecurityContext{
		RunAsUser:                &rootUser,
		AllowPrivilegeEscalation: &no,
		ReadOnlyRootFilesystem:   &yes,
		Capabilities:             &corev1.Capabilities{Drop: []corev1.Capability{"ALL"}, Add: []corev1.Capability{"DAC_OVERRIDE"}},
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
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns, Labels: labels},
		Spec: corev1.PodSpec{
			RestartPolicy:                corev1.RestartPolicyNever,
			NodeName:                     nodeName,
			AutomountServiceAccountToken: &no,
			Containers: []corev1.Container{{
				Name:                     "worker",
				Image:                    w.Image,
				ImagePullPolicy:          pullPolicy(w.ImagePullPolicy),
				Args:                     []string{"worker"},
				EnvFrom:                  envFromSecret(name),
				Resources:                resources,
				SecurityContext:          secCtx,
				TerminationMessagePolicy: corev1.TerminationMessageReadFile,
				VolumeMounts: []corev1.VolumeMount{
					{Name: "data", MountPath: "/data", ReadOnly: true},
					{Name: "tmp", MountPath: "/tmp"},
				},
			}},
			Volumes: []corev1.Volume{
				{Name: "data", VolumeSource: corev1.VolumeSource{PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{ClaimName: claim, ReadOnly: readOnly}}},
				{Name: "tmp", VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{}}},
			},
		},
	}
}

func pullPolicy(p string) corev1.PullPolicy {
	switch corev1.PullPolicy(p) {
	case corev1.PullAlways, corev1.PullNever, corev1.PullIfNotPresent:
		return corev1.PullPolicy(p)
	}
	return corev1.PullIfNotPresent
}

func superviseWorker(ctx context.Context, c *Clients, ns, name string, timeout time.Duration) (*workerOutcome, error) {
	deadline := time.Now().Add(timeout)
	created := time.Now()
	for {
		pod, err := c.Core.CoreV1().Pods(ns).Get(ctx, name, metav1.GetOptions{})
		if err == nil {
			switch pod.Status.Phase {
			case corev1.PodSucceeded, corev1.PodFailed:
				return parseOutcome(ctx, c, pod)
			case corev1.PodPending:
				if time.Since(created) > unschedulableGrace {
					for _, cond := range pod.Status.Conditions {
						if cond.Type == corev1.PodScheduled && cond.Status == corev1.ConditionFalse {
							return nil, fmt.Errorf("worker pod unschedulable: %s", cond.Message)
						}
					}
				}
			}
		}
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("worker pod did not finish within %s", timeout)
		}
		select {
		case <-ctx.Done():
			return nil, context.Cause(ctx)
		case <-time.After(pollInterval):
		}
	}
}

func parseOutcome(ctx context.Context, c *Clients, pod *corev1.Pod) (*workerOutcome, error) {
	msg, reason, exit := "", "", int32(0)
	for _, cs := range pod.Status.ContainerStatuses {
		if cs.State.Terminated != nil {
			msg = cs.State.Terminated.Message
			reason = cs.State.Terminated.Reason
			exit = cs.State.Terminated.ExitCode
		}
	}
	var out workerOutcome
	if msg != "" {
		if err := json.Unmarshal([]byte(msg), &out); err != nil {
			out = workerOutcome{Error: strings.TrimSpace(msg)}
		}
	}
	if out.DetailsInLog {
		// The termination message was too large: the worker logged the full outcome
		if full, ok := outcomeFromLog(ctx, c, pod.Namespace, pod.Name); ok {
			out = *full
		} else {
			slog.Warn("Worker outcome exceeded the termination message and could not be read from the pod log; run details will be incomplete", "pod", pod.Namespace+"/"+pod.Name)
		}
	}
	if pod.Status.Phase != corev1.PodFailed || out.Result != nil {
		return &out, nil
	}
	// The pod failed. Build the most informative error we can: the structured error
	// from the termination message when present, plus the container's exit reason
	// (OOMKilled, Error, …) and the worker's own log tail — which is the channel that
	// survives an unwritable termination file or a killed process.
	var b strings.Builder
	if out.Error != "" {
		b.WriteString(out.Error)
	} else {
		b.WriteString("worker pod failed")
	}
	if reason != "" && reason != "Error" {
		fmt.Fprintf(&b, " (%s)", reason)
	}
	if exit != 0 {
		fmt.Fprintf(&b, " [exit %d]", exit)
	}
	// Fetch the pod logs, retrying briefly to beat the kubelet's log-flush lag so the
	// worker's final ERROR line is not missed.
	tail := ""
	for attempt := 0; attempt < 3; attempt++ {
		if tail = podLogTail(ctx, c, pod.Namespace, pod.Name); tail != "" {
			break
		}
		select {
		case <-ctx.Done():
		case <-time.After(time.Second):
		}
	}
	if tail != "" {
		// Only the tail end of the log carries the failure; the full worker log is in
		// the pod's own logs (kubectl) — keep this small so aggregated volume results
		// stay well within Temporal's payload limit.
		b.WriteString("\n--- worker log (tail) ---\n")
		b.WriteString(lastBytes(tail, 1500))
	}
	out.Error = truncate(b.String(), maxVolumeErrorBytes)
	out.Result = nil
	return &out, nil
}

// maxVolumeErrorBytes bounds one volume's error text; many failing volumes are
// aggregated into one activity input and the run record, which Temporal caps at 2 MiB.
const maxVolumeErrorBytes = 3000

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "…(truncated)"
}

func lastBytes(s string, n int) string {
	if len(s) <= n {
		return s
	}
	cut := s[len(s)-n:]
	if i := strings.IndexByte(cut, '\n'); i >= 0 && i < len(cut)-1 {
		cut = cut[i+1:]
	}
	return cut
}

// outcomeFromLog finds the full outcome JSON the worker wrote to its log (retrying
// briefly for the kubelet's log-flush lag)
func outcomeFromLog(ctx context.Context, c *Clients, ns, name string) (*workerOutcome, bool) {
	for attempt := 0; attempt < 3; attempt++ {
		limit := int64(16 << 20)
		req := c.Core.CoreV1().Pods(ns).GetLogs(name, &corev1.PodLogOptions{LimitBytes: &limit})
		if stream, err := req.Stream(ctx); err == nil {
			data, _ := io.ReadAll(stream)
			stream.Close()
			for _, line := range strings.Split(string(data), "\n") {
				if !strings.HasPrefix(line, outcomeLogMarker) {
					continue
				}
				var out workerOutcome
				if err := json.Unmarshal([]byte(strings.TrimPrefix(line, outcomeLogMarker)), &out); err == nil {
					return &out, true
				}
			}
		}
		select {
		case <-ctx.Done():
			return nil, false
		case <-time.After(time.Second):
		}
	}
	return nil, false
}

func podLogTail(ctx context.Context, c *Clients, ns, name string) string {
	lines := int64(50)
	req := c.Core.CoreV1().Pods(ns).GetLogs(name, &corev1.PodLogOptions{TailLines: &lines})
	stream, err := req.Stream(ctx)
	if err != nil {
		return ""
	}
	defer stream.Close()
	data, _ := io.ReadAll(io.LimitReader(stream, 32*1024))
	return strings.TrimSpace(string(data))
}

// createEnvSecret stores a worker's environment (ticket, token, credentials) in a
// Secret the pod loads with envFrom, so nothing sensitive sits in Pod.spec where
// anyone with "get pods" can read it. Named like the pod, labelled like the pod,
// deleted with the pod.
func createEnvSecret(ctx context.Context, c *Clients, ns, name string, labels map[string]string, env []corev1.EnvVar) error {
	data := make(map[string]string, len(env))
	for _, e := range env {
		data[e.Name] = e.Value
	}
	secret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns, Labels: labels}, StringData: data}
	if _, err := c.Core.CoreV1().Secrets(ns).Create(ctx, secret, metav1.CreateOptions{}); err != nil {
		return fmt.Errorf("creating worker env secret %s/%s: %w", ns, name, err)
	}
	return nil
}

// envFromSecret is the container-side half of createEnvSecret
func envFromSecret(name string) []corev1.EnvFromSource {
	return []corev1.EnvFromSource{{SecretRef: &corev1.SecretEnvSource{LocalObjectReference: corev1.LocalObjectReference{Name: name}}}}
}

// ---- cleanup ----------------------------------------------------------------

type cleanup struct {
	c         *Clients
	namespace string
	pod       string
	secret    string
	pvc       string
	snapshot  string
	done      bool
}

func newCleanup(c *Clients, ns string) *cleanup { return &cleanup{c: c, namespace: ns} }

// run deletes everything the volume backup created; safe on every path including
// cancellation (fresh background context) and idempotent.
func (cl *cleanup) run() {
	if cl.done {
		return
	}
	cl.done = true
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	del := func(kind, name string, fn func() error) {
		if name == "" {
			return
		}
		if err := fn(); err != nil && !apierrors.IsNotFound(err) {
			slog.Warn("Cleanup failed; the orphan sweep will retry", "kind", kind, "name", name, "namespace", cl.namespace, "error", err)
		}
	}
	del("pod", cl.pod, func() error {
		return cl.c.Core.CoreV1().Pods(cl.namespace).Delete(ctx, cl.pod, metav1.DeleteOptions{})
	})
	del("secret", cl.secret, func() error {
		return cl.c.Core.CoreV1().Secrets(cl.namespace).Delete(ctx, cl.secret, metav1.DeleteOptions{})
	})
	del("pvc", cl.pvc, func() error {
		return cl.c.Core.CoreV1().PersistentVolumeClaims(cl.namespace).Delete(ctx, cl.pvc, metav1.DeleteOptions{})
	})
	del("volumesnapshot", cl.snapshot, func() error {
		return cl.c.Dynamic.Resource(snapshotGVR).Namespace(cl.namespace).Delete(ctx, cl.snapshot, metav1.DeleteOptions{})
	})
}

func unstructuredBool(obj map[string]interface{}, fields ...string) (bool, bool, error) {
	cur := obj
	for i, f := range fields {
		v, ok := cur[f]
		if !ok {
			return false, false, nil
		}
		if i == len(fields)-1 {
			b, ok := v.(bool)
			return b, ok, nil
		}
		next, ok := v.(map[string]interface{})
		if !ok {
			return false, false, nil
		}
		cur = next
	}
	return false, false, nil
}

func toAny(m map[string]string) map[string]interface{} {
	out := make(map[string]interface{}, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}
