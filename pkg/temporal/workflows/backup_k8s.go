package workflows

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/osshield/fallbck/pkg/db"
	"github.com/osshield/fallbck/pkg/k8sbackup"
	"github.com/osshield/fallbck/pkg/rundetail"
	fbtemporal "github.com/osshield/fallbck/pkg/temporal"
	"github.com/osshield/fallbck/pkg/temporal/activities"
	sdktemporal "go.temporal.io/sdk/temporal"
	"go.temporal.io/sdk/workflow"
)

// maxAggregatedFailures / maxErrorMessageBytes bound the run's error text so the
// finalize activity input and history stay within Temporal's payload limit.
const (
	maxAggregatedFailures = 25
	maxErrorMessageBytes  = 24 * 1024
)

// joinFailures renders failed-volume messages, capping the count and total size
func joinFailures(failed []string) string {
	shown := failed
	suffix := ""
	if len(shown) > maxAggregatedFailures {
		suffix = fmt.Sprintf("; … and %d more", len(shown)-maxAggregatedFailures)
		shown = shown[:maxAggregatedFailures]
	}
	msg := strings.Join(shown, "; ") + suffix
	if len(msg) > maxErrorMessageBytes {
		msg = msg[:maxErrorMessageBytes] + "…(truncated)"
	}
	return msg
}

// kubernetesOutcome aggregates a kubernetes run for finalize
type kubernetesOutcome struct {
	result fbtemporal.BackupExecutionResult
	err    error
}

// runKubernetesBackup orchestrates one kubernetes run: discover the volume plan, fan
// out one activity per volume (bounded by volumes.parallelism), then dump and upload
// the API resources with the manifest embedding every volume outcome.
func runKubernetesBackup(ctx workflow.Context, session *fbtemporal.BackupSessionInfo) kubernetesOutcome {
	logger := workflow.GetLogger(ctx)
	var k8sActs *activities.K8sAgentActivities
	out := kubernetesOutcome{}

	spec := session.K8sConfig
	if spec == nil {
		out.err = fmt.Errorf("kubernetes job has no configuration")
		out.result.ErrorMessage = out.err.Error()
		return out
	}

	baseOpts := workflow.ActivityOptions{
		TaskQueue:           session.AgentTaskQueue,
		StartToCloseTimeout: 10 * time.Minute,
		HeartbeatTimeout:    60 * time.Second,
		RetryPolicy: &sdktemporal.RetryPolicy{
			InitialInterval:        5 * time.Second,
			BackoffCoefficient:     2.0,
			MaximumAttempts:        2,
			NonRetryableErrorTypes: []string{activities.ErrTypeDBPrecheckFailed},
		},
	}

	// 1. Discovery
	var plan k8sbackup.Plan
	if err := workflow.ExecuteActivity(workflow.WithActivityOptions(ctx, baseOpts), k8sActs.DiscoverKubernetesBackup, session).Get(ctx, &plan); err != nil {
		out.err = err
		out.result.ErrorMessage = "discovering the cluster failed: " + err.Error()
		return out
	}
	logger.Info("Kubernetes backup plan", "volumes", len(plan.Volumes), "snapshot_crd", plan.SnapshotCRD)
	// 2. Volume fan-out, bounded by a token pool
	volOpts := baseOpts
	volOpts.StartToCloseTimeout = spec.Volumes.EffVolumeTimeout() + 15*time.Minute
	results := make([]k8sbackup.VolumeResult, len(plan.Volumes))
	if len(plan.Volumes) > 0 {
		sem := workflow.NewBufferedChannel(ctx, spec.Volumes.EffParallelism())
		wg := workflow.NewWaitGroup(ctx)
		for i := range plan.Volumes {
			i := i
			vol := plan.Volumes[i]
			wg.Add(1)
			workflow.Go(ctx, func(gctx workflow.Context) {
				defer wg.Done()
				sem.Send(gctx, nil)
				defer sem.Receive(gctx, nil)
				var res k8sbackup.VolumeResult
				err := workflow.ExecuteActivity(workflow.WithActivityOptions(gctx, volOpts), k8sActs.BackupKubernetesVolume, session, vol).Get(gctx, &res)
				if err != nil {
					res = k8sbackup.VolumeResult{
						Namespace: vol.Namespace, PVCName: vol.PVCName, GroupID: vol.GroupID,
						Mode: vol.Mode, Status: "failed", Error: err.Error(),
					}
					if sdktemporal.IsCanceledError(err) {
						res.Status, res.Error = "cancelled", "cancelled by operator"
					}
				}
				results[i] = res
			})
		}
		wg.Wait(ctx)
	}

	// 3. Resources + manifest (runs last so the manifest lists the volume outcomes)
	resOpts := baseOpts
	resOpts.StartToCloseTimeout = 2 * time.Hour
	var resResult fbtemporal.BackupExecutionResult
	resErr := workflow.ExecuteActivity(workflow.WithActivityOptions(ctx, resOpts), k8sActs.BackupKubernetesResources, session, &plan, results).Get(ctx, &resResult)

	// 4. Aggregate
	out.result = resResult
	var failed []string
	completed := 0
	for _, r := range results {
		out.result.BytesScanned += r.BytesScanned
		out.result.BytesUploaded += r.BytesUploaded
		out.result.ChunkCount += r.ChunkCount
		switch r.Status {
		case "failed":
			failed = append(failed, fmt.Sprintf("%s/%s: %s", r.Namespace, r.PVCName, r.Error))
		case "completed":
			completed++
		}
	}
	if out.result.BytesUploaded > 0 {
		out.result.DedupRatio = float64(out.result.BytesScanned) / float64(out.result.BytesUploaded)
	}

	// The manifest (with every volume outcome) is produced by the resources step; when
	// that step did not finish, keep the outcomes anyway so the run page still shows
	// which volumes made it to PBS and which did not
	if len(out.result.Details) == 0 && len(results) > 0 {
		out.result.Details = partialKubernetesDetails(session, results)
	}

	switch {
	case resErr != nil:
		// Wrapped, not replaced: the workflow reads the phase and log tail off the
		// activity error, and the run's error text is taken from err
		out.err = fmt.Errorf("resource backup failed: %w", resErr)
		if len(results) > 0 {
			out.err = fmt.Errorf("resource backup failed after %d of %d volumes completed (%d failed): %w", completed, len(results), len(failed), resErr)
		}
		out.result.ErrorMessage = out.err.Error()
	case len(failed) > 0 && (!spec.Volumes.EffContinueOnError() || completed == 0 && len(failed) == len(results)):
		out.err = fmt.Errorf("%d of %d volumes failed: %s", len(failed), len(results), joinFailures(failed))
		out.result.ErrorMessage = out.err.Error()
	case len(failed) > 0:
		out.result.Status = db.RunStatusPartial
		out.result.ErrorMessage = fmt.Sprintf("%d of %d volumes failed: %s", len(failed), len(results), joinFailures(failed))
		logger.Warn("Kubernetes backup completed with volume failures", "failed", len(failed))
	}
	return out
}

// partialKubernetesDetails is the run detail blob for a kubernetes run that ended
// before the agent wrote the manifest: the volume outcomes, tagged partial
func partialKubernetesDetails(session *fbtemporal.BackupSessionInfo, results []k8sbackup.VolumeResult) json.RawMessage {
	m := &k8sbackup.Manifest{
		SchemaVersion: k8sbackup.ManifestSchemaVersion,
		Job:           k8sbackup.ManifestJob{ID: session.JobID.String(), Name: session.JobName, RunID: session.RunID, BackupRunID: session.BackupRunID.String()},
		Volumes:       results,
		Partial:       true,
	}
	data, err := m.Marshal()
	if err != nil {
		return nil
	}
	return rundetail.WrapManifest(rundetail.TypeKubernetes, data)
}
