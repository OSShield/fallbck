package k8sbackup

import (
	"context"
	"log/slog"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// sweepMinAge protects freshly created objects of in-flight runs
var sweepMinAge = time.Hour

// Sweep removes leftover worker pods, clone PVCs and VolumeSnapshots this agent
// created (crashes, evictions). isActive reports whether a run id is currently
// executing on this agent; objects of active runs are never touched. Runs at agent
// start and every 6 hours.
func Sweep(ctx context.Context, c *Clients, agentID string, isActive func(runID string) bool) {
	selector := labelManagedBy + "=" + labelValue + "," + labelAgentID + "=" + agentID
	tooOld := func(created metav1.Time) bool { return time.Since(created.Time) > sweepMinAge }

	if pods, err := c.Core.CoreV1().Pods("").List(ctx, metav1.ListOptions{LabelSelector: selector}); err == nil {
		for i := range pods.Items {
			p := &pods.Items[i]
			if tooOld(p.CreationTimestamp) && !isActive(p.Labels[labelRunID]) {
				slog.Info("Sweeping orphaned worker pod", "namespace", p.Namespace, "name", p.Name)
				_ = c.Core.CoreV1().Pods(p.Namespace).Delete(ctx, p.Name, metav1.DeleteOptions{})
			}
		}
	}
	if secrets, err := c.Core.CoreV1().Secrets("").List(ctx, metav1.ListOptions{LabelSelector: selector}); err == nil {
		for i := range secrets.Items {
			s := &secrets.Items[i]
			if tooOld(s.CreationTimestamp) && !isActive(s.Labels[labelRunID]) {
				slog.Info("Sweeping orphaned worker env secret", "namespace", s.Namespace, "name", s.Name)
				_ = c.Core.CoreV1().Secrets(s.Namespace).Delete(ctx, s.Name, metav1.DeleteOptions{})
			}
		}
	}
	if pvcs, err := c.Core.CoreV1().PersistentVolumeClaims("").List(ctx, metav1.ListOptions{LabelSelector: selector}); err == nil {
		for i := range pvcs.Items {
			p := &pvcs.Items[i]
			if tooOld(p.CreationTimestamp) && !isActive(p.Labels[labelRunID]) {
				slog.Info("Sweeping orphaned clone PVC", "namespace", p.Namespace, "name", p.Name)
				_ = c.Core.CoreV1().PersistentVolumeClaims(p.Namespace).Delete(ctx, p.Name, metav1.DeleteOptions{})
			}
		}
	}
	if snaps, err := c.Dynamic.Resource(snapshotGVR).Namespace("").List(ctx, metav1.ListOptions{LabelSelector: selector}); err == nil {
		for i := range snaps.Items {
			s := &snaps.Items[i]
			if tooOld(metav1.Time{Time: s.GetCreationTimestamp().Time}) && !isActive(s.GetLabels()[labelRunID]) {
				slog.Info("Sweeping orphaned volume snapshot", "namespace", s.GetNamespace(), "name", s.GetName())
				_ = c.Dynamic.Resource(snapshotGVR).Namespace(s.GetNamespace()).Delete(ctx, s.GetName(), metav1.DeleteOptions{})
			}
		}
	}
}
