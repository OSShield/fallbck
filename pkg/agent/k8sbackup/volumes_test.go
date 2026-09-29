package k8sbackup

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	spec "github.com/osshield/fallbck/pkg/k8sbackup"
	"github.com/osshield/fallbck/pkg/temporal"
	corev1 "k8s.io/api/core/v1"
	storagev1 "k8s.io/api/storage/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	fakediscovery "k8s.io/client-go/discovery/fake"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	k8sfake "k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
)

func fastPolling(t *testing.T) {
	t.Helper()
	oldPoll, oldGrace := pollInterval, unschedulableGrace
	pollInterval, unschedulableGrace = 5*time.Millisecond, 50*time.Millisecond
	t.Cleanup(func() { pollInterval, unschedulableGrace = oldPoll, oldGrace })
}

// succeedPods makes every created worker pod complete immediately with the message
func succeedPods(core *k8sfake.Clientset, phase corev1.PodPhase, message string) {
	core.PrependReactor("create", "pods", func(action k8stesting.Action) (bool, runtime.Object, error) {
		pod := action.(k8stesting.CreateAction).GetObject().(*corev1.Pod)
		pod.Status.Phase = phase
		pod.Status.ContainerStatuses = []corev1.ContainerStatus{{
			State: corev1.ContainerState{Terminated: &corev1.ContainerStateTerminated{Message: message}},
		}}
		return false, nil, nil
	})
}

func readySnapshots(dyn *dynamicfake.FakeDynamicClient) {
	dyn.PrependReactor("create", "volumesnapshots", func(action k8stesting.Action) (bool, runtime.Object, error) {
		obj := action.(k8stesting.CreateAction).GetObject().(*unstructured.Unstructured)
		obj.Object["status"] = map[string]interface{}{"readyToUse": true, "restoreSize": "2Gi"}
		return false, nil, nil
	})
}

func volumeClients(t *testing.T, extra ...runtime.Object) (*Clients, *k8sfake.Clientset, *dynamicfake.FakeDynamicClient) {
	t.Helper()
	objs := append([]runtime.Object{
		&corev1.PersistentVolumeClaim{
			ObjectMeta: metav1.ObjectMeta{Name: "data", Namespace: "app"},
			Spec:       corev1.PersistentVolumeClaimSpec{AccessModes: []corev1.PersistentVolumeAccessMode{corev1.ReadWriteOnce}},
			Status:     corev1.PersistentVolumeClaimStatus{Phase: corev1.ClaimBound},
		},
		&corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Name: "db-0", Namespace: "app"},
			Spec: corev1.PodSpec{NodeName: "node-1", Volumes: []corev1.Volume{{
				Name:         "d",
				VolumeSource: corev1.VolumeSource{PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{ClaimName: "data"}},
			}}},
			Status: corev1.PodStatus{Phase: corev1.PodRunning},
		},
	}, extra...)
	core := k8sfake.NewSimpleClientset(objs...)
	scheme := runtime.NewScheme()
	dyn := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(scheme, map[schema.GroupVersionResource]string{
		snapshotGVR:      "VolumeSnapshotList",
		snapshotClassGVR: "VolumeSnapshotClassList",
	})
	return &Clients{Discovery: core.Discovery(), Dynamic: dyn, Core: core}, core, dyn
}

func testRequest(mode string) VolumeBackupRequest {
	return VolumeBackupRequest{
		Plan: spec.VolumePlan{
			Namespace: "app", PVCName: "data", StorageClass: "fast", Mode: mode,
			SnapshotClass: "fast-snap", GroupID: "k8s-c1-pvc-app-data", CapacityBytes: 1 << 30,
		},
		RunID: "11112222-3333-4444-5555-666677778888", AgentID: "agent-1",
		SnapshotTimeout: time.Second, VolumeTimeout: 5 * time.Second, AllowLiveFallback: true,
		Worker: WorkerConfig{Image: "fallbck/k8s-agent:test"},
	}
}

func successMessage(t *testing.T) string {
	t.Helper()
	out := workerOutcome{Result: &temporal.BackupExecutionResult{Status: "completed", SnapshotID: "host/k8s-c1-pvc-app-data/2026-09-05T00:00:00Z", BytesScanned: 100, BytesUploaded: 10, ChunkCount: 3}}
	data, err := json.Marshal(out)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func TestBackupVolumeSnapshotPath(t *testing.T) {
	fastPolling(t)
	c, core, dyn := volumeClients(t)
	readySnapshots(dyn)
	succeedPods(core, corev1.PodSucceeded, successMessage(t))

	res, err := BackupVolume(context.Background(), c, testRequest(spec.ModeSnapshot))
	if err != nil {
		t.Fatalf("BackupVolume: %v", err)
	}
	if res.Status != "completed" || res.Consistency != "csi-snapshot" || res.SnapshotID == "" || res.BytesScanned != 100 {
		t.Errorf("result: %+v", res)
	}

	// worker pod mounted the clone read-write pvc name fb-...; and everything cleaned up
	var sawPod, sawClone bool
	for _, a := range core.Actions() {
		if a.GetVerb() == "create" && a.GetResource().Resource == "pods" {
			pod := a.(k8stesting.CreateAction).GetObject().(*corev1.Pod)
			sawPod = true
			claim := pod.Spec.Volumes[0].PersistentVolumeClaim.ClaimName
			if claim == "data" {
				t.Error("worker mounted the live PVC in snapshot mode")
			}
			if pod.Spec.Containers[0].Args[0] != "worker" || *pod.Spec.AutomountServiceAccountToken {
				t.Errorf("worker pod spec: %+v", pod.Spec)
			}
		}
		if a.GetVerb() == "create" && a.GetResource().Resource == "persistentvolumeclaims" {
			pvc := a.(k8stesting.CreateAction).GetObject().(*corev1.PersistentVolumeClaim)
			sawClone = true
			if pvc.Spec.DataSource == nil || pvc.Spec.DataSource.Kind != "VolumeSnapshot" {
				t.Errorf("clone pvc has no snapshot dataSource: %+v", pvc.Spec)
			}
			// restoreSize 2Gi > requested 1Gi must win
			if pvc.Spec.Resources.Requests.Storage().Value() != 2<<30 {
				t.Errorf("clone size %v", pvc.Spec.Resources.Requests.Storage())
			}
		}
	}
	if !sawPod || !sawClone {
		t.Error("worker pod or clone PVC never created")
	}
	if pods, _ := core.CoreV1().Pods("app").List(context.Background(), metav1.ListOptions{}); len(pods.Items) != 1 { // only db-0 remains
		t.Errorf("worker pod not cleaned up: %d pods", len(pods.Items))
	}
	if snaps, _ := dyn.Resource(snapshotGVR).Namespace("app").List(context.Background(), metav1.ListOptions{}); len(snaps.Items) != 0 {
		t.Error("volume snapshot not cleaned up")
	}
}

func TestBackupVolumeLiveFallbackAndPinning(t *testing.T) {
	fastPolling(t)
	c, core, _ := volumeClients(t) // no snapshot reactor: snapshots never become ready
	succeedPods(core, corev1.PodSucceeded, successMessage(t))

	res, err := BackupVolume(context.Background(), c, testRequest(spec.ModeSnapshot))
	if err != nil {
		t.Fatalf("BackupVolume: %v", err)
	}
	if res.Mode != spec.ModeLive || res.Consistency != "crash-consistent-live" {
		t.Errorf("fallback result: %+v", res)
	}
	for _, a := range core.Actions() {
		if a.GetVerb() == "create" && a.GetResource().Resource == "pods" {
			pod := a.(k8stesting.CreateAction).GetObject().(*corev1.Pod)
			if pod.Spec.NodeName != "node-1" {
				t.Errorf("live RWO worker not pinned: node %q", pod.Spec.NodeName)
			}
			if !pod.Spec.Volumes[0].PersistentVolumeClaim.ReadOnly {
				t.Error("live mount not read-only")
			}
		}
	}
}

func TestBackupVolumeWorkerFailure(t *testing.T) {
	fastPolling(t)
	c, core, _ := volumeClients(t)
	succeedPods(core, corev1.PodFailed, `{"error":"pbs: dial refused","phase":"upload"}`)
	req := testRequest(spec.ModeLive)
	res, err := BackupVolume(context.Background(), c, req)
	if err == nil || res.Status != "failed" {
		t.Fatalf("expected failure: %+v %v", res, err)
	}
	if res.Error == "" || res.GroupID != req.Plan.GroupID {
		t.Errorf("failure result: %+v", res)
	}
}

func TestBackupVolumeSkipped(t *testing.T) {
	c, _, _ := volumeClients(t)
	req := testRequest(spec.ModeSkipped)
	req.Plan.SkipReason = "volumeMode Block is not supported"
	res, err := BackupVolume(context.Background(), c, req)
	if err != nil || res.Status != "skipped" || res.Error == "" {
		t.Errorf("skipped: %+v %v", res, err)
	}
}

func TestPlanVolumes(t *testing.T) {
	scheme := runtime.NewScheme()
	vsClass := &unstructured.Unstructured{Object: map[string]interface{}{
		"apiVersion": "snapshot.storage.k8s.io/v1", "kind": "VolumeSnapshotClass",
		"metadata": map[string]interface{}{"name": "ceph-snap"},
		"driver":   "rbd.csi.ceph.com",
	}}
	dyn := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(scheme, map[schema.GroupVersionResource]string{
		snapshotGVR: "VolumeSnapshotList", snapshotClassGVR: "VolumeSnapshotClassList",
	}, vsClass)
	sc := func(name, prov string) *storagev1.StorageClass {
		return &storagev1.StorageClass{ObjectMeta: metav1.ObjectMeta{Name: name}, Provisioner: prov}
	}
	pvc := func(ns, name, class string, phase corev1.PersistentVolumeClaimPhase, ann map[string]string) *corev1.PersistentVolumeClaim {
		return &corev1.PersistentVolumeClaim{
			ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns, Annotations: ann},
			Spec:       corev1.PersistentVolumeClaimSpec{StorageClassName: &class},
			Status:     corev1.PersistentVolumeClaimStatus{Phase: phase},
		}
	}
	optOut := pvc("app", "optout", "ceph", corev1.ClaimBound, nil)
	optOut.Labels = map[string]string{"fallbck.io/skip-backup": "true"}
	core := k8sfake.NewSimpleClientset(
		sc("ceph", "rbd.csi.ceph.com"), sc("local", "rancher.io/local-path"), optOut,
		pvc("app", "snapme", "ceph", corev1.ClaimBound, nil),
		pvc("app", "liveme", "local", corev1.ClaimBound, nil),
		pvc("app", "skipme", "ceph", corev1.ClaimBound, map[string]string{"fallbck.io/skip": "true"}),
		pvc("app", "pending", "ceph", corev1.ClaimPending, nil),
		pvc("kube-system", "sysvol", "ceph", corev1.ClaimBound, nil),
	)
	disc := core.Discovery().(*fakediscovery.FakeDiscovery)
	disc.Resources = []*metav1.APIResourceList{{
		GroupVersion: "snapshot.storage.k8s.io/v1",
		APIResources: []metav1.APIResource{{Name: "volumesnapshots", Kind: "VolumeSnapshot", Verbs: []string{"get", "list"}}},
	}}
	c := &Clients{Discovery: disc, Dynamic: dyn, Core: core}
	s := &spec.Spec{Namespaces: spec.NamespaceFilter{Exclude: []string{"kube-system"}}}
	if err := s.Validate(); err != nil {
		t.Fatal(err)
	}
	plans, _, _, err := PlanVolumes(context.Background(), c, s, "k8s-c1")
	if err != nil {
		t.Fatalf("PlanVolumes: %v", err)
	}
	byName := map[string]spec.VolumePlan{}
	for _, p := range plans {
		byName[p.PVCName] = p
	}
	if len(plans) != 4 || byName["optout"].PVCName == "" {
		t.Fatalf("plans (labelled PVC is included without a skip selector): %+v", plans)
	}
	if p := byName["snapme"]; p.Mode != spec.ModeSnapshot || p.SnapshotClass != "ceph-snap" || p.GroupID != "k8s-c1-pvc-app-snapme" {
		t.Errorf("snapme: %+v", p)
	}
	if p := byName["liveme"]; p.Mode != spec.ModeLive {
		t.Errorf("liveme: %+v", p)
	}
	if p := byName["pending"]; p.Mode != spec.ModeSkipped {
		t.Errorf("pending: %+v", p)
	}

	// skip label selector → left out of the plan entirely
	s3 := &spec.Spec{Namespaces: spec.NamespaceFilter{Exclude: []string{"kube-system"}}, Volumes: spec.VolumeOptions{SkipLabelSelector: "fallbck.io/skip-backup=true"}}
	if err := s3.Validate(); err != nil {
		t.Fatal(err)
	}
	plans3, _, _, err := PlanVolumes(context.Background(), c, s3, "k8s-c1")
	if err != nil {
		t.Fatal(err)
	}
	if len(plans3) != 3 {
		t.Errorf("skip selector: %+v", plans3)
	}
	for _, p := range plans3 {
		if p.PVCName == "optout" {
			t.Error("optout must be skipped by label")
		}
	}

	// live fallback disabled → skipped with reason
	no := false
	s2 := &spec.Spec{Volumes: spec.VolumeOptions{AllowLiveFallback: &no}}
	_ = s2.Validate()
	plans2, _, _, err := PlanVolumes(context.Background(), c, s2, "k8s-c1")
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range plans2 {
		if p.PVCName == "liveme" && p.Mode != spec.ModeSkipped {
			t.Errorf("liveme without fallback: %+v", p)
		}
	}
}

func TestBackupVolumeKilledSurfacesReasonAndLogs(t *testing.T) {
	fastPolling(t)
	c, core, _ := volumeClients(t)
	// Pod killed before it could write a termination message (empty message,
	// OOMKilled, exit 137) — the failure must still surface the reason and the logs.
	core.PrependReactor("create", "pods", func(action k8stesting.Action) (bool, runtime.Object, error) {
		pod := action.(k8stesting.CreateAction).GetObject().(*corev1.Pod)
		pod.Status.Phase = corev1.PodFailed
		pod.Status.ContainerStatuses = []corev1.ContainerStatus{{
			State: corev1.ContainerState{Terminated: &corev1.ContainerStateTerminated{Reason: "OOMKilled", ExitCode: 137}},
		}}
		return false, nil, nil
	})
	res, err := BackupVolume(context.Background(), c, testRequest(spec.ModeLive))
	if err == nil || res.Status != "failed" {
		t.Fatalf("expected failure: %+v %v", res, err)
	}
	if !strings.Contains(res.Error, "OOMKilled") || !strings.Contains(res.Error, "exit 137") {
		t.Errorf("error missing kill reason/exit code: %q", res.Error)
	}
	if !strings.Contains(res.Error, "worker log") {
		t.Errorf("error missing worker log tail: %q", res.Error)
	}
}

func TestBackupVolumePinsToVolumeAttachmentNode(t *testing.T) {
	fastPolling(t)
	pvName := "pv-xyz"
	// A live RWO PVC bound to pv-xyz, attached (per the CSI VolumeAttachment) to
	// node-7, with no consumer pod running — the worker must still land on node-7.
	va := &storagev1.VolumeAttachment{
		ObjectMeta: metav1.ObjectMeta{Name: "csi-att"},
		Spec:       storagev1.VolumeAttachmentSpec{NodeName: "node-7", Source: storagev1.VolumeAttachmentSource{PersistentVolumeName: &pvName}},
		Status:     storagev1.VolumeAttachmentStatus{Attached: true},
	}
	pvc := &corev1.PersistentVolumeClaim{
		ObjectMeta: metav1.ObjectMeta{Name: "data", Namespace: "app"},
		Spec:       corev1.PersistentVolumeClaimSpec{AccessModes: []corev1.PersistentVolumeAccessMode{corev1.ReadWriteOnce}, VolumeName: pvName},
		Status:     corev1.PersistentVolumeClaimStatus{Phase: corev1.ClaimBound},
	}
	core := k8sfake.NewSimpleClientset(pvc, va)
	scheme := runtime.NewScheme()
	dyn := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(scheme, map[schema.GroupVersionResource]string{
		snapshotGVR: "VolumeSnapshotList", snapshotClassGVR: "VolumeSnapshotClassList",
	})
	c := &Clients{Discovery: core.Discovery(), Dynamic: dyn, Core: core}
	succeedPods(core, corev1.PodSucceeded, successMessage(t))

	req := testRequest(spec.ModeLive)
	req.Plan.PVName = pvName
	if _, err := BackupVolume(context.Background(), c, req); err != nil {
		t.Fatalf("BackupVolume: %v", err)
	}
	for _, a := range core.Actions() {
		if a.GetVerb() == "create" && a.GetResource().Resource == "pods" {
			pod := a.(k8stesting.CreateAction).GetObject().(*corev1.Pod)
			if pod.Spec.NodeName != "node-7" {
				t.Errorf("worker not pinned to the attached node: %q", pod.Spec.NodeName)
			}
		}
	}
}
