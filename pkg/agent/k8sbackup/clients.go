// Package k8sbackup implements the Kubernetes backup agent: API resource dumps,
// PVC snapshots/clones, worker-pod supervision and the Secret-backed identity.
package k8sbackup

import (
	"fmt"

	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/discovery"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

// Clients bundles the API clients the agent needs; tests inject fakes.
type Clients struct {
	Discovery discovery.DiscoveryInterface
	Dynamic   dynamic.Interface
	Core      kubernetes.Interface
}

// InClusterClients builds the clients from the pod's ServiceAccount
func InClusterClients() (*Clients, error) {
	cfg, err := rest.InClusterConfig()
	if err != nil {
		return nil, fmt.Errorf("in-cluster kubeconfig (the agent must run inside the target cluster): %w", err)
	}
	cfg.QPS = 50
	cfg.Burst = 100
	core, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return nil, err
	}
	dyn, err := dynamic.NewForConfig(cfg)
	if err != nil {
		return nil, err
	}
	return &Clients{Discovery: core.Discovery(), Dynamic: dyn, Core: core}, nil
}

// CSI external-snapshotter API (accessed dynamically to avoid the clientset dependency)
var (
	snapshotGVR      = schema.GroupVersionResource{Group: "snapshot.storage.k8s.io", Version: "v1", Resource: "volumesnapshots"}
	snapshotClassGVR = schema.GroupVersionResource{Group: "snapshot.storage.k8s.io", Version: "v1", Resource: "volumesnapshotclasses"}
)
