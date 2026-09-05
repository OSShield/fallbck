package k8sbackup

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	spec "github.com/osshield/fallbck/pkg/k8sbackup"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	fakediscovery "k8s.io/client-go/discovery/fake"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	k8sfake "k8s.io/client-go/kubernetes/fake"
)

func obj(apiVersion, kind, ns, name string, labels map[string]string) *unstructured.Unstructured {
	u := &unstructured.Unstructured{Object: map[string]interface{}{
		"apiVersion": apiVersion,
		"kind":       kind,
		"metadata": map[string]interface{}{
			"name": name,
			"managedFields": []interface{}{
				map[string]interface{}{"manager": "kubectl"},
			},
		},
	}}
	if ns != "" {
		u.SetNamespace(ns)
	}
	if labels != nil {
		u.SetLabels(labels)
	}
	return u
}

func testClients(t *testing.T, objs ...runtime.Object) *Clients {
	t.Helper()
	core := k8sfake.NewSimpleClientset(
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "app"}},
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "kube-system"}},
	)
	disc := core.Discovery().(*fakediscovery.FakeDiscovery)
	disc.Resources = []*metav1.APIResourceList{
		{GroupVersion: "v1", APIResources: []metav1.APIResource{
			{Name: "configmaps", Namespaced: true, Kind: "ConfigMap", Verbs: []string{"get", "list"}},
			{Name: "secrets", Namespaced: true, Kind: "Secret", Verbs: []string{"get", "list"}},
			{Name: "events", Namespaced: true, Kind: "Event", Verbs: []string{"get", "list"}},
			{Name: "pods/status", Namespaced: true, Kind: "Pod", Verbs: []string{"get", "list"}},
			{Name: "bindings", Namespaced: true, Kind: "Binding", Verbs: []string{"create"}},
		}},
		{GroupVersion: "rbac.authorization.k8s.io/v1", APIResources: []metav1.APIResource{
			{Name: "clusterroles", Namespaced: false, Kind: "ClusterRole", Verbs: []string{"get", "list"}},
		}},
	}
	scheme := runtime.NewScheme()
	listKinds := map[schema.GroupVersionResource]string{
		{Version: "v1", Resource: "configmaps"}:                                       "ConfigMapList",
		{Version: "v1", Resource: "secrets"}:                                          "SecretList",
		{Version: "v1", Resource: "events"}:                                           "EventList",
		{Group: "rbac.authorization.k8s.io", Version: "v1", Resource: "clusterroles"}: "ClusterRoleList",
		snapshotGVR:      "VolumeSnapshotList",
		snapshotClassGVR: "VolumeSnapshotClassList",
	}
	dyn := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(scheme, listKinds, objs...)
	return &Clients{Discovery: disc, Dynamic: dyn, Core: core}
}

func TestDumpResources(t *testing.T) {
	c := testClients(t,
		obj("v1", "ConfigMap", "app", "settings", nil),
		obj("v1", "ConfigMap", "kube-system", "cluster-info", nil),
		obj("v1", "Secret", "app", "credentials", nil),
		obj("v1", "Event", "app", "noise", nil),
		obj("rbac.authorization.k8s.io/v1", "ClusterRole", "", "system:masters", nil),
	)
	s := &spec.Spec{Namespaces: spec.NamespaceFilter{Exclude: []string{"kube-system"}}}
	if err := s.Validate(); err != nil {
		t.Fatal(err)
	}
	spool := t.TempDir()
	stats, err := DumpResources(context.Background(), c, s, spool, nil)
	if err != nil {
		t.Fatalf("DumpResources: %v", err)
	}
	for _, want := range []string{
		"namespaces/app/core/v1/configmaps/settings.yaml",
		"namespaces/app/core/v1/secrets/credentials.yaml",
		"cluster/rbac.authorization.k8s.io/v1/clusterroles/system_masters.yaml",
	} {
		if _, err := os.Stat(filepath.Join(spool, want)); err != nil {
			t.Errorf("missing %s", want)
		}
	}
	for _, unwanted := range []string{
		"namespaces/kube-system/core/v1/configmaps/cluster-info.yaml", // excluded namespace
		"namespaces/app/core/v1/events/noise.yaml",                    // default exclusion
	} {
		if _, err := os.Stat(filepath.Join(spool, unwanted)); err == nil {
			t.Errorf("unexpected %s", unwanted)
		}
	}
	if stats.Counts["/configmaps"] != 1 || stats.Counts["/secrets"] != 1 || stats.Counts["rbac.authorization.k8s.io/clusterroles"] != 1 {
		t.Errorf("counts: %+v", stats.Counts)
	}
	found := false
	for _, e := range stats.Excluded {
		if e == "/events" {
			found = true
		}
	}
	if !found {
		t.Errorf("events not recorded as excluded: %v", stats.Excluded)
	}
	data, _ := os.ReadFile(filepath.Join(spool, "namespaces/app/core/v1/configmaps/settings.yaml"))
	if strings.Contains(string(data), "managedFields") {
		t.Error("managedFields not stripped")
	}
	if !strings.Contains(string(data), "name: settings") {
		t.Errorf("yaml content: %s", data)
	}

	// include_secrets=false drops secrets
	no := false
	s2 := &spec.Spec{Resources: spec.ResourceOptions{IncludeSecrets: &no}}
	_ = s2.Validate()
	spool2 := t.TempDir()
	if _, err := DumpResources(context.Background(), c, s2, spool2, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(spool2, "namespaces/app/core/v1/secrets/credentials.yaml")); err == nil {
		t.Error("secrets dumped despite include_secrets=false")
	}
}

func TestMatchResource(t *testing.T) {
	cases := []struct {
		pattern, group, resource string
		want                     bool
	}{
		{"/events", "", "events", true},
		{"*/secrets", "", "secrets", true},
		{"*/secrets", "whatever.io", "secrets", true},
		{"apps/deployments", "apps", "deployments", true},
		{"apps/deployments", "apps", "statefulsets", false},
		{"cert-manager.io/*", "cert-manager.io", "certificates", true},
		{"metrics.k8s.io/*", "metrics.k8s.io", "nodes", true},
		{"noslash", "", "noslash", false},
	}
	for _, c := range cases {
		if got := matchResource(c.pattern, c.group, c.resource); got != c.want {
			t.Errorf("matchResource(%q,%q,%q) = %v", c.pattern, c.group, c.resource, got)
		}
	}
}
