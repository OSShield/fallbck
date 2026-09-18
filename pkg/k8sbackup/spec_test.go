package k8sbackup

import (
	"strings"
	"testing"
	"time"
)

func TestSpecValidateDefaults(t *testing.T) {
	s := &Spec{}
	if err := s.Validate(); err != nil {
		t.Fatal(err)
	}
	if s.Volumes.Mode != VolumesAll || s.Volumes.EffParallelism() != 2 || !s.IncludeSecrets() ||
		!s.Volumes.EffAllowLiveFallback() || !s.Volumes.EffContinueOnError() ||
		s.Volumes.EffSnapshotTimeout() != 10*time.Minute || s.Volumes.EffVolumeTimeout() != 2*time.Hour {
		t.Errorf("defaults not applied: %+v", s)
	}
}

func TestSpecValidateRejects(t *testing.T) {
	cases := map[string]*Spec{
		"bad ns glob":        {Namespaces: NamespaceFilter{Include: []string{"UPPER"}}},
		"bad selector":       {LabelSelector: "a=b,("},
		"bad extra":          {Resources: ResourceOptions{ExcludeExtra: []string{"noslash"}}},
		"bad mode":           {Volumes: VolumeOptions{Mode: "some"}},
		"labeled needs sel":  {Volumes: VolumeOptions{Mode: VolumesLabeled}},
		"bad vol selector":   {Volumes: VolumeOptions{LabelSelector: "!!"}},
		"parallelism high":   {Volumes: VolumeOptions{Parallelism: 20}},
		"snapshot too long":  {Volumes: VolumeOptions{SnapshotTimeout: "2h"}},
		"volume bad":         {Volumes: VolumeOptions{VolumeTimeout: "soon"}},
		"empty override":     {Volumes: VolumeOptions{SnapshotClassOverrides: map[string]string{"sc": ""}}},
		"bad vol ns pattern": {Volumes: VolumeOptions{Namespaces: &NamespaceFilter{Exclude: []string{"bad ns"}}}},
	}
	for name, s := range cases {
		if err := s.Validate(); err == nil {
			t.Errorf("%s: accepted", name)
		} else if !strings.Contains(err.Error(), "invalid kubernetes job configuration") {
			t.Errorf("%s: not wrapped: %v", name, err)
		}
	}
	ok := &Spec{
		Namespaces:    NamespaceFilter{Include: []string{"app-*"}, Exclude: []string{"kube-system"}},
		LabelSelector: "team=web,env in (prod,staging)",
		Resources:     ResourceOptions{ExcludeExtra: []string{"*/secrets", "cert-manager.io/*"}},
		Volumes:       VolumeOptions{Mode: VolumesLabeled, LabelSelector: "backup=true", Parallelism: 4, SnapshotTimeout: "5m", VolumeTimeout: "1h"},
	}
	if err := ok.Validate(); err != nil {
		t.Errorf("valid spec rejected: %v", err)
	}
}

func TestNamespaceFilter(t *testing.T) {
	f := NamespaceFilter{Include: []string{"app-*", "shared"}, Exclude: []string{"app-legacy"}}
	for ns, want := range map[string]bool{"app-1": true, "shared": true, "app-legacy": false, "other": false} {
		if f.Matches(ns) != want {
			t.Errorf("Matches(%q) = %v, want %v", ns, !want, want)
		}
	}
	empty := NamespaceFilter{Exclude: []string{"kube-system"}}
	if !empty.Matches("anything") || empty.Matches("kube-system") {
		t.Error("empty include must mean all-but-excluded")
	}
}

func TestVolumeGroupID(t *testing.T) {
	id := VolumeGroupID("k8s-prod", "app", "data")
	if id != "k8s-prod-pvc-app-data" || !IsVolumeGroup("k8s-prod", id) || IsVolumeGroup("k8s-other", id) {
		t.Errorf("group id %q", id)
	}
	long := VolumeGroupID("k8s-prod", strings.Repeat("n", 60), strings.Repeat("p", 60))
	if len(long) > 90 {
		t.Errorf("group id not capped: %d", len(long))
	}
	if long == VolumeGroupID("k8s-prod", strings.Repeat("n", 60), strings.Repeat("p", 61)) {
		t.Error("truncated ids must stay distinct")
	}
	if VolumeGroupID("k8s-prod", "app", "we~ird/name") != "k8s-prod-pvc-app-we-ird-name" {
		t.Errorf("sanitisation: %q", VolumeGroupID("k8s-prod", "app", "we~ird/name"))
	}
}

func TestManifestRoundTrip(t *testing.T) {
	m := &Manifest{SchemaVersion: ManifestSchemaVersion, Volumes: []VolumeResult{{Namespace: "app", PVCName: "data", GroupID: "g", Status: "completed"}}}
	data, err := m.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	back, err := ParseManifest(data)
	if err != nil || back.Volumes[0].GroupID != "g" {
		t.Errorf("round trip: %v %+v", err, back)
	}
}
