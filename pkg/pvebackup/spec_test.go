package pvebackup

import (
	"strings"
	"testing"
	"time"
)

func TestSpecValidate(t *testing.T) {
	s := &Spec{DataPaths: []string{" /mnt/pve/nfs ", "/var/lib/vz", "/var/lib/vz", ""}, ExcludePaths: []string{"/vz/template/cache", " "}}
	if err := s.Validate(); err != nil {
		t.Fatal(err)
	}
	if strings.Join(s.DataPaths, ",") != "/mnt/pve/nfs,/var/lib/vz" {
		t.Errorf("data paths %v", s.DataPaths)
	}
	if len(s.ExcludePaths) != 1 {
		t.Errorf("exclude patterns %v", s.ExcludePaths)
	}
	if !s.EffIncludeRootHome() || s.EffIncludeGuestImages() {
		t.Error("defaults: root home on, guest images off")
	}
	if !strings.Contains(s.Summary(), "/var/lib/vz") {
		t.Errorf("summary %q", s.Summary())
	}
	var empty *Spec
	if empty.Summary() != "host configuration" || !empty.EffIncludeRootHome() {
		t.Error("nil spec defaults")
	}
	c := s.Clone()
	c.DataPaths[0] = "/x"
	if s.DataPaths[0] == "/x" {
		t.Error("Clone shares the data paths slice")
	}

	bad := map[string]*Spec{
		"relative":    {DataPaths: []string{"data"}},
		"root":        {DataPaths: []string{"/"}},
		"inside etc":  {DataPaths: []string{"/etc/pve"}},
		"nested":      {DataPaths: []string{"/var/lib/vz", "/var/lib/vz/dump"}},
		"bad pattern": {ExcludePaths: []string{"[unclosed"}},
		"root home":   {DataPaths: []string{"/root/data"}},
	}
	for name, spec := range bad {
		if err := spec.Validate(); err == nil {
			t.Errorf("%s: expected a validation error", name)
		}
	}
}

func TestManifestRoundTrip(t *testing.T) {
	m := &Manifest{SchemaVersion: ManifestSchemaVersion, Host: HostInfo{Hostname: "pve01", PVEVersion: "8.2.4", PVEMajor: 8},
		Snapshot: ManifestSnapshot{Type: "host", ID: "pve01-pve", Time: time.Date(2026, 9, 11, 2, 0, 0, 0, time.UTC)},
		Guests:   []Guest{{VMID: 100, Type: "qemu", Name: "web"}}, Entries: []ArchiveEntry{{Name: "etc", Source: "/etc", Kind: "etc"}}}
	data, err := m.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	back, err := ParseManifest(data)
	if err != nil || back.Host.PVEMajor != 8 || len(back.Guests) != 1 || back.Guests[0].Name != "web" || back.Entries[0].Kind != "etc" {
		t.Fatalf("round trip: %+v %v", back, err)
	}
}
