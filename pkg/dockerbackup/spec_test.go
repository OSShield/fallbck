package dockerbackup

import (
	"strings"
	"testing"
)

func TestSpecValidateDefaults(t *testing.T) {
	s := &Spec{}
	if err := s.Validate(); err != nil {
		t.Fatal(err)
	}
	if s.EffImages() != ImagesRefs || !s.EffIncludeUnusedVolumes() || !s.EffIncludeStopped() {
		t.Errorf("defaults: images=%q unused=%v stopped=%v", s.EffImages(), s.EffIncludeUnusedVolumes(), s.EffIncludeStopped())
	}
	if s.Summary() != "definitions + volumes" {
		t.Errorf("summary %q", s.Summary())
	}
}

func TestSpecValidateNormalises(t *testing.T) {
	s := &Spec{ExcludeVolumes: []string{" *_cache ", ""}, Images: " Local ", ExcludePaths: []string{" /vol-*/tmp ", ""}, PauseContainers: []string{"db-*"}}
	if err := s.Validate(); err != nil {
		t.Fatal(err)
	}
	if len(s.ExcludeVolumes) != 1 || s.ExcludeVolumes[0] != "*_cache" {
		t.Errorf("exclude volumes %v", s.ExcludeVolumes)
	}
	if s.Images != ImagesLocal || len(s.ExcludePaths) != 1 || s.ExcludePaths[0] != "/vol-*/tmp" {
		t.Errorf("images %q excludes %v", s.Images, s.ExcludePaths)
	}
	if !strings.Contains(s.Summary(), "local images") || !strings.Contains(s.Summary(), "except *_cache") {
		t.Errorf("summary %q", s.Summary())
	}
	c := s.Clone()
	c.ExcludeVolumes[0] = "x"
	if s.ExcludeVolumes[0] != "*_cache" {
		t.Error("clone shares the slice")
	}
}

func TestSpecHostPaths(t *testing.T) {
	s := &Spec{HostPaths: []string{" /srv/app/ ", "/opt/compose", "/srv/app", ""}}
	if err := s.Validate(); err != nil {
		t.Fatal(err)
	}
	if strings.Join(s.HostPaths, ",") != "/opt/compose,/srv/app" {
		t.Errorf("host paths %v", s.HostPaths)
	}
	if HostPathEntry("/srv/app/") != "host-srv-app" || HostPathEntry("/opt") != "host-opt" {
		t.Error("entry names")
	}
	if !strings.Contains(s.Summary(), "+ /opt/compose, /srv/app") {
		t.Errorf("summary %q", s.Summary())
	}
}

func TestSpecValidateRejects(t *testing.T) {
	cases := map[string]*Spec{
		"bad glob":      {ExcludeContainers: []string{"[abc"}},
		"bad image":     {Images: "some"},
		"relative path": {HostPaths: []string{"srv/app"}},
		"root path":     {HostPaths: []string{"/"}},
		"nested paths":  {HostPaths: []string{"/srv", "/srv/app"}},
	}
	for name, s := range cases {
		if err := s.Validate(); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
	if (*Spec)(nil).Validate() == nil {
		t.Error("nil spec must fail")
	}
}

func TestMatchesAny(t *testing.T) {
	if !MatchesAny("/app-db-1", []string{"app-db-*"}) || MatchesAny("web", []string{"app-*"}) || MatchesAny("x", nil) {
		t.Error("glob matching")
	}
}

func TestConfigValidate(t *testing.T) {
	c := &Config{VolumeAccess: " Direct "}
	if err := c.Validate(); err != nil || c.VolumeAccess != VolumeAccessDirect {
		t.Errorf("validate: %v %q", err, c.VolumeAccess)
	}
	if (&Config{VolumeAccess: "nfs"}).Validate() == nil {
		t.Error("unknown mode accepted")
	}
	if (&Config{}).EffVolumeAccess() != VolumeAccessAuto || (&Config{}).EffHelperImage() != DefaultHelperImage {
		t.Error("defaults")
	}
	t.Setenv("DOCKER_HOST", "unix:///run/user/1000/docker.sock")
	if (&Config{}).EffSocket() != "/run/user/1000/docker.sock" {
		t.Errorf("socket from DOCKER_HOST: %q", (&Config{}).EffSocket())
	}
	if (&Config{Socket: "/x.sock"}).EffSocket() != "/x.sock" {
		t.Error("explicit socket")
	}
	t.Setenv("DOCKER_HOST", "tcp://10.0.0.1:2375")
	if (&Config{}).EffSocket() != DefaultSocket {
		t.Error("tcp DOCKER_HOST must fall back to the default socket")
	}
}

func TestIsDockerHostWithoutSocket(t *testing.T) {
	if IsDockerHost(t.TempDir() + "/missing.sock") {
		t.Error("missing socket reported as docker host")
	}
}
