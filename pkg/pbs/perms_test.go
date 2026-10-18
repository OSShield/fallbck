package pbs

import (
	"strings"
	"testing"
)

type perms = map[string]map[string]bool

func TestEvaluateToken(t *testing.T) {
	backup := map[string]bool{PrivBackup: true}
	cases := []struct {
		name      string
		all       perms
		atTarget  perms
		ns        string
		want      string
		findPaths []string
	}{
		{"DatastoreBackup on the store", perms{"/datastore/s1": backup}, perms{"/datastore/s1": backup}, "", TokenOK, nil},
		{"on the namespace", perms{"/datastore/s1/hosts/web": backup}, perms{"/datastore/s1/hosts/web": backup}, "hosts/web", TokenOK, nil},
		{"on a parent namespace", perms{"/datastore/s1/hosts": backup}, perms{"/datastore/s1/hosts/web": backup}, "hosts/web", TokenOK, nil},
		{"store grant for a namespace target", perms{"/datastore/s1": backup, "/datastore/s1/other": backup}, perms{"/datastore/s1/hosts": backup}, "hosts", TokenOK, nil},
		{"also on another store", perms{"/datastore/s1": backup, "/datastore/s2": backup}, perms{"/datastore/s1": backup}, "", TokenExcess, []string{"/datastore/s2"}},
		{"on / with propagate", perms{"/": backup, "/datastore": backup, "/datastore/s1": backup, "/datastore/s2": backup}, perms{"/datastore/s1": backup}, "", TokenExcess, []string{"/"}},
		{"Admin on /", perms{
			"/":             {"Sys.Modify": true, "Datastore.Allocate": true, PrivBackup: true},
			"/access":       {"Sys.Modify": true, "Datastore.Allocate": true, PrivBackup: true},
			"/datastore/s1": {"Sys.Modify": true, "Datastore.Allocate": true, PrivBackup: true},
		}, perms{"/datastore/s1": {PrivBackup: true, "Sys.Modify": true}}, "", TokenExcess, []string{"/"}},
		{"Audit added on the store", perms{"/datastore/s1": {PrivBackup: true, "Datastore.Audit": true}}, perms{"/datastore/s1": {PrivBackup: true, "Datastore.Audit": true}}, "", TokenExcess, []string{"/datastore/s1"}},
		{"non-propagating extra repeats below", perms{"/": {"Sys.Audit": false}, "/system": {"Sys.Audit": true}}, perms{"/datastore/s1": backup}, "", TokenExcess, []string{"/", "/system"}},
		{"no privileges at all", perms{}, perms{}, "", TokenMissing, nil},
		{"grant on another namespace only", perms{"/datastore/s1/other": backup}, perms{}, "hosts", TokenMissing, nil},
		{"deeper than the target only", perms{"/datastore/s1/hosts/web/child": backup}, perms{}, "hosts/web", TokenMissing, nil},
		{"missing beats excess", perms{"/datastore/s2": backup}, perms{}, "", TokenMissing, []string{"/datastore/s2"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := EvaluateToken(tc.all, tc.atTarget, "s1", tc.ns)
			if got.Status != tc.want {
				t.Errorf("status %s, want %s (findings %+v)", got.Status, tc.want, got.Findings)
			}
			var paths []string
			for _, f := range got.Findings {
				paths = append(paths, f.Path)
				if f.Problem == "" || len(f.Privileges) == 0 {
					t.Errorf("finding without explanation: %+v", f)
				}
			}
			if strings.Join(paths, ",") != strings.Join(tc.findPaths, ",") {
				t.Errorf("findings at %v, want %v", paths, tc.findPaths)
			}
		})
	}
}

func TestEvaluateTokenDescribes(t *testing.T) {
	got := EvaluateToken(perms{"/": {"Sys.Modify": true}}, perms{"/datastore/s1": {PrivBackup: true}}, "s1", "")
	if len(got.Findings) != 1 || !strings.Contains(got.Findings[0].Problem, "everything on this PBS") {
		t.Errorf("findings %+v", got.Findings)
	}
	if TargetACLPath("s1", "/a/b/") != "/datastore/s1/a/b" || TargetACLPath("s1", "") != "/datastore/s1" {
		t.Error("TargetACLPath")
	}
}
