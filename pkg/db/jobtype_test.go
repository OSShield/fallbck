package db

import "testing"

func TestJobAllowedOnAgent(t *testing.T) {
	cases := []struct {
		job, agent string
		want       bool
	}{
		{"filesystem", "filesystem", true},
		{"", "", true},
		{"database", "database", true},
		{"kubernetes", "kubernetes", true},
		{"database", "kubernetes", true},
		{"kubernetes", "database", false},
		{"filesystem", "kubernetes", false},
		{"database", "filesystem", false},
	}
	for _, c := range cases {
		if got := JobAllowedOnAgent(c.job, c.agent); got != c.want {
			t.Errorf("JobAllowedOnAgent(%q, %q) = %v, want %v", c.job, c.agent, got, c.want)
		}
	}
}

func TestNormalizeJobTypeAndPVEPairing(t *testing.T) {
	if jt, ok := NormalizeJobType("pve"); !ok || jt != JobTypePVE {
		t.Errorf("pve job type: %q %v", jt, ok)
	}
	if jt, ok := NormalizeJobType(""); !ok || jt != JobTypeFilesystem {
		t.Errorf("empty job type: %q %v", jt, ok)
	}
	if _, ok := NormalizeAgentType("pve"); ok {
		t.Error("pve must not be an agent type")
	}
	if !JobAllowedOnAgent("pve", "filesystem") || JobAllowedOnAgent("pve", "database") || JobAllowedOnAgent("pve", "kubernetes") {
		t.Error("pve jobs run on filesystem agents only")
	}
}
