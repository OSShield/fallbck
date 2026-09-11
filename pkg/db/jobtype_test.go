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
