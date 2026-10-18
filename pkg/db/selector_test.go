package db

import (
	"encoding/json"
	"testing"
)

func TestParseSelectorCanonical(t *testing.T) {
	cases := map[string]string{
		"":                                  "",
		"team=web":                          "team=web",
		"team == web":                       "team=web",
		" env in (stage, prod) , team=web ": "env in (prod, stage), team=web",
		"env in(prod)":                      "env=prod",
		"env notin (dev, test)":             "env notin (dev, test)",
		"env NOTIN (dev)":                   "env!=dev",
		"env != dev":                        "env!=dev",
		"managed, !legacy":                  "!legacy, managed",
		"fallbck.io/tier in (gold, gold)":   "fallbck.io/tier=gold",
		"team=web, team=web":                "team=web",
		"team=":                             "team=",
	}
	for in, want := range cases {
		s, err := ParseSelector(in)
		if err != nil {
			t.Errorf("%q: %v", in, err)
			continue
		}
		if s.String() != want {
			t.Errorf("%q: %q, want %q", in, s.String(), want)
		}
		again, err := ParseSelector(s.String())
		if err != nil || again.String() != want {
			t.Errorf("%q: canonical form does not re-parse to itself: %q %v", in, again, err)
		}
	}
	for _, bad := range []string{"team=web,,env=x", "team in prod", "team in ()", "team in (a b)", "team=a b", "-team", "team ~ a", "team in (a", "!team=a", "a=b=c"} {
		if s, err := ParseSelector(bad); err == nil {
			t.Errorf("%q: expected an error, got %q", bad, s)
		}
	}
}

func TestSelectorMatches(t *testing.T) {
	obj := Labels{"team": "web", "env": "prod"}
	cases := map[string]bool{
		"":                              true,
		"team=web":                      true,
		"team=db":                       false,
		"team in (db, web)":             true,
		"team notin (db)":               true,
		"team notin (web)":              false,
		"owner notin (x)":               true, // absent keys satisfy notin, like Kubernetes
		"team":                          true,
		"owner":                         false,
		"!owner":                        true,
		"!team":                         false,
		"team=web, env in (prod, test)": true,
		"team=web, env=test":            false,
	}
	for text, want := range cases {
		if got := MustSelector(text).Matches(obj); got != want {
			t.Errorf("%q on %v: %v, want %v", text, obj, got, want)
		}
	}
}

func TestSelectorJSON(t *testing.T) {
	var s Selector
	if err := json.Unmarshal([]byte(`"env in (prod, stage), team=web"`), &s); err != nil || s.String() != "env in (prod, stage), team=web" {
		t.Fatalf("string form: %q %v", s, err)
	}
	// The equality-only object form from before set-based selectors still works
	if err := json.Unmarshal([]byte(`{"team":"web","env":"prod"}`), &s); err != nil || s.String() != "env=prod, team=web" {
		t.Fatalf("object form: %q %v", s, err)
	}
	if err := json.Unmarshal([]byte(`"team in ("`), &s); err == nil {
		t.Error("a broken string must not decode")
	}
	if err := json.Unmarshal([]byte(`{"team":"a b"}`), &s); err == nil {
		t.Error("an object with a bad value must not decode")
	}
	b, _ := json.Marshal(MustSelector("team=web"))
	if string(b) != `"team=web"` {
		t.Errorf("marshal: %s", b)
	}
	var stored Selector
	if err := stored.Scan("team=web, !legacy"); err != nil || stored.String() != "!legacy, team=web" {
		t.Errorf("scan: %q %v", stored, err)
	}
}

func TestSelectorNarrows(t *testing.T) {
	cases := []struct {
		narrow, wide string
		want         bool
	}{
		{"team=a", "", true},
		{"", "team=a", false},
		{"team=a, env=prod", "team=a", true},
		{"team=a", "team in (a, b)", true},
		{"team in (a, b)", "team=a", false},
		{"team in (a, b)", "team in (a, b, c)", true},
		{"team=a", "team", true},
		{"team", "team=a", false},
		{"team=a", "team notin (b)", true},
		{"team=b", "team notin (b)", false},
		{"team notin (b, c)", "team notin (b)", true},
		{"team notin (b)", "team notin (b, c)", false},
		{"!team", "team notin (b)", true},
		{"!team", "!team", true},
		{"team", "!team", false},
	}
	for _, tc := range cases {
		if got := MustSelector(tc.narrow).Narrows(MustSelector(tc.wide)); got != tc.want {
			t.Errorf("%q narrows %q: %v, want %v", tc.narrow, tc.wide, got, tc.want)
		}
	}
}
