package db

import (
	"strings"
	"testing"
)

func TestValidateLabels(t *testing.T) {
	ok := []Labels{
		nil,
		{"team": "a"},
		{"env": ""},
		{"fallbck.io/tier": "gold_1.x-y"},
		{"a": strings.Repeat("v", 63)},
	}
	for _, l := range ok {
		if err := ValidateLabels(l); err != nil {
			t.Errorf("%v: %v", l, err)
		}
	}
	bad := []Labels{
		{"": "x"},
		{"-team": "a"},
		{"team": "a b"},
		{"team": "-a"},
		{"Bad_Prefix/x": "a"},
		{"/x": "a"},
		{"a": strings.Repeat("v", 64)},
		{strings.Repeat("k", 64): "a"},
		{"team": "a=b"},
	}
	for _, l := range bad {
		if err := ValidateLabels(l); err == nil {
			t.Errorf("%v: expected an error", l)
		}
	}
	many := Labels{}
	for i := 0; i <= MaxLabels; i++ {
		many[strings.Repeat("k", i+1)] = "v"
	}
	if ValidateLabels(many) == nil {
		t.Error("more than MaxLabels entries should fail")
	}
}

func TestLabelsHelpers(t *testing.T) {
	l := Labels{"b": "2", "a": "1"}
	if l.String() != "a=1,b=2" {
		t.Errorf("String = %s", l.String())
	}
	if !l.Contains(Labels{"a": "1"}) || l.Contains(Labels{"a": "2"}) || !l.Contains(nil) {
		t.Error("Contains")
	}
	if Labels(nil).JSON() != "{}" {
		t.Error("nil labels must render as {} for the NOT NULL columns")
	}
	if !Labels(nil).Equal(Labels{}) || l.Equal(Labels{"a": "1"}) {
		t.Error("Equal")
	}
}
