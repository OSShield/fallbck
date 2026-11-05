package naming

import "testing"

func TestSafeName(t *testing.T) {
	cases := map[string]string{
		"alice@contoso.com":               "alice_contoso.com",
		"Sales & Marketing":               "sales-marketing",
		"contoso.sharepoint.com/sites/HR": "contoso.sharepoint.com-sites-hr",
		"  ":                              "unnamed",
		"-leading":                        "leading",
		"ÄÖ team":                         "team",
		".hidden":                         "hidden",
	}
	for in, want := range cases {
		if got := SafeName(in); got != want {
			t.Errorf("SafeName(%q) = %q, want %q", in, got, want)
		}
		if !ValidGroupID(SafeName(in)) {
			t.Errorf("SafeName(%q) is not a valid group id", in)
		}
	}
}

func TestSelected(t *testing.T) {
	if !Selected("alice@contoso.com", nil, nil) {
		t.Error("no globs selects everything")
	}
	if !Selected("Alice@contoso.com", []string{"*@contoso.com"}, nil) || Selected("bob@fabrikam.com", []string{"*@contoso.com"}, nil) {
		t.Error("include")
	}
	if Selected("alice@contoso.com", nil, []string{"alice@*"}) {
		t.Error("exclude")
	}
}

func TestCleanGlobs(t *testing.T) {
	got, err := CleanGlobs("x", []string{" a* ", "", "b"})
	if err != nil || len(got) != 2 || got[0] != "a*" {
		t.Errorf("CleanGlobs = %v, %v", got, err)
	}
	if _, err := CleanGlobs("x", []string{"[a"}); err == nil {
		t.Error("bad glob accepted")
	}
}
