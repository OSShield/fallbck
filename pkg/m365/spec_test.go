package m365

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/google/uuid"
)

func TestSpecValidate(t *testing.T) {
	tenant := uuid.New()
	off := false
	cases := map[string]struct {
		spec *Spec
		ok   bool
	}{
		"nil":          {nil, false},
		"no tenant":    {&Spec{}, false},
		"minimal":      {&Spec{TenantID: tenant}, true},
		"no workloads": {&Spec{TenantID: tenant, Workloads: Workloads{Mailboxes: &off, OneDrive: &off, Sites: &off, Teams: &off, Entra: &off}}, false},
		"bad glob":     {&Spec{TenantID: tenant, Users: UserSelection{Include: []string{"[a"}}}, false},
		"bad pattern":  {&Spec{TenantID: tenant, ExcludePaths: []string{"[unclosed"}}, false},
		"concurrency":  {&Spec{TenantID: tenant, Concurrency: 99}, false},
		"bad group":    {&Spec{TenantID: tenant, BackupID: "has space"}, false},
		"good group":   {&Spec{TenantID: tenant, BackupID: "m365-contoso"}, true},
	}
	for name, c := range cases {
		err := c.spec.Validate()
		if (err == nil) != c.ok {
			t.Errorf("%s: err=%v, want ok=%v", name, err, c.ok)
		}
		if err != nil && !errors.Is(err, ErrInvalidSpec) {
			t.Errorf("%s: error does not wrap ErrInvalidSpec: %v", name, err)
		}
	}
	// Normalisation
	s := &Spec{TenantID: tenant, Users: UserSelection{Include: []string{" alice@* ", ""}}, ExcludeTypes: []string{" IPM.Note ", ""}, BackupID: " g "}
	if err := s.Validate(); err != nil {
		t.Fatal(err)
	}
	if len(s.Users.Include) != 1 || s.Users.Include[0] != "alice@*" || len(s.ExcludeTypes) != 1 || s.BackupID != "g" {
		t.Errorf("not normalised: %+v", s)
	}
}

func TestSpecDefaults(t *testing.T) {
	var absent, empty Spec
	if err := json.Unmarshal([]byte(`{"tenant_id":"`+uuid.NewString()+`"}`), &absent); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal([]byte(`{"tenant_id":"`+uuid.NewString()+`","mail_folder_excludes":[],"concurrency":2}`), &empty); err != nil {
		t.Fatal(err)
	}
	if got := absent.EffMailFolderExcludes(); len(got) != len(DefaultMailFolderExcludes) {
		t.Errorf("absent list should mean the defaults, got %v", got)
	}
	if got := empty.EffMailFolderExcludes(); len(got) != 0 {
		t.Errorf("empty list should mean none, got %v", got)
	}
	if absent.EffConcurrency() != DefaultConcurrency || empty.EffConcurrency() != 2 {
		t.Errorf("concurrency defaults: %d %d", absent.EffConcurrency(), empty.EffConcurrency())
	}
	if !absent.Workloads.EffTeams() || !absent.Users.EffShared() || absent.Users.Unlicensed {
		t.Error("workload / selection defaults")
	}
	var nilSpec *Spec
	if nilSpec.EffConcurrency() != DefaultConcurrency || nilSpec.Summary() == "" || nilSpec.Clone() != nil {
		t.Error("nil spec helpers")
	}
}

func TestSafeNameAndGroups(t *testing.T) {
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
		if !groupIDRe.MatchString(SafeName(in)) {
			t.Errorf("SafeName(%q) is not a valid group id", in)
		}
	}
	if DefaultBackupID("Contoso Ltd") != "m365-contoso-ltd" {
		t.Error(DefaultBackupID("Contoso Ltd"))
	}
	g := UnitGroup("m365-contoso", UnitUser, "Alice@Contoso.com")
	if g != "m365-contoso-user-alice_contoso.com" || !strings.HasPrefix(g, GroupPrefix("m365-contoso")) {
		t.Error(g)
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

func TestSummary(t *testing.T) {
	off := false
	s := &Spec{TenantID: uuid.New(), Workloads: Workloads{Teams: &off}, Users: UserSelection{Groups: []string{"Backup users"}}}
	got := s.Summary()
	if !strings.Contains(got, "mailboxes") || strings.Contains(got, "Teams") || !strings.Contains(got, "Backup users") {
		t.Error(got)
	}
	c := s.Clone()
	c.Users.Groups[0] = "changed"
	*c.Workloads.Teams = true
	if s.Users.Groups[0] != "Backup users" || *s.Workloads.Teams {
		t.Error("Clone shares memory with the original")
	}
}
