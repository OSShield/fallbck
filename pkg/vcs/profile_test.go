package vcs

import (
	"os"
	"path/filepath"
	"testing"
)

func TestProfileToken(t *testing.T) {
	p := &Profile{URL: "https://GitLab.example.com/", Token: " glpat-x "}
	if err := p.Validate(); err != nil || p.URL != "https://gitlab.example.com" || p.Token != "glpat-x" {
		t.Fatalf("%+v %v", p, err)
	}
	if tok, err := p.ResolveToken(); err != nil || tok != "glpat-x" {
		t.Errorf("token %q %v", tok, err)
	}

	file := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(file, []byte("glpat-from-file\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	fp := &Profile{URL: "https://gitlab.example.com", TokenFile: file}
	if err := fp.Validate(); err != nil {
		t.Fatal(err)
	}
	if tok, err := fp.ResolveToken(); err != nil || tok != "glpat-from-file" {
		t.Errorf("file token %q %v", tok, err)
	}
	for content, want := range map[string]string{"": "empty", "a b": "spaces"} {
		if err := os.WriteFile(file, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := fp.ResolveToken(); err == nil {
			t.Errorf("token file %q (%s) accepted", content, want)
		}
	}
	missing := &Profile{URL: "https://x", TokenFile: filepath.Join(t.TempDir(), "nope")}
	if _, err := missing.ResolveToken(); err == nil {
		t.Error("missing token file accepted")
	}
	if !ValidProfileName("gitlab-internal") || ValidProfileName("-x") || ValidProfileName("a b") {
		t.Error("ValidProfileName")
	}
	if NormalizeProfileName(" GitLab ") != "gitlab" {
		t.Error("NormalizeProfileName")
	}
}
