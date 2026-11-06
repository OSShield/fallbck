package vcs

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	spec "github.com/osshield/fallbck/pkg/vcs"
)

// fakeGitLabAPI serves /version, /user and the project listings. Group listings
// are paginated one project per page, with next links pointing at another host to
// check that only their query is followed.
func fakeGitLabAPI(t *testing.T, admin bool) *httptest.Server {
	t.Helper()
	type proj = map[string]any
	all := []proj{
		{"id": 1, "path_with_namespace": "platform/api", "wiki_access_level": "enabled", "statistics": map[string]any{"repository_size": 2048}},
		{"id": 2, "path_with_namespace": "platform/infra/terraform", "wiki_access_level": "disabled"},
		{"id": 3, "path_with_namespace": "platform/old", "archived": true},
		{"id": 4, "path_with_namespace": "platform/api-fork", "forked_from_project": map[string]any{"id": 1}},
		{"id": 5, "path_with_namespace": "data/pipelines", "wiki_enabled": false},
		{"id": 6, "path_with_namespace": "platform/../escape"},
	}
	groups := map[string][]proj{
		"platform":       {all[0], all[1], all[2], all[3], all[5]},
		"platform/infra": {all[1]},
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("PRIVATE-TOKEN") != "glpat-test" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		path := strings.TrimPrefix(r.URL.EscapedPath(), "/api/v4")
		switch {
		case path == "/version":
			_ = json.NewEncoder(w).Encode(map[string]string{"version": "17.5.0"})
		case path == "/user":
			_ = json.NewEncoder(w).Encode(map[string]any{"username": "backup", "is_admin": admin})
		case path == "/projects":
			if !admin && r.URL.Query().Get("membership") != "true" {
				t.Error("a non-admin listing must ask for membership")
			}
			_ = json.NewEncoder(w).Encode(all[4:5])
		case strings.HasPrefix(path, "/groups/") && strings.HasSuffix(path, "/projects"):
			name := strings.ReplaceAll(strings.TrimSuffix(strings.TrimPrefix(path, "/groups/"), "/projects"), "%2F", "/")
			list, ok := groups[name]
			if !ok {
				w.WriteHeader(http.StatusNotFound)
				_, _ = w.Write([]byte(`{"message":"404 Group Not Found"}`))
				return
			}
			page := 0
			_, _ = fmt.Sscan(r.URL.Query().Get("page"), &page)
			if page+1 < len(list) {
				q := r.URL.Query()
				q.Set("page", fmt.Sprint(page+1))
				w.Header().Set("Link", `<https://elsewhere.example/api/v4`+path+`?`+q.Encode()+`>; rel="next", <https://elsewhere.example/>; rel="first"`)
			}
			_ = json.NewEncoder(w).Encode(list[page : page+1])
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestGitLabProvider(t *testing.T) {
	srv := fakeGitLabAPI(t, false)
	creds := spec.Credentials{Provider: spec.ProviderGitLab, BaseURL: srv.URL, Token: "glpat-test"}
	no := false

	p := &GitLabProvider{Spec: &spec.Spec{Groups: []string{"platform", "platform/infra", "missing"}, Archived: &no, Forks: &no}, Credentials: creds, Client: srv.Client()}
	projects, warnings, err := p.Projects(ctx(t))
	if err != nil {
		t.Fatal(err)
	}
	var paths []string
	for _, pr := range projects {
		paths = append(paths, pr.Path)
	}
	if want := []string{"platform/api", "platform/infra/terraform"}; !slices.Equal(paths, want) {
		t.Fatalf("projects = %v, want %v (archived, fork, unsafe path and duplicate left out)", paths, want)
	}
	api := projects[0]
	if api.Key != "p1" || api.URL != srv.URL+"/platform/api.git" || api.WikiURL != srv.URL+"/platform/api.wiki.git" || api.Size != 2048 {
		t.Errorf("platform/api = %+v", api)
	}
	if projects[1].WikiURL != "" {
		t.Error("a disabled wiki must not be fetched")
	}
	joined := strings.Join(warnings, "\n")
	if !strings.Contains(joined, "missing") || !strings.Contains(joined, "unusable path") {
		t.Errorf("warnings = %v", warnings)
	}
	var src spec.SourceInfo
	p.Describe(&src)
	if src.Version != "17.5.0" || src.Username != "backup" || src.IsAdmin {
		t.Errorf("source = %+v", src)
	}

	// Without subgroups, platform/infra/terraform is out of scope
	sub := false
	p = &GitLabProvider{Spec: &spec.Spec{Groups: []string{"platform"}, IncludeSubgroups: &sub}, Credentials: creds, Client: srv.Client()}
	if projects, _, err = p.Projects(ctx(t)); err != nil || slices.ContainsFunc(projects, func(pr Project) bool { return pr.Path == "platform/infra/terraform" }) {
		t.Errorf("without subgroups: %v, %v", projects, err)
	}

	// No group exists: the run cannot back up anything
	p = &GitLabProvider{Spec: &spec.Spec{Groups: []string{"missing"}}, Credentials: creds, Client: srv.Client()}
	if _, _, err := p.Projects(ctx(t)); err == nil {
		t.Error("expected an error when none of the groups exist")
	}

	// No groups and no admin: the user's projects, with a warning
	p = &GitLabProvider{Spec: &spec.Spec{}, Credentials: creds, Client: srv.Client()}
	projects, warnings, err = p.Projects(ctx(t))
	if err != nil || len(projects) != 1 || projects[0].WikiURL != "" || len(warnings) != 1 || !strings.Contains(warnings[0], "not an administrator") {
		t.Errorf("membership listing: %v, %v, %v", projects, warnings, err)
	}

	// A wrong token stops the listing
	creds.Token = "wrong"
	p = &GitLabProvider{Spec: &spec.Spec{Groups: []string{"platform"}}, Credentials: creds, Client: srv.Client()}
	if _, _, err := p.Projects(ctx(t)); err == nil || !strings.Contains(err.Error(), "rejected the token") {
		t.Errorf("wrong token: %v", err)
	}
}
