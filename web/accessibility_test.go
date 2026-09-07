package web

import (
	"bytes"
	"html/template"
	"io/fs"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/osshield/fallbck/pkg/config"
	"golang.org/x/net/html"
)

func documentNodes(t *testing.T, body string) []*html.Node {
	t.Helper()
	root, err := html.Parse(strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	var nodes []*html.Node
	var walk func(*html.Node)
	walk = func(n *html.Node) {
		if n.Type == html.ElementNode {
			nodes = append(nodes, n)
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}
	walk(root)
	return nodes
}
func attr(n *html.Node, key string) string {
	for _, a := range n.Attr {
		if a.Key == key {
			return a.Val
		}
	}
	return ""
}
func checkReferences(t *testing.T, body string) {
	t.Helper()
	nodes := documentNodes(t, body)
	ids := map[string]bool{}
	for _, n := range nodes {
		if id := attr(n, "id"); id != "" {
			if ids[id] {
				t.Errorf("duplicate id %s", id)
			}
			ids[id] = true
		}
	}
	for _, n := range nodes {
		for _, key := range []string{"for", "aria-describedby", "aria-controls"} {
			for _, id := range strings.Fields(attr(n, key)) {
				if !ids[id] {
					t.Errorf("%s references missing %s", key, id)
				}
			}
		}
	}
}
func exportAccessibilityFixture(t *testing.T, name, body string) {
	t.Helper()
	dir := os.Getenv("FALLBCK_A11Y_EXPORT")
	if dir == "" {
		return
	}
	if err := os.MkdirAll(dir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, name+".html"), []byte(body), 0644); err != nil {
		t.Fatal(err)
	}
	err := fs.WalkDir(Content, "static", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		dest := filepath.Join(dir, path)
		if d.IsDir() {
			return os.MkdirAll(dest, 0755)
		}
		b, e := fs.ReadFile(Content, path)
		if e != nil {
			return e
		}
		return os.WriteFile(dest, b, 0644)
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestAccessibleDocuments(t *testing.T) {
	router := chi.NewRouter()
	u := NewUIHandler(nil, config.DefaultServerConfig(), Deps{})
	u.RegisterRoutes(router)
	for _, path := range []string{"/dashboard", "/agents", "/targets", "/jobs", "/kubernetes", "/runs", "/tokens", "/apikeys", "/runs/invalid"} {
		t.Run(path, func(t *testing.T) {
			w := httptest.NewRecorder()
			router.ServeHTTP(w, httptest.NewRequest("GET", path, nil))
			body := w.Body.String()
			checkReferences(t, body)
			counts := map[string]int{}
			for _, n := range documentNodes(t, body) {
				counts[n.Data]++
				if n.Data == "html" && attr(n, "lang") != "en" {
					t.Error("missing document language")
				}
				if n.Data == "th" && attr(n, "scope") != "col" {
					t.Error("table header lost its column association")
				}
			}
			for _, tag := range []string{"main", "h1"} {
				if counts[tag] != 1 {
					t.Errorf("expected one %s, got %d", tag, counts[tag])
				}
			}
			if !strings.Contains(body, `href="#main"`) || !strings.Contains(body, `id="main" tabindex="-1"`) {
				t.Error("missing focusable skip target")
			}
			exportAccessibilityFixture(t, strings.ReplaceAll(strings.TrimPrefix(path, "/"), "/", "-"), body)
		})
	}
	for _, resource := range []string{"targets", "jobs", "agents", "tokens", "apikeys"} {
		t.Run("form/"+resource, func(t *testing.T) {
			w := httptest.NewRecorder()
			router.ServeHTTP(w, httptest.NewRequest("GET", "/ui/"+resource+"/form", nil))
			body := w.Body.String()
			checkReferences(t, body)
			nodes := documentNodes(t, body)
			labels := map[string]bool{}
			for _, n := range nodes {
				if n.Data == "label" {
					labels[attr(n, "for")] = true
				}
			}
			for _, n := range nodes {
				if n.Data != "input" && n.Data != "select" && n.Data != "textarea" {
					continue
				}
				if attr(n, "type") == "checkbox" {
					if n.Parent.Data != "label" {
						t.Error("checkbox has no label")
					}
				} else if !labels[attr(n, "id")] {
					t.Errorf("unlabeled field %s", attr(n, "name"))
				}
				if attr(n, "aria-describedby") == "" {
					t.Errorf("missing help association for %s", attr(n, "name"))
				}
			}
		})
	}
	for _, state := range []string{"normal", "error", "unconfigured"} {
		tmpl := template.Must(template.ParseFS(Content, "templates/login.html"))
		var out bytes.Buffer
		data := map[string]any{"Version": "accessibility fixture", "Next": "/dashboard", "NoOIDC": state == "unconfigured"}
		if state == "error" {
			data["Error"] = "Sign-in failed. Please try again."
		}
		if err := tmpl.ExecuteTemplate(&out, "login", data); err != nil {
			t.Fatal(err)
		}
		exportAccessibilityFixture(t, "login-"+state, out.String())
		checkReferences(t, out.String())
	}
	w := httptest.NewRecorder()
	u.renderLoadError(w, httptest.NewRequest("GET", "/jobs", nil), fs.ErrNotExist)
	exportAccessibilityFixture(t, "load-error", w.Body.String())
}

func TestStatusHasTextAndDistinctShape(t *testing.T) {
	tmpl := template.Must(template.New("components").Funcs(template.FuncMap{"shortID": func(any) string { return "test-id" }, "formatBytes": formatBytes, "formatTime": formatTime}).ParseFS(Content, "templates/components.html"))
	shapes := map[string]string{}
	var gallery strings.Builder
	for _, state := range []string{"completed", "running", "failed", "disabled", "cancelled", "pending", "unverified", "online", "offline", "enabled", "active", "revoked", "expired", "exhausted", "configured", "missing", "verified"} {
		var out bytes.Buffer
		if err := tmpl.ExecuteTemplate(&out, "status", state); err != nil {
			t.Fatal(err)
		}
		body := out.String()
		if !strings.Contains(body, state) || !strings.Contains(body, `aria-hidden="true"`) {
			t.Errorf("status %s lacks text or decorative icon semantics", state)
		}
		start := strings.Index(body, "<svg")
		end := strings.Index(body, "</svg>")
		if start < 0 || end < 0 {
			t.Fatalf("status %s has no shape", state)
		}
		shapes[state] = body[start:end]
		gallery.WriteString(body + " ")
	}
	// The principal execution states must remain different in monochrome.
	unique := map[string]bool{}
	for _, state := range []string{"completed", "running", "failed", "disabled", "cancelled", "pending", "unverified"} {
		if unique[shapes[state]] {
			t.Errorf("%s reuses an indistinguishable execution shape", state)
		}
		unique[shapes[state]] = true
	}
	exportAccessibilityFixture(t, "statuses", `<!doctype html><html lang="en"><head><meta name="viewport" content="width=device-width,initial-scale=1"><title>Status review</title><link rel="stylesheet" href="/static/css/app.css"><script src="/static/js/theme.js"></script><script src="/static/js/app.js" defer></script></head><body><main><h1>Status indicators</h1><button class="btn" data-theme-toggle>Dark</button><p style="display:flex;flex-wrap:wrap;gap:16px;padding:24px 0">`+gallery.String()+`</p></main></body></html>`)
}
