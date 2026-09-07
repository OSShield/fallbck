package web

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/osshield/fallbck/pkg/auth"
	"github.com/osshield/fallbck/pkg/config"
	"github.com/osshield/fallbck/pkg/db"
	"github.com/osshield/fallbck/pkg/dbbackup"
	"github.com/osshield/fallbck/pkg/k8sbackup"
	"github.com/osshield/fallbck/pkg/rundetail"
)

func TestHTMXNavigationFragments(t *testing.T) {
	router := chi.NewRouter()
	NewUIHandler(nil, config.DefaultServerConfig(), Deps{}).RegisterRoutes(router)
	for _, path := range []string{"/dashboard", "/agents", "/targets", "/jobs", "/kubernetes", "/runs", "/tokens", "/apikeys"} {
		t.Run(path, func(t *testing.T) {
			r := httptest.NewRequest("GET", path, nil)
			r.Header.Set("HX-Request", "true")
			w := httptest.NewRecorder()
			router.ServeHTTP(w, r)
			body := w.Body.String()
			if w.Code != 200 || !strings.Contains(body, `id="app"`) {
				t.Fatalf("%d %s", w.Code, body)
			}
			if strings.Contains(body, "<html") || strings.Contains(body, "<script") {
				t.Fatal("navigation fragment must not reload document scripts")
			}
			if w.Header().Get("Cache-Control") != "no-store" || w.Header().Get("Vary") != "HX-Request" {
				t.Fatal("private fragments must not be cached as full pages")
			}
		})
	}
}
func defaultForm(resource string) url.Values {
	values := url.Values{}
	for _, s := range formSchema(resource) {
		for _, f := range s.Fields {
			value := f.Value
			if f.Checked {
				value = "on"
			}
			if f.Required && value == "" {
				value = "test"
			}
			values.Set(f.Name, value)
		}
	}
	return values
}
func TestFormDecodingAllBackupTypes(t *testing.T) {
	for _, kind := range []string{"filesystem", "database", "kubernetes"} {
		engines := []string{""}
		if kind == "database" {
			engines = []string{"postgres", "mysql", "mongodb"}
		}
		for _, engine := range engines {
			t.Run(kind+"/"+engine, func(t *testing.T) {
				values := defaultForm("jobs")
				values.Set("job_type", kind)
				values.Set("agent_id", uuid.NewString())
				values.Set("target_id", uuid.NewString())
				values.Set("backup_paths", "/etc\n /srv/data \n")
				values.Set("exclude_paths", "*.tmp\n/cache")
				values.Set("retention_policy.keep_yearly", "3")
				values.Set("db_config.engine", engine)
				values.Set("db_config.password", "a secret with spaces ")
				values.Set("k8s_config.volumes.snapshot_class_overrides", "fast.csi.example.com=snapshot-fast\nslow=snapshot-slow")
				payload, err := decodeForm("jobs", values)
				if err != nil {
					t.Fatal(err)
				}
				encoded, _ := json.Marshal(payload)
				var job db.BackupJob
				if err = json.Unmarshal(encoded, &job); err != nil {
					t.Fatal(err)
				}
				if job.JobType != kind || job.RetentionPolicy.KeepYearly != 3 {
					t.Fatal(job)
				}
				switch kind {
				case "filesystem":
					if len(job.BackupPaths) != 2 || job.DBConfig != nil || job.K8sConfig != nil {
						t.Fatal("hidden sections were submitted")
					}
				case "database":
					if len(job.BackupPaths) != 0 || job.K8sConfig != nil || job.DBConfig.Engine != engine || job.DBConfig.Password != "a secret with spaces " {
						t.Fatal("database fields lost or hidden sections submitted")
					}
				case "kubernetes":
					if job.DBConfig != nil || job.K8sConfig.Volumes.SnapshotClassOverrides["fast.csi.example.com"] != "snapshot-fast" || job.K8sConfig.Volumes.Parallelism != 2 {
						t.Fatal("cluster options not retained")
					}
				}
			})
		}
	}
}
func TestFormRejectsInvalidInput(t *testing.T) {
	for _, tc := range []struct{ resource, key, value string }{{"tokens", "max_uses", "-1"}, {"tokens", "days", "abc"}, {"apikeys", "days", "9999999999"}, {"targets", "name", ""}, {"targets", "pxar_format", "unsupported"}, {"jobs", "retention_policy.keep_last", "-2"}} {
		values := defaultForm(tc.resource)
		values.Set(tc.key, tc.value)
		if _, err := decodeForm(tc.resource, values); err == nil {
			t.Errorf("accepted %s=%s", tc.key, tc.value)
		}
	}
	values := defaultForm("jobs")
	values.Set("job_type", "kubernetes")
	values.Set("k8s_config.volumes.snapshot_class_overrides", "invalid pair")
	if _, err := decodeForm("jobs", values); err == nil {
		t.Fatal("accepted invalid snapshot override")
	}
}
func TestUIValidationIsHTMLAndEscaped(t *testing.T) {
	w := httptest.NewRecorder()
	uiError(w, `<script>alert("x")</script>`, 422, "#form-errors")
	if w.Code != 422 || w.Header().Get("HX-Retarget") != "#form-errors" || strings.Contains(w.Body.String(), "<script>") {
		t.Fatal("unsafe validation response")
	}
}
func TestUIRoutesRequireSessionAndCSRF(t *testing.T) {
	cfg := config.DefaultServerConfig()
	tm := auth.NewTokenManager("test-secret-key-must-be-very-long-123456")
	router := chi.NewRouter()
	NewUIHandler(nil, cfg, Deps{TokenManager: tm, Admin: auth.NewAdminAuth(tm, nil, false)}).RegisterRoutes(router)
	session, _, err := tm.CreateSession(&auth.Identity{Subject: "test", Email: "test@example.invalid"}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"/ui/targets/save", "/ui/jobs/save", "/ui/tokens/save", "/ui/apikeys/save", "/ui/agents/save", "/ui/agents/test/delete", "/ui/jobs/test/run", "/ui/runs/test/cancel", "/ui/apikeys/test/delete"} {
		r := httptest.NewRequest("POST", path, nil)
		r.Header.Set("HX-Request", "true")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, r)
		if w.Code != 401 || w.Header().Get("HX-Redirect") == "" {
			t.Errorf("%s: missing session: %d", path, w.Code)
		}
		r = httptest.NewRequest("POST", path, nil)
		r.AddCookie(&http.Cookie{Name: auth.SessionCookieName, Value: session})
		w = httptest.NewRecorder()
		router.ServeHTTP(w, r)
		if w.Code != 403 {
			t.Errorf("%s: missing CSRF: %d", path, w.Code)
		}
	}
	r := httptest.NewRequest("GET", "/ui/jobs/form", nil)
	r.Header.Set("HX-Request", "true")
	r.Header.Set("HX-Current-URL", "https://evil.invalid/stolen")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, r)
	if strings.Contains(w.Header().Get("HX-Redirect"), "evil") {
		t.Fatal("external redirect")
	}
}
func TestRunDetailServerRendering(t *testing.T) {
	now := time.Now()
	base := db.BackupRun{ID: uuid.New(), JobID: uuid.New(), Status: db.RunStatusRunning, JobName: `<script>bad</script>`, StartTime: &now, Progress: rundetail.Marshal(rundetail.Progress{Phase: "Uploading", Items: map[string]rundetail.ProgressItem{"pvc": {Name: "data", Status: "running", BytesUploaded: 2048}}})}
	cases := []struct {
		name    string
		details json.RawMessage
		want    string
	}{
		{"filesystem", rundetail.Marshal(rundetail.Filesystem{Type: "filesystem", Paths: []string{"/etc"}, Archives: []rundetail.ArchiveStat{{Name: "root.pxar", SizeBytes: 1000}}}), "root.pxar"},
		{"database", rundetail.WrapManifest("database", rundetail.Marshal(dbbackup.Manifest{Engine: "postgres", Databases: []dbbackup.DatabaseEntry{{Name: "accounts"}}, Restore: dbbackup.Restore{Commands: []string{"pg_restore database.dump"}}})), "pg_restore"},
		{"kubernetes", rundetail.WrapManifest("kubernetes", rundetail.Marshal(k8sbackup.Manifest{Volumes: []k8sbackup.VolumeResult{{PVCName: "persistent-data", Status: "completed"}}, Restore: k8sbackup.ManifestRestore{Commands: []string{"kubectl apply -f resources"}}})), "persistent-data"},
	}
	u := NewUIHandler(nil, config.DefaultServerConfig(), Deps{})
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			run := base
			run.Details = tc.details
			w := httptest.NewRecorder()
			u.renderFragment(w, "run-panel", runDetailData(&run), "run_detail.html")
			body := w.Body.String()
			if w.Code != 200 || !strings.Contains(body, tc.want) || !strings.Contains(body, "Uploading") || !strings.Contains(body, `hx-trigger="every 3s"`) {
				t.Fatalf("%d %s", w.Code, body)
			}
			if strings.Contains(body, "<script>bad") {
				t.Fatal("run data was not escaped")
			}
			run.Status = db.RunStatusCompleted
			w = httptest.NewRecorder()
			u.renderFragment(w, "run-panel", runDetailData(&run), "run_detail.html")
			if strings.Contains(w.Body.String(), `hx-trigger="every 3s"`) {
				t.Fatal("completed run still polls")
			}
		})
	}
}
func TestAdvancedSettingsSurviveFormUpdates(t *testing.T) {
	original := map[string]any{"db_config": map[string]any{"tls": map[string]any{"cert_file": "client.pem"}, "postgres": map[string]any{"extra_dump_args": []string{"--no-owner"}}}, "k8s_config": map[string]any{"volumes": map[string]any{"snapshot_class_overrides": map[string]any{"old": "old"}}}}
	updates := map[string]any{"db_config": map[string]any{"tls": map[string]any{"mode": "verify-full"}}, "k8s_config": map[string]any{"volumes": map[string]any{"snapshot_class_overrides": map[string]string{}}}}
	mergeFormPayload(original, updates)
	b, _ := json.Marshal(original)
	if !strings.Contains(string(b), "client.pem") || !strings.Contains(string(b), "--no-owner") || strings.Contains(string(b), `"old"`) {
		t.Fatal(string(b))
	}
}
