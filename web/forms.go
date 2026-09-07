package web

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
)

// The HTML adapter uses the existing API handlers so validation, secret handling,
// scheduling and authorization semantics remain shared with the CLI/API.
type apiResponse struct {
	header http.Header
	status int
	bytes.Buffer
}

func (w *apiResponse) Header() http.Header    { return w.header }
func (w *apiResponse) WriteHeader(status int) { w.status = status }
func (u *UIHandler) callAPI(r *http.Request, handler http.HandlerFunc, id string, payload any) *apiResponse {
	out := &apiResponse{header: make(http.Header), status: http.StatusOK}
	if u.DB == nil || u.deps.API == nil {
		out.status = 503
		out.WriteString(`{"error":"The database is unavailable. Try again after reconnecting."}`)
		return out
	}
	clone := r.Clone(r.Context())
	route := chi.NewRouteContext()
	route.URLParams.Add("id", id)
	clone = clone.WithContext(context.WithValue(clone.Context(), chi.RouteCtxKey, route))
	if payload != nil {
		body, _ := json.Marshal(payload)
		clone.Body = io.NopCloser(bytes.NewReader(body))
		clone.Header = r.Header.Clone()
		clone.Header.Set("Content-Type", "application/json")
	}
	handler(out, clone)
	return out
}
func (u *UIHandler) registerUIRoutes(r chi.Router) {
	r.Get("/ui/{resource}/form", u.handleForm)
	r.Post("/ui/{resource}/save", u.handleSave)
	r.Post("/ui/{resource}/{id}/{action}", u.handleAction)
}
func (u *UIHandler) renderFragment(w http.ResponseWriter, name string, data any, files ...string) {
	paths := []string{"templates/components.html"}
	for _, file := range files {
		paths = append(paths, "templates/"+file)
	}
	t, err := template.New(name).Funcs(template.FuncMap{"formatBytes": formatBytes, "formatTime": formatTime, "prettyJSON": prettyJSON, "join": strings.Join, "shortID": func(v any) string {
		s := fmt.Sprint(v)
		if len(s) > 8 {
			return s[:8]
		}
		return s
	}}).ParseFS(Content, paths...)
	var out bytes.Buffer
	if err == nil {
		err = t.ExecuteTemplate(&out, name, data)
	}
	if err != nil {
		http.Error(w, "Unable to render this view.", 500)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(out.Bytes())
}
func uiError(w http.ResponseWriter, message string, status int, target string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	if target != "" {
		w.Header().Set("HX-Retarget", target)
		w.Header().Set("HX-Reswap", "innerHTML")
		w.Header().Set("HX-Reselect", ".notice")
	}
	w.WriteHeader(status)
	fmt.Fprintf(w, `<div class="notice error" role="alert" tabindex="-1"><strong>Action could not be completed</strong><p>%s</p></div>`, template.HTMLEscapeString(message))
}
func apiError(out *apiResponse) string {
	var v map[string]any
	_ = json.Unmarshal(out.Bytes(), &v)
	if s, ok := v["error"].(string); ok {
		return s
	}
	return "The server could not complete this request. Please try again."
}
func uiLocation(w http.ResponseWriter, path string) {
	b, _ := json.Marshal(map[string]string{"path": path, "target": "#app", "select": "#app", "swap": "outerHTML"})
	w.Header().Set("HX-Location", string(b))
	w.WriteHeader(200)
}

type option struct{ Value, Label string }
type field struct {
	Name, Label, Type, Value, Help, Min, Max string
	Required, Checked                        bool
	Options                                  []option
}
type section struct {
	Title, Help, When string
	Fields            []field
}
type formView struct {
	Resource, ID, Title, Return, Timezone string
	Sections                              []section
}

func f(name, label, kind, value, help string) field {
	return field{Name: name, Label: label, Type: kind, Value: value, Help: help}
}
func req(name, label, kind, value, help string) field {
	v := f(name, label, kind, value, help)
	v.Required = true
	return v
}
func choice(name, label, value, help string, options ...string) field {
	v := f(name, label, "select", value, help)
	for _, o := range options {
		p := strings.SplitN(o, "|", 2)
		label := p[0]
		if len(p) > 1 {
			label = p[1]
		}
		v.Options = append(v.Options, option{p[0], label})
	}
	return v
}
func number(name, label, value, min, max string) field {
	v := f(name, label, "number", value, "")
	v.Min = min
	v.Max = max
	return v
}
func check(name, label string, on bool, help string) field {
	v := f(name, label, "checkbox", "", help)
	v.Checked = on
	return v
}

func formSchema(resource string) []section {
	switch resource {
	case "targets":
		return []section{
			{Title: "Repository", Fields: []field{req("name", "Target name", "text", "", "A name you can recognize during a restore."), req("endpoint", "PBS endpoint", "url", "", "Include the scheme and port, e.g. https://pbs.internal:8007."), req("datastore", "Datastore", "text", "", ""), f("namespace", "Namespace", "text", "", "Leave blank to use the root namespace."), choice("pxar_format", "Archive format", "v1", "", "v1|pxar v1 · catalog", "v2|pxar v2 · split metadata / payload (PBS 3.2+)")}},
			{Title: "Access & trust", Fields: []field{f("auth_token", "PBS API token", "password", "", "user@realm!tokenid:secret. Needs Datastore.Backup. Leave blank when editing to keep the stored token."), f("fingerprint", "TLS fingerprint", "text", "", "Optional SHA-256 fingerprint for a self-signed server."), check("tls_verify", "Verify TLS certificates", true, "")}},
		}
	case "tokens":
		return []section{{Title: "Enrollment permission", Fields: []field{req("name", "Token name", "text", "", ""), number("max_uses", "Maximum uses", "1", "0", "1000000"), number("days", "Valid for (days)", "7", "1", "3650")}, Help: "A maximum of 0 permits unlimited enrollments until expiry. The token is shown once."}}
	case "apikeys":
		return []section{{Title: "Automation access", Fields: []field{req("name", "Key name", "text", "", "Use a separate key for each integration."), number("days", "Expires in (days)", "90", "0", "3650")}, Help: "API keys grant administrator access. Set 0 days for no expiry. The key is shown once."}}
	case "agents":
		return []section{{Title: "Enroll a host", Help: "Install the appropriate FallBCK package on the host first. Generate a single-use token, valid for 24 hours, then run the command on that host.", Fields: []field{req("name", "Host or cluster label", "text", "", ""), choice("platform", "Agent installation", "linux", "", "linux|Linux · filesystem", "cli|Binary CLI · filesystem", "db|Database agent", "k8s|Kubernetes · Helm", "windows|Windows · binary CLI")}}}
	case "jobs":
		return jobSchema()
	}
	return nil
}
func jobSchema() []section {
	return []section{
		{Title: "Assignment", Fields: []field{req("name", "Job name", "text", "", ""), choice("job_type", "Backup type", "filesystem", "", "filesystem|Filesystem", "database|Database", "kubernetes|Kubernetes"), req("agent_id", "Agent", "select", "", ""), req("target_id", "PBS target", "select", "", "")}},
		{Title: "Filesystem", When: "job_type=filesystem", Fields: []field{req("backup_paths", "Directories to back up", "lines", "", "One absolute path per line."), f("exclude_paths", "Exclude patterns", "lines", "", "One per line. Uses proxmox-backup-client patterns; .pxarexclude files are also honored.")}},
		{Title: "Database connection", When: "job_type=database", Fields: []field{choice("db_config.engine", "Engine", "postgres", "", "postgres|PostgreSQL", "mysql|MySQL / MariaDB", "mongodb|MongoDB"), req("db_config.host", "Host or Unix socket", "text", "", ""), number("db_config.port", "Port (0 = engine default)", "0", "0", "65535"), f("db_config.user", "User", "text", "", ""), f("db_config.password", "Password", "password", "", "Leave blank to keep an existing password, or use an agent credential profile."), check("db_config.clear_password", "Clear stored password", false, ""), f("db_config.profile", "Credential profile", "text", "", "Resolved on the agent; defaults to the engine name."), f("db_config.databases", "Databases", "lines", "", "One per line. Leave blank for all databases."), choice("db_config.tls.mode", "TLS mode", "", "", "|Prefer (default)", "disable|Disabled", "require|Require · without verification", "verify-ca|Verify CA", "verify-full|Verify CA & hostname"), f("db_config.tls.ca_file", "CA file on agent", "text", "", ""), choice("db_config.compression", "Dump compression", "none", "", "none|None · best PBS deduplication", "gzip|gzip · less spool disk"), f("db_config.backup_id", "Backup group ID", "text", "", "Defaults to db-<engine>-<host>.")}},
		{Title: "PostgreSQL", When: "job_type=database db_config.engine=postgres", Fields: []field{choice("db_config.postgres.mode", "Mode", "dump", "", "dump|Logical dump", "basebackup|Physical base backup + WAL", "both|Logical & physical"), choice("db_config.postgres.format", "Dump format", "custom", "", "custom|Custom · pg_restore", "plain|Plain SQL · psql"), choice("db_config.postgres.role_passwords", "Role passwords", "auto", "", "auto|Include when superuser", "include|Include", "omit|Omit"), check("db_config.postgres.globals", "Include globals", true, "Roles and tablespaces via pg_dumpall.")}},
		{Title: "MySQL / MariaDB", When: "job_type=database db_config.engine=mysql", Fields: []field{check("db_config.mysql.single_transaction", "Consistent snapshot", true, "Uses --single-transaction for InnoDB tables."), check("db_config.mysql.include_binlogs", "Include binary logs", false, "Requires log_bin and REPLICATION SLAVE. Rotates the binary log per run.")}},
		{Title: "MongoDB", When: "job_type=database db_config.engine=mongodb", Fields: []field{choice("db_config.mongodb.read_preference", "Read preference", "", "", "|Primary (default)", "secondaryPreferred|Secondary preferred", "secondary|Secondary", "nearest|Nearest"), f("db_config.mongodb.auth_source", "Authentication source", "text", "", "Defaults to admin."), f("db_config.mongodb.replica_set", "Replica set", "text", "", ""), check("db_config.mongodb.oplog", "Capture the oplog", true, "Requires a replica set and all databases. Restore with --oplogReplay.")}},
		{Title: "Cluster resources", When: "job_type=kubernetes", Fields: []field{f("k8s_config.namespaces.include", "Include namespaces", "lines", "", "Blank means all namespaces. One pattern per line."), f("k8s_config.namespaces.exclude", "Exclude namespaces", "lines", "kube-system\nkube-node-lease\nkube-public", ""), f("k8s_config.label_selector", "Resource label selector", "text", "", ""), f("k8s_config.resources.exclude_extra", "Extra excluded resources", "lines", "", "Group/resource patterns, one per line."), check("k8s_config.resources.include_secrets", "Include Kubernetes Secrets", true, "Secrets are needed for disaster recovery and will be stored in the backup.")}},
		{Title: "Persistent volumes", When: "job_type=kubernetes", Fields: []field{choice("k8s_config.volumes.mode", "Volume selection", "all", "", "all|All matching PVCs", "labeled|Labeled PVCs", "none|Resources only"), f("k8s_config.volumes.label_selector", "PVC label selector", "text", "", ""), f("k8s_config.volumes.storage_classes", "Include storage classes", "lines", "", "Blank means all."), f("k8s_config.volumes.exclude_storage_classes", "Exclude storage classes", "lines", "", ""), f("k8s_config.volumes.snapshot_class_overrides", "Snapshot class overrides", "pairs", "", "One storage-class=snapshot-class pair per line."), check("k8s_config.volumes.allow_live_fallback", "Allow live-mount fallback", true, "Live mounts are crash-consistent when snapshots are unavailable."), check("k8s_config.volumes.continue_on_error", "Continue after a volume fails", true, "Records the failure and continues with remaining volumes."), number("k8s_config.volumes.parallelism", "Parallel volume uploads", "2", "1", "8"), f("k8s_config.volumes.snapshot_timeout", "Snapshot timeout", "text", "10m", "Maximum 30m."), f("k8s_config.volumes.volume_timeout", "Volume timeout", "text", "2h", "Maximum 5h."), number("k8s_config.volumes.forget_orphans_after_days", "Forget orphan groups after (days)", "0", "0", "36500")}},
		{Title: "Schedule & retention", Help: "Cron uses the server timezone displayed below. Leave the schedule blank for manual runs.", Fields: []field{f("schedule_cron", "Cron schedule", "text", "", "Example: 0 2 * * *, @daily, or @every 6h."), number("retention_policy.keep_last", "Keep last", "7", "0", "1000000"), number("retention_policy.keep_daily", "Keep daily", "7", "0", "1000000"), number("retention_policy.keep_weekly", "Keep weekly", "4", "0", "1000000"), number("retention_policy.keep_monthly", "Keep monthly", "12", "0", "1000000"), number("retention_policy.keep_yearly", "Keep yearly", "0", "0", "1000000"), check("enabled", "Enable automated schedule", true, ""), check("direct_pbs", "Connect agent directly to PBS", false, "The agent receives the target API token for each run, bypassing the server tunnel.")}},
	}
}

func flatten(prefix string, value any, out map[string]string) {
	switch v := value.(type) {
	case map[string]any:
		for k, item := range v {
			name := k
			if prefix != "" {
				name = prefix + "." + k
			}
			flatten(name, item, out)
		}
	case []any:
		var lines []string
		for _, item := range v {
			lines = append(lines, fmt.Sprint(item))
		}
		out[prefix] = strings.Join(lines, "\n")
	case nil:
	default:
		out[prefix] = fmt.Sprint(v)
	}
}
func (u *UIHandler) handleForm(w http.ResponseWriter, r *http.Request) {
	resource := chi.URLParam(r, "resource")
	sections := formSchema(resource)
	if sections == nil {
		http.NotFound(w, r)
		return
	}
	id := r.URL.Query().Get("id")
	values := map[string]string{}
	if id != "" {
		if u.deps.API == nil {
			uiError(w, "The database is unavailable.", 503, "")
			return
		}
		var handler http.HandlerFunc
		switch resource {
		case "targets":
			handler = u.deps.API.HandleGetTarget
		case "jobs":
			handler = u.deps.API.HandleGetJob
		default:
			http.NotFound(w, r)
			return
		}
		out := u.callAPI(r, handler, id, nil)
		if out.status >= 400 {
			uiError(w, apiError(out), out.status, "")
			return
		}
		var obj map[string]any
		_ = json.Unmarshal(out.Bytes(), &obj)
		flatten("", obj, values)
		// Map-valued override names may contain dots, so read the original map.
		if k, ok := obj["k8s_config"].(map[string]any); ok {
			if v, ok := k["volumes"].(map[string]any); ok {
				if pairs, ok := v["snapshot_class_overrides"].(map[string]any); ok {
					var lines []string
					for key, val := range pairs {
						lines = append(lines, key+"="+fmt.Sprint(val))
					}
					sort.Strings(lines)
					values["k8s_config.volumes.snapshot_class_overrides"] = strings.Join(lines, "\n")
				}
			}
		}
	}
	if id == "" && resource == "jobs" && r.URL.Query().Get("kind") == "kubernetes" {
		values["job_type"] = "kubernetes"
	}
	for si := range sections {
		for fi := range sections[si].Fields {
			f := &sections[si].Fields[fi]
			if val, ok := values[f.Name]; ok && f.Type != "password" {
				f.Value = val
				f.Checked = val == "true"
			}
			if f.Name == "agent_id" && u.DB != nil {
				agents, err := u.DB.ListAgents(r.Context())
				if err != nil {
					uiError(w, "Unable to load agents.", 503, "")
					return
				}
				f.Options = []option{{"", "Choose an agent"}}
				for _, a := range agents {
					f.Options = append(f.Options, option{a.ID.String(), a.Hostname + " · " + a.AgentType})
				}
			}
			if f.Name == "target_id" && u.DB != nil {
				targets, err := u.DB.ListTargets(r.Context())
				if err != nil {
					uiError(w, "Unable to load targets.", 503, "")
					return
				}
				f.Options = []option{{"", "Choose a target"}}
				for _, t := range targets {
					f.Options = append(f.Options, option{t.ID.String(), t.Name + " · " + t.Datastore})
				}
			}
		}
	}
	title := map[string]string{"targets": "Add PBS target", "jobs": "Create backup job", "tokens": "Generate enrollment token", "apikeys": "Create API key", "agents": "Add agent"}[resource]
	if id != "" {
		title = map[string]string{"targets": "Edit PBS target", "jobs": "Edit backup job"}[resource]
	}
	ret := "/" + resource
	if resource == "jobs" && values["job_type"] == "kubernetes" {
		ret = "/kubernetes"
	}
	u.renderFragment(w, "resource-form", formView{resource, id, title, ret, u.timezone(), sections}, "form.html")
}
func setNested(obj map[string]any, name string, value any) {
	parts := strings.Split(name, ".")
	for _, part := range parts[:len(parts)-1] {
		next, ok := obj[part].(map[string]any)
		if !ok {
			next = map[string]any{}
			obj[part] = next
		}
		obj = next
	}
	obj[parts[len(parts)-1]] = value
}
func lines(raw string) []string {
	out := []string{}
	for _, s := range strings.Split(raw, "\n") {
		if s = strings.TrimSpace(s); s != "" {
			out = append(out, s)
		}
	}
	return out
}
func matches(when string, values url.Values) bool {
	for _, cond := range strings.Fields(when) {
		p := strings.SplitN(cond, "=", 2)
		if values.Get(p[0]) != p[1] {
			return false
		}
	}
	return true
}
func decodeForm(resource string, values url.Values) (map[string]any, error) {
	payload := map[string]any{}
	for _, s := range formSchema(resource) {
		if !matches(s.When, values) {
			continue
		}
		for _, f := range s.Fields {
			raw := strings.TrimSpace(values.Get(f.Name))
			if f.Type == "password" {
				raw = values.Get(f.Name)
			}
			if f.Required && raw == "" {
				return nil, fmt.Errorf("%s is required.", f.Label)
			}
			var value any = raw
			switch f.Type {
			case "checkbox":
				value = raw == "on"
			case "number":
				n, err := strconv.Atoi(raw)
				if err != nil {
					return nil, fmt.Errorf("%s must be a whole number.", f.Label)
				}
				min, _ := strconv.Atoi(f.Min)
				max, _ := strconv.Atoi(f.Max)
				if n < min || (f.Max != "" && n > max) {
					return nil, fmt.Errorf("%s must be between %s and %s.", f.Label, f.Min, f.Max)
				}
				value = n
			case "lines":
				value = lines(raw)
			case "pairs":
				pairs := map[string]string{}
				for _, line := range lines(raw) {
					p := strings.SplitN(line, "=", 2)
					if len(p) != 2 || strings.TrimSpace(p[0]) == "" || strings.TrimSpace(p[1]) == "" {
						return nil, fmt.Errorf("%s needs one name=value pair per line.", f.Label)
					}
					pairs[strings.TrimSpace(p[0])] = strings.TrimSpace(p[1])
				}
				value = pairs
			case "select":
				if len(f.Options) > 0 {
					valid := false
					for _, o := range f.Options {
						valid = valid || o.Value == raw
					}
					if !valid {
						return nil, fmt.Errorf("Choose a valid %s.", strings.ToLower(f.Label))
					}
				}
			}
			setNested(payload, f.Name, value)
		}
	}
	if resource == "targets" {
		payload["target_type"] = "pbs"
	}
	if resource == "tokens" || resource == "apikeys" {
		days := payload["days"].(int)
		delete(payload, "days")
		if days > 0 {
			payload["expires_at"] = time.Now().UTC().Add(time.Duration(days) * 24 * time.Hour)
		}
	}
	if resource == "agents" {
		payload["max_uses"] = 1
		payload["expires_at"] = time.Now().UTC().Add(24 * time.Hour)
	}
	return payload, nil
}
func (u *UIHandler) handleSave(w http.ResponseWriter, r *http.Request) {
	resource := chi.URLParam(r, "resource")
	if formSchema(resource) == nil {
		http.NotFound(w, r)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	if err := r.ParseForm(); err != nil {
		uiError(w, "The form is too large or could not be read.", 400, "#form-errors")
		return
	}
	payload, err := decodeForm(resource, r.PostForm)
	if err != nil {
		uiError(w, err.Error(), 422, "#form-errors")
		return
	}
	if u.deps.API == nil {
		uiError(w, "The database is unavailable.", 503, "#form-errors")
		return
	}
	id := r.URL.Query().Get("id")
	var handler http.HandlerFunc
	switch resource {
	case "targets":
		handler = u.deps.API.HandleCreateTarget
		if id != "" {
			handler = u.deps.API.HandleUpdateTarget
		}
	case "jobs":
		handler = u.deps.API.HandleCreateJob
		if id != "" {
			handler = u.deps.API.HandleUpdateJob
		}
	case "tokens", "agents":
		handler = u.deps.API.HandleCreateToken
	case "apikeys":
		handler = u.deps.API.HandleCreateAPIKey
	}
	if resource == "jobs" && id != "" {
		existing := u.callAPI(r, u.deps.API.HandleGetJob, id, nil)
		if existing.status >= 400 {
			uiError(w, apiError(existing), existing.status, "#form-errors")
			return
		}
		var original map[string]any
		if err := json.Unmarshal(existing.Bytes(), &original); err != nil {
			uiError(w, "Unable to read the existing job.", 500, "#form-errors")
			return
		}
		// Merge only the same backup type. Changing engines discards the old engine settings.
		if original["job_type"] == payload["job_type"] {
			if oldDB, ok := original["db_config"].(map[string]any); ok {
				if newDB, ok := payload["db_config"].(map[string]any); ok && oldDB["engine"] != newDB["engine"] {
					delete(original, "db_config")
				}
			}
			mergeFormPayload(original, payload)
			payload = original
		}
	}
	out := u.callAPI(r, handler, id, payload)
	if out.status >= 400 {
		uiError(w, apiError(out), out.status, "#form-errors")
		return
	}
	ret := "/" + resource
	if resource == "jobs" && payload["job_type"] == "kubernetes" {
		ret = "/kubernetes"
	}
	if resource == "tokens" || resource == "apikeys" || resource == "agents" {
		var result map[string]any
		_ = json.Unmarshal(out.Bytes(), &result)
		secret, _ := result["raw_token"].(string)
		if resource == "apikeys" {
			secret, _ = result["raw_key"].(string)
		}
		command := ""
		if resource == "agents" {
			command = installCommand(r.PostForm.Get("platform"), u.Config.PublicURL, secret)
		}
		u.renderFragment(w, "secret-result", map[string]any{"Secret": secret, "Command": command, "Return": ret, "Title": "Access created", "Name": payload["name"]}, "form.html")
		return
	}
	uiLocation(w, ret)
}
func (u *UIHandler) handleAction(w http.ResponseWriter, r *http.Request) {
	resource, id, action := chi.URLParam(r, "resource"), chi.URLParam(r, "id"), chi.URLParam(r, "action")
	if u.deps.API == nil {
		uiError(w, "The database is unavailable.", 503, "#notifications")
		return
	}
	var handler http.HandlerFunc
	var payload any
	switch resource + "/" + action {
	case "agents/delete":
		handler = u.deps.API.HandleDeleteAgent
	case "agents/debug-on":
		handler = u.deps.API.HandleSetAgentDebug
		payload = map[string]bool{"enabled": true}
	case "agents/debug-off":
		handler = u.deps.API.HandleSetAgentDebug
		payload = map[string]bool{"enabled": false}
	case "targets/delete":
		handler = u.deps.API.HandleDeleteTarget
	case "jobs/delete":
		handler = u.deps.API.HandleDeleteJob
	case "jobs/run":
		handler = u.deps.API.HandleTriggerJob
	case "tokens/delete":
		handler = u.deps.API.HandleDeleteToken
	case "apikeys/delete":
		handler = u.deps.API.HandleRevokeAPIKey
	case "runs/cancel":
		handler = u.deps.API.HandleCancelRun
	default:
		http.NotFound(w, r)
		return
	}
	out := u.callAPI(r, handler, id, payload)
	if out.status >= 400 {
		uiError(w, apiError(out), out.status, "#notifications")
		return
	}
	ret := "/" + resource
	if current, err := url.Parse(r.Header.Get("HX-Current-URL")); err == nil && current.Host == r.Host {
		switch current.Path {
		case "/dashboard", "/agents", "/targets", "/jobs", "/kubernetes", "/runs", "/tokens", "/apikeys":
			ret = current.Path
		default:
			if resource == "runs" && current.Path == "/runs/"+id {
				ret = current.Path
			}
		}
	}
	if action == "run" {
		ret = "/runs"
	}
	uiLocation(w, ret)
}
func shellQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", "'\"'\"'") + "'" }
func installCommand(platform, server, token string) string {
	switch platform {
	case "k8s":
		return "helm install fallbck-k8s-agent ./deploy/helm/fallbck-k8s-agent \\\n  --namespace fallbck --create-namespace \\\n  --set-string server.url=" + shellQuote(server) + " \\\n  --set-string clusterName=YOUR_CLUSTER_NAME \\\n  --set-string enrollment.key=" + shellQuote(token)
	case "db":
		return "fallbck-db-agent enroll --server " + shellQuote(server) + " --token " + shellQuote(token) + "\nfallbck-db-agent tools\nsystemctl enable --now fallbck-db-agent"
	case "windows":
		q := func(s string) string { return "'" + strings.ReplaceAll(s, "'", "''") + "'" }
		return ".\\fallbck-agent.exe enroll --server " + q(server) + " --token " + q(token) + "\n.\\fallbck-agent.exe run"
	default:
		return "fallbck-agent enroll --server " + shellQuote(server) + " --token " + shellQuote(token) + "\nfallbck-agent run"
	}
}

// Merge nested editable settings without discarding advanced API configuration.
func mergeFormPayload(original, updates map[string]any) {
	for k, v := range updates {
		child, nested := v.(map[string]any)
		old, existed := original[k].(map[string]any)
		if nested && existed && k != "snapshot_class_overrides" {
			mergeFormPayload(old, child)
		} else {
			original[k] = v
		}
	}
}
