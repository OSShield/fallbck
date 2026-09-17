package dockerbackup

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	dockerspec "github.com/osshield/fallbck/pkg/dockerbackup"
	"github.com/osshield/fallbck/pkg/temporal"
	"github.com/osshield/gopbs"
)

// fakeDaemon answers the Engine API endpoints the agent uses from canned documents
// and records the state-changing calls (pause, unpause, helper create/remove)
type fakeDaemon struct {
	t      *testing.T
	socket string
	srv    *httptest.Server
	mu     sync.Mutex
	calls  []string
	// volumeMount is the Mountpoint reported for the "data" volume
	volumeMount string
	// composeFile is served through the helper archive endpoint
	composeFile string
}

var versionPrefix = regexp.MustCompile(`^/v[0-9.]+`)

func newFakeDaemon(t *testing.T) *fakeDaemon {
	t.Helper()
	// Unix socket paths are short-limited; keep it in a short temp dir
	dir, err := os.MkdirTemp("", "fbkd")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	f := &fakeDaemon{t: t, socket: filepath.Join(dir, "d.sock"), volumeMount: "/var/lib/docker/volumes/data/_data",
		composeFile: "services:\n  db:\n    image: postgres:17\n"}
	l, err := net.Listen("unix", f.socket)
	if err != nil {
		t.Fatal(err)
	}
	f.srv = httptest.NewUnstartedServer(http.HandlerFunc(f.handle))
	f.srv.Listener = l
	f.srv.Start()
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeDaemon) record(s string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, s)
}

func (f *fakeDaemon) recorded() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.calls...)
}

func jsonOK(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func tarOf(name, content string) []byte {
	var b bytes.Buffer
	tw := tar.NewWriter(&b)
	_ = tw.WriteHeader(&tar.Header{Name: filepath.Dir(name) + "/", Typeflag: tar.TypeDir, Mode: 0o755, ModTime: time.Now()})
	_ = tw.WriteHeader(&tar.Header{Name: name, Typeflag: tar.TypeReg, Mode: 0o640, Size: int64(len(content)), ModTime: time.Now(), Uid: 999, Gid: 999})
	_, _ = tw.Write([]byte(content))
	_ = tw.Close()
	return b.Bytes()
}

func (f *fakeDaemon) handle(w http.ResponseWriter, r *http.Request) {
	p := versionPrefix.ReplaceAllString(r.URL.Path, "")
	switch {
	case p == "/_ping":
		_, _ = w.Write([]byte("OK"))
	case p == "/version":
		jsonOK(w, map[string]any{"Version": "27.1.0", "ApiVersion": "1.46", "MinAPIVersion": "1.24", "Os": "linux", "Arch": "amd64", "KernelVersion": "6.8.0"})
	case p == "/info":
		jsonOK(w, map[string]any{"ID": "abc", "Name": "dock01", "ServerVersion": "27.1.0", "DockerRootDir": "/var/lib/docker", "Driver": "overlay2",
			"OperatingSystem": "Debian GNU/Linux 12", "OSType": "linux", "Architecture": "x86_64", "KernelVersion": "6.8.0",
			"Containers": 2, "ContainersRunning": 1, "Images": 2, "Swarm": map[string]any{"LocalNodeState": "inactive"}})
	case p == "/containers/json":
		jsonOK(w, []map[string]any{
			{"Id": "c1" + strings.Repeat("0", 62), "Names": []string{"/app-db-1"}, "Image": "postgres:17", "ImageID": "sha256:img1", "State": "running", "Status": "Up 2 days",
				"Labels": map[string]string{"com.docker.compose.project": "app", "com.docker.compose.service": "db", "fallbck.io/pause": "true"}},
			{"Id": "c2" + strings.Repeat("0", 62), "Names": []string{"/tools"}, "Image": "local/tools:dev", "ImageID": "sha256:img2", "State": "exited", "Status": "Exited (0)", "Labels": map[string]string{}},
			{"Id": "c3" + strings.Repeat("0", 62), "Names": []string{"/skipme"}, "Image": "busybox", "ImageID": "sha256:img3", "State": "running", "Status": "Up", "Labels": map[string]string{"fallbck.io/skip": "true"}},
		})
	case strings.HasPrefix(p, "/containers/c1") && strings.HasSuffix(p, "/json"):
		jsonOK(w, map[string]any{"Id": "c1" + strings.Repeat("0", 62), "Name": "/app-db-1", "Created": "2026-09-01T00:00:00Z", "Image": "sha256:img1",
			"State": map[string]any{"Status": "running", "Running": true},
			"Config": map[string]any{"Image": "postgres:17", "Env": []string{"POSTGRES_PASSWORD=x"}, "Labels": map[string]string{
				"com.docker.compose.project": "app", "com.docker.compose.service": "db", "com.docker.compose.project.working_dir": "/srv/app",
				"com.docker.compose.project.config_files": "/srv/app/docker-compose.yml", "fallbck.io/pause": "true"}},
			"HostConfig": map[string]any{"RestartPolicy": map[string]any{"Name": "unless-stopped"}, "PortBindings": map[string]any{"5432/tcp": []map[string]string{{"HostIp": "", "HostPort": "5432"}}}},
			"Mounts": []map[string]any{{"Type": "volume", "Name": "data", "Source": f.volumeMount, "Destination": "/var/lib/postgresql/data", "RW": true},
				{"Type": "bind", "Source": "/srv/app/init", "Destination": "/docker-entrypoint-initdb.d", "RW": false}},
			"NetworkSettings": map[string]any{"Networks": map[string]any{"app_default": map[string]any{"IPAddress": "172.20.0.2"}}}})
	case strings.HasPrefix(p, "/containers/c2") && strings.HasSuffix(p, "/json"):
		jsonOK(w, map[string]any{"Id": "c2" + strings.Repeat("0", 62), "Name": "/tools", "Image": "sha256:img2", "State": map[string]any{"Status": "exited"},
			"Config": map[string]any{"Image": "local/tools:dev", "Labels": map[string]string{}}, "HostConfig": map[string]any{"RestartPolicy": map[string]any{"Name": "no"}},
			"Mounts":          []map[string]any{{"Type": "volume", "Name": "toolcache", "Source": "/var/lib/docker/volumes/toolcache/_data", "Destination": "/cache", "RW": true}},
			"NetworkSettings": map[string]any{"Networks": map[string]any{"bridge": map[string]any{}}}})
	case strings.HasPrefix(p, "/containers/c3") && strings.HasSuffix(p, "/json"):
		jsonOK(w, map[string]any{"Id": "c3" + strings.Repeat("0", 62), "Name": "/skipme", "Image": "sha256:img3", "State": map[string]any{"Status": "running", "Running": true},
			"Config": map[string]any{"Image": "busybox", "Labels": map[string]string{"fallbck.io/skip": "true"}}, "HostConfig": map[string]any{}})
	case p == "/networks":
		jsonOK(w, []map[string]any{{"Name": "bridge", "Id": "n0", "Driver": "bridge", "Scope": "local"}, {"Name": "app_default", "Id": "n1", "Driver": "bridge", "Scope": "local"}})
	case strings.HasPrefix(p, "/networks/n0"):
		jsonOK(w, map[string]any{"Name": "bridge", "Id": "n0", "Driver": "bridge", "Scope": "local"})
	case strings.HasPrefix(p, "/networks/n1"):
		jsonOK(w, map[string]any{"Name": "app_default", "Id": "n1", "Driver": "bridge", "Scope": "local", "Attachable": false,
			"IPAM":   map[string]any{"Driver": "default", "Config": []map[string]string{{"Subnet": "172.20.0.0/16", "Gateway": "172.20.0.1"}}},
			"Labels": map[string]string{"com.docker.compose.project": "app"}, "Containers": map[string]any{"c1": map[string]string{"Name": "app-db-1"}}})
	case p == "/volumes":
		jsonOK(w, map[string]any{"Volumes": []map[string]any{
			{"Name": "data", "Driver": "local", "Mountpoint": f.volumeMount, "Scope": "local", "Labels": map[string]string{"com.docker.compose.project": "app"}},
			{"Name": "toolcache", "Driver": "local", "Mountpoint": "/var/lib/docker/volumes/toolcache/_data", "Scope": "local"},
			{"Name": "orphan", "Driver": "local", "Mountpoint": "/var/lib/docker/volumes/orphan/_data", "Scope": "local"},
		}})
	case strings.HasPrefix(p, "/volumes/"):
		name := strings.TrimPrefix(p, "/volumes/")
		jsonOK(w, map[string]any{"Name": name, "Driver": "local", "Mountpoint": "/var/lib/docker/volumes/" + name + "/_data"})
	case p == "/images/json":
		jsonOK(w, []map[string]any{
			{"Id": "sha256:img1", "RepoTags": []string{"postgres:17"}, "RepoDigests": []string{"postgres@sha256:aaaa"}, "Size": 400},
			{"Id": "sha256:img2", "RepoTags": []string{"local/tools:dev"}, "RepoDigests": []string{}, "Size": 50},
			{"Id": "sha256:img9", "RepoTags": []string{"unused:1"}, "RepoDigests": []string{}, "Size": 1},
		})
	case p == "/images/get":
		f.record("save " + r.URL.Query().Get("names"))
		_, _ = w.Write(tarOf("manifest.json", "[]"))
	case strings.HasPrefix(p, "/images/") && strings.HasSuffix(p, "/json"):
		jsonOK(w, map[string]any{"Id": "sha256:helper"})
	case p == "/containers/create" && r.Method == http.MethodPost:
		var body struct {
			HostConfig struct{ Binds []string }
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		f.record("create " + strings.Join(body.HostConfig.Binds, ","))
		w.WriteHeader(http.StatusCreated)
		jsonOK(w, map[string]any{"Id": "helper1"})
	case strings.HasSuffix(p, "/pause"):
		f.record("pause " + strings.TrimSuffix(strings.TrimPrefix(p, "/containers/"), "/pause")[:2])
		w.WriteHeader(http.StatusNoContent)
	case strings.HasSuffix(p, "/unpause"):
		f.record("unpause " + strings.TrimSuffix(strings.TrimPrefix(p, "/containers/"), "/unpause")[:2])
		w.WriteHeader(http.StatusNoContent)
	case strings.HasSuffix(p, "/archive"):
		path := r.URL.Query().Get("path")
		f.record("archive " + path)
		switch path {
		case "/vol":
			w.Header().Set("Content-Type", "application/x-tar")
			_, _ = w.Write(tarOf("vol/pgdata/PG_VERSION", "17\n"))
		case "/src/docker-compose.yml":
			_, _ = w.Write(tarOf("src/docker-compose.yml", f.composeFile))
		default:
			w.WriteHeader(http.StatusNotFound)
			jsonOK(w, map[string]string{"message": "Could not find the file " + path + " in container helper1"})
		}
	case r.Method == http.MethodDelete && strings.HasPrefix(p, "/containers/"):
		f.record("remove " + strings.TrimPrefix(p, "/containers/"))
		w.WriteHeader(http.StatusNoContent)
	default:
		f.t.Errorf("unexpected request %s %s", r.Method, r.URL.String())
		w.WriteHeader(http.StatusNotFound)
	}
}

func testSession(t *testing.T) *temporal.BackupSessionInfo {
	t.Helper()
	return &temporal.BackupSessionInfo{
		JobID: uuid.New(), BackupRunID: uuid.New(), JobName: "docker nightly", RunID: "run-1",
		BackupType: "host", BackupID: "dock01-docker", BackupTime: time.Date(2026, 9, 17, 2, 0, 0, 0, time.UTC).Unix(),
	}
}

type uploadCall struct {
	paths, readPaths, excludes []string
	blobs                      []gopbs.Blob
}

func runWith(t *testing.T, f *fakeDaemon, spec *dockerspec.Spec, settings dockerspec.Config, spool string) (*uploadCall, *dockerspec.Manifest) {
	t.Helper()
	var call uploadCall
	res, err := Run(context.Background(), RunOptions{
		Session: testSession(t), Spec: spec, Settings: settings, SpoolDir: spool, Client: NewClient(f.socket),
		Hostname: "dock01", AgentVersion: "test", KeepSpool: true,
		Upload: func(_ context.Context, paths, readPaths, excludes []string, blobs []gopbs.Blob) (*temporal.BackupExecutionResult, error) {
			call = uploadCall{paths: paths, readPaths: readPaths, excludes: excludes, blobs: blobs}
			for _, p := range readPaths {
				if _, err := os.Stat(p); err != nil {
					t.Errorf("read path %s: %v", p, err)
				}
			}
			return &temporal.BackupExecutionResult{SnapshotID: "host/dock01-docker/2026-09-17T02:00:00Z"}, nil
		},
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res == nil || len(res.Details) == 0 {
		t.Fatal("result without details")
	}
	if len(call.blobs) != 1 || call.blobs[0].Name != dockerspec.ManifestBlobName {
		t.Fatalf("blobs %+v", call.blobs)
	}
	m, err := dockerspec.ParseManifest(call.blobs[0].Data)
	if err != nil {
		t.Fatal(err)
	}
	return &call, m
}

func TestRunHelperMode(t *testing.T) {
	f := newFakeDaemon(t)
	spool := t.TempDir()
	daemonConfigPath = filepath.Join(t.TempDir(), "daemon.json")
	procSelfCgroup, procSelfMounts = "/nonexistent/cgroup", "/nonexistent/mountinfo"
	_ = os.WriteFile(daemonConfigPath, []byte(`{"log-driver":"json-file"}`), 0o600)

	spec := &dockerspec.Spec{Images: dockerspec.ImagesLocal, ExcludeVolumes: []string{"tool*"}}
	call, m := runWith(t, f, spec, dockerspec.Config{VolumeAccess: dockerspec.VolumeAccessHelper}, spool)

	// Archive layout: collect + the two volumes that were not excluded (orphan is unused but included by default)
	wantPaths := []string{logicalRoot + "/collect", logicalRoot + "/vol-data", logicalRoot + "/vol-orphan"}
	if strings.Join(call.paths, " ") != strings.Join(wantPaths, " ") {
		t.Errorf("paths %v", call.paths)
	}
	if !strings.HasPrefix(call.readPaths[1], spool) {
		t.Errorf("helper mode must stage into the spool, got %s", call.readPaths[1])
	}
	if data, err := os.ReadFile(filepath.Join(call.readPaths[1], "pgdata", "PG_VERSION")); err != nil || string(data) != "17\n" {
		t.Errorf("staged volume content: %v %q", err, data)
	}

	// Manifest
	if m.Host.DockerVersion != "27.1.0" || m.Host.VolumeAccess != accessHelper {
		t.Errorf("host %+v", m.Host)
	}
	byName := map[string]dockerspec.Container{}
	for _, c := range m.Containers {
		byName[c.Name] = c
	}
	if c := byName["app-db-1"]; c.Project != "app" || c.Service != "db" || c.Definition == "" || !c.Paused || c.Restart != "unless-stopped" || len(c.Ports) != 1 {
		t.Errorf("app-db-1 %+v", c)
	}
	if c := byName["skipme"]; !strings.Contains(c.Skipped, "fallbck.io/skip") || c.Definition != "" {
		t.Errorf("skipme %+v", c)
	}
	if c := byName["tools"]; c.Skipped != "" || c.State != "exited" {
		t.Errorf("tools (stopped, included by default) %+v", c)
	}
	vols := map[string]dockerspec.Volume{}
	for _, v := range m.Volumes {
		vols[v.Name] = v
	}
	if v := vols["data"]; v.Entry != "vol-data" || v.Access != accessHelper || strings.Join(v.Paused, ",") != "app-db-1" || strings.Join(v.UsedBy, ",") != "app-db-1" {
		t.Errorf("data %+v", v)
	}
	if v := vols["toolcache"]; !strings.Contains(v.Skipped, "excluded") || v.Entry != "" {
		t.Errorf("toolcache %+v", v)
	}
	if len(m.Compose) != 1 || m.Compose[0].Name != "app" || len(m.Compose[0].Archived) != 1 || m.Compose[0].Archived[0].Source != "/srv/app/docker-compose.yml" {
		t.Errorf("compose %+v", m.Compose)
	}
	if !m.Daemon.Archived {
		t.Error("daemon.json (readable directly) not archived")
	}
	var localSaved, refOnly bool
	for _, im := range m.Images {
		switch im.ID {
		case "sha256:img2":
			localSaved = im.Local && im.Saved != ""
		case "sha256:img1":
			refOnly = !im.Local && im.Saved == ""
		case "sha256:img9":
			t.Error("unused image listed")
		}
	}
	if !localSaved || !refOnly {
		t.Errorf("images %+v", m.Images)
	}
	if len(m.BindMounts) != 1 || m.BindMounts[0].Source != "/srv/app/init" {
		t.Errorf("bind mounts %+v", m.BindMounts)
	}
	for _, n := range m.Networks {
		if n.Name == "app_default" && (n.Builtin || len(n.Subnets) != 1 || n.Definition == "") {
			t.Errorf("network %+v", n)
		}
		if n.Name == "bridge" && (!n.Builtin || n.Definition != "") {
			t.Errorf("bridge %+v", n)
		}
	}

	// Files in collect/
	collectDir := call.readPaths[0]
	for _, want := range []string{"info.json", "version.json", "containers/app-db-1.json", "containers/tools.json", "networks/app_default.json",
		"volumes/data.json", "images.json", "compose/app/docker-compose.yml", "daemon/daemon.json", "images/local_tools_dev.tar",
		dockerspec.ManifestFileName, dockerspec.RestoreScriptName} {
		if _, err := os.Stat(filepath.Join(collectDir, want)); err != nil {
			t.Errorf("collect/%s missing: %v", want, err)
		}
	}
	if _, err := os.Stat(filepath.Join(collectDir, "containers/skipme.json")); err == nil {
		t.Error("skipped container definition was written")
	}

	// Pause bracket around the volume copy, helper removed afterwards
	calls := strings.Join(f.recorded(), "\n")
	pause, archive, unpause := strings.Index(calls, "pause c1"), strings.Index(calls, "archive /vol"), strings.Index(calls, "unpause c1")
	if pause < 0 || archive < 0 || unpause < 0 || !(pause < archive && archive < unpause) {
		t.Errorf("pause ordering wrong:\n%s", calls)
	}
	if !strings.Contains(calls, "create data:/vol:ro") || !strings.Contains(calls, "create /srv/app:/src:ro") || !strings.Contains(calls, "remove helper1") {
		t.Errorf("helper containers:\n%s", calls)
	}

	// Restore script
	script, _ := os.ReadFile(filepath.Join(collectDir, dockerspec.RestoreScriptName))
	for _, want := range []string{"docker network create --driver bridge --subnet 172.20.0.0/16 --gateway 172.20.0.1", "docker volume create --label com.docker.compose.project=app data",
		"vol-data:/src:ro", "docker load -i \"$COLLECT/images/local_tools_dev.tar\"", "docker pull postgres@sha256:aaaa", "docker compose -p app -f /srv/app/docker-compose.yml up -d",
		"docker run -d --name tools", "/srv/app/init"} {
		if !strings.Contains(string(script), want) {
			t.Errorf("restore script lacks %q", want)
		}
	}
	if m.Restore.Script != "collect/"+dockerspec.RestoreScriptName || len(m.Restore.Commands) == 0 {
		t.Errorf("restore %+v", m.Restore)
	}
}

func TestRunDirectMode(t *testing.T) {
	f := newFakeDaemon(t)
	mount := t.TempDir()
	if err := os.WriteFile(filepath.Join(mount, "hello.txt"), []byte("hi"), 0o644); err != nil {
		t.Fatal(err)
	}
	f.volumeMount = mount
	daemonConfigPath = "/nonexistent/daemon.json"
	procSelfCgroup, procSelfMounts = "/nonexistent/cgroup", "/nonexistent/mountinfo"

	// No pause label match: the paused container is still labeled, so "data" is staged;
	// disable pausing by excluding the container from the pause set via IncludeStopped
	// is not possible, so test staging here and plain direct reads with "orphan"
	spec := &dockerspec.Spec{IncludeUnusedVolumes: boolPtr(true), ExcludeVolumes: []string{"toolcache"}}
	call, m := runWith(t, f, spec, dockerspec.Config{VolumeAccess: dockerspec.VolumeAccessAuto}, t.TempDir())

	vols := map[string]dockerspec.Volume{}
	for _, v := range m.Volumes {
		vols[v.Name] = v
	}
	// "data" is visible and local but its container is paused: staged copy
	if v := vols["data"]; v.Access != accessStaged || v.Entry != "vol-data" {
		t.Errorf("data %+v", v)
	}
	if v := vols["orphan"]; v.Access != accessHelper || v.Entry != "vol-orphan" {
		t.Errorf("orphan (mountpoint not visible → helper in auto mode) %+v", v)
	}
	if m.Host.VolumeAccess != "mixed" {
		t.Errorf("volume access summary %q", m.Host.VolumeAccess)
	}
	if data, err := os.ReadFile(filepath.Join(call.readPaths[1], "hello.txt")); err != nil || string(data) != "hi" {
		t.Errorf("staged copy: %v %q", err, data)
	}
	if m.Daemon.Archived {
		t.Error("missing daemon.json reported as archived")
	}

	// Strict direct mode refuses a volume it cannot see instead of falling back
	_, m = runWith(t, f, spec, dockerspec.Config{VolumeAccess: dockerspec.VolumeAccessDirect}, t.TempDir())
	vols = map[string]dockerspec.Volume{}
	for _, v := range m.Volumes {
		vols[v.Name] = v
	}
	if v := vols["orphan"]; !strings.Contains(v.Skipped, "not readable") {
		t.Errorf("direct mode must skip invisible volumes: %+v", v)
	}
}

func TestRunPrecheckWithoutDaemon(t *testing.T) {
	_, err := Run(context.Background(), RunOptions{
		Session: testSession(t), SpoolDir: t.TempDir(), Client: NewClient(filepath.Join(t.TempDir(), "none.sock")),
		Upload: func(context.Context, []string, []string, []string, []gopbs.Blob) (*temporal.BackupExecutionResult, error) {
			t.Fatal("upload must not run")
			return nil, nil
		},
	})
	if err == nil || !strings.Contains(err.Error(), "not reachable") {
		t.Fatalf("expected a precheck error, got %v", err)
	}
}

func TestUntarRefusesEscapes(t *testing.T) {
	var b bytes.Buffer
	tw := tar.NewWriter(&b)
	_ = tw.WriteHeader(&tar.Header{Name: "vol/../../etc/passwd", Typeflag: tar.TypeReg, Mode: 0o644, Size: 1})
	_, _ = tw.Write([]byte("x"))
	_ = tw.Close()
	if err := untar(&b, t.TempDir(), "vol"); err == nil {
		t.Error("escaping entry accepted")
	}
}

func TestUntarPreservesLayout(t *testing.T) {
	var b bytes.Buffer
	tw := tar.NewWriter(&b)
	_ = tw.WriteHeader(&tar.Header{Name: "vol/", Typeflag: tar.TypeDir, Mode: 0o700})
	_ = tw.WriteHeader(&tar.Header{Name: "vol/a/", Typeflag: tar.TypeDir, Mode: 0o750})
	_ = tw.WriteHeader(&tar.Header{Name: "vol/a/f", Typeflag: tar.TypeReg, Mode: 0o600, Size: 3, ModTime: time.Unix(1700000000, 0)})
	_, _ = tw.Write([]byte("abc"))
	_ = tw.WriteHeader(&tar.Header{Name: "vol/a/l", Typeflag: tar.TypeSymlink, Linkname: "f"})
	_ = tw.WriteHeader(&tar.Header{Name: "vol/a/h", Typeflag: tar.TypeLink, Linkname: "vol/a/f"})
	_ = tw.Close()
	dst := t.TempDir()
	if err := untar(&b, dst, "vol"); err != nil {
		t.Fatal(err)
	}
	if st, err := os.Stat(filepath.Join(dst, "a", "f")); err != nil || st.Size() != 3 || st.Mode().Perm() != 0o600 || st.ModTime().Unix() != 1700000000 {
		t.Errorf("file: %v %+v", err, st)
	}
	if l, err := os.Readlink(filepath.Join(dst, "a", "l")); err != nil || l != "f" {
		t.Errorf("symlink: %v %q", err, l)
	}
	if data, err := os.ReadFile(filepath.Join(dst, "a", "h")); err != nil || string(data) != "abc" {
		t.Errorf("hardlink: %v %q", err, data)
	}
	if st, err := os.Stat(filepath.Join(dst, "a")); err != nil || st.Mode().Perm() != 0o750 {
		t.Errorf("dir mode: %v", err)
	}
}

func TestShellQuote(t *testing.T) {
	if shellQuote("plain-1.0") != "plain-1.0" || shellQuote("it's") != `'it'\''s'` || shellQuote("a b") != "'a b'" {
		t.Error("quoting")
	}
}

func boolPtr(b bool) *bool { return &b }
