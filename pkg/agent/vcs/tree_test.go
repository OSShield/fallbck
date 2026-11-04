package vcs

import (
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/osshield/gopbs/scan"
)

// flatten maps archive paths (below the root) to nodes
func flatten(n *scan.Node, prefix string, out map[string]*scan.Node) map[string]*scan.Node {
	for _, c := range n.Children {
		p := c.Name
		if prefix != "" {
			p = prefix + "/" + c.Name
		}
		out[p] = c
		flatten(c, p, out)
	}
	return out
}

// materialize writes a tree to disk the way a restore would
func materialize(t *testing.T, n *scan.Node, dir string) {
	t.Helper()
	for _, c := range n.Children {
		p := filepath.Join(dir, c.Name)
		switch c.Kind {
		case scan.KindDirectory:
			if err := os.MkdirAll(p, 0o755); err != nil {
				t.Fatal(err)
			}
			materialize(t, c, p)
		case scan.KindStream:
			data, err := io.ReadAll(c.Stream)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(p, data, os.FileMode(c.Stat.Mode&0o777)|0o200); err != nil {
				t.Fatal(err)
			}
		}
	}
}

func bareRepo(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "m.git")
	hostGit(t, "", "init", "--bare", "--quiet", dir)
	return dir
}

func TestBuildTreeLayout(t *testing.T) {
	needGit(t)
	api, wiki, tf := bareRepo(t), bareRepo(t), bareRepo(t)
	for _, f := range []string{"FETCH_HEAD", "packed-refs.lock", "index.lock"} {
		if err := os.WriteFile(filepath.Join(api, f), []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	now := time.Now()
	root, err := BuildTree("vcs", []TreeProject{
		{Path: "platform/infra/terraform", Repository: tf},
		{Path: "/platform/api/", Repository: api, Wiki: wiki},
	}, now)
	if err != nil {
		t.Fatal(err)
	}
	nodes := flatten(root, "", map[string]*scan.Node{})
	for _, want := range []string{
		"RESTORE.md", "restore.sh",
		"platform/api/repository.git/HEAD", "platform/api/repository.git/config",
		"platform/api/wiki.git/HEAD",
		"platform/infra/terraform/repository.git/HEAD",
	} {
		if nodes[want] == nil {
			t.Errorf("missing %s", want)
		}
	}
	for _, skipped := range []string{"platform/api/repository.git/FETCH_HEAD", "platform/api/repository.git/packed-refs.lock", "platform/api/repository.git/index.lock"} {
		if nodes[skipped] != nil {
			t.Errorf("%s should be left out", skipped)
		}
	}
	if nodes["platform/infra/terraform/wiki.git"] != nil {
		t.Error("a project without a wiki got one")
	}
	if m := nodes["restore.sh"].Stat.Mode & 0o777; m != 0o755 {
		t.Errorf("restore.sh mode %o", m)
	}

	// Leaves carry the file's on-disk metadata and content
	head := nodes["platform/api/repository.git/HEAD"]
	fi, _ := os.Stat(filepath.Join(api, "HEAD"))
	if head.Kind != scan.KindStream || head.Stat.Size != fi.Size() || head.Stat.MtimeSecs != fi.ModTime().Unix() || head.Stat.MtimeNanos != uint32(fi.ModTime().Nanosecond()) {
		t.Errorf("HEAD stat %+v vs %d bytes, %v", head.Stat, fi.Size(), fi.ModTime())
	}
	data, err := io.ReadAll(head.Stream)
	disk, _ := os.ReadFile(filepath.Join(api, "HEAD"))
	if err != nil || string(data) != string(disk) {
		t.Errorf("HEAD content %q vs %q: %v", data, disk, err)
	}
	// Children are in archive order
	for _, n := range []*scan.Node{root, nodes["platform"]} {
		for i := 1; i < len(n.Children); i++ {
			if n.Children[i-1].Name >= n.Children[i].Name {
				t.Errorf("children of %s not sorted", n.Name)
			}
		}
	}
}

func TestBuildTreeRejects(t *testing.T) {
	needGit(t)
	repo := bareRepo(t)
	cases := map[string][]TreeProject{
		"empty path":       {{Path: "", Repository: repo}},
		"dot segment":      {{Path: "a/../b", Repository: repo}},
		"reserved segment": {{Path: "a/repository.git/b", Repository: repo}},
		"wiki segment":     {{Path: "a/wiki.git", Repository: repo}},
		"root collision":   {{Path: "restore.sh/x", Repository: repo}},
		"duplicate":        {{Path: "a/b", Repository: repo}, {Path: "a/b/", Repository: repo}},
		"missing mirror":   {{Path: "a/b", Repository: filepath.Join(t.TempDir(), "nope.git")}},
		"missing wiki":     {{Path: "a/b", Repository: repo, Wiki: filepath.Join(t.TempDir(), "nope.git")}},
	}
	for name, projects := range cases {
		if _, err := BuildTree("vcs", projects, time.Now()); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
	if runtime.GOOS != "windows" {
		if err := os.Symlink("/etc/passwd", filepath.Join(repo, "link")); err != nil {
			t.Fatal(err)
		}
		if _, err := BuildTree("vcs", []TreeProject{{Path: "a/b", Repository: repo}}, time.Now()); err == nil || !strings.Contains(err.Error(), "unexpected") {
			t.Errorf("a symlink in a mirror must be refused: %v", err)
		}
	}
}

// TestRestoreScript restores a project from a materialized tree into an empty
// repository: branches and tags arrive, merge request refs stay behind
func TestRestoreScript(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("restore.sh is a POSIX shell script")
	}
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("no sh")
	}
	h := newGitHost(t)
	h.repo(t, "team/app.git")
	g := h.git(t, testToken)
	mirror := g.NewMirror(filepath.Join(t.TempDir(), "101.git"), h.url("team/app.git"))
	if _, err := mirror.Fetch(ctx(t), nil); err != nil {
		t.Fatal(err)
	}
	root, err := BuildTree("vcs", []TreeProject{{Path: "team/app", Repository: mirror.Dir}}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	restored := t.TempDir()
	materialize(t, root, restored)

	target := bareRepo(t)
	cmd := exec.Command("sh", filepath.Join(restored, RestoreScript), "team/app", target)
	cmd.Env = append(os.Environ(), "GIT_CONFIG_GLOBAL="+os.DevNull, "GIT_CONFIG_NOSYSTEM=1")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("restore.sh: %v\n%s", err, out)
	}
	want := hostGit(t, mirror.Dir, "for-each-ref", "--format=%(objectname) %(refname)", "refs/heads", "refs/tags")
	got := hostGit(t, target, "for-each-ref", "--format=%(objectname) %(refname)")
	if got != want {
		t.Errorf("restored refs:\n%s\nwant:\n%s", got, want)
	}
	hostGit(t, target, "fsck", "--no-progress")

	usage := exec.Command("sh", filepath.Join(restored, RestoreScript), "team/app")
	if out, err := usage.CombinedOutput(); err == nil || !strings.Contains(string(out), "usage") {
		t.Errorf("missing arguments: %v %s", err, out)
	}
}
