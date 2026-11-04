package vcs

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/osshield/fallbck/pkg/agent/backup"
	"github.com/osshield/fallbck/pkg/db"
	"github.com/osshield/fallbck/pkg/proxy"
	"github.com/osshield/fallbck/pkg/proxy/pbstest"
	"github.com/osshield/fallbck/pkg/rundetail"
	"github.com/osshield/fallbck/pkg/temporal"
	"github.com/osshield/gopbs/pbs"
)

// The VCS job keeps one bare mirror per project, keyed by project id, and archives
// them under their project paths as a virtual tree. On a v2 target, mirror files that
// did not change since the previous run must be referenced from the previous
// snapshot instead of being read and uploaded again, and a renamed project (same
// mirror, new path) must still deduplicate at the chunk level.

func dialFake(fake *pbstest.Server, s *temporal.BackupSessionInfo) func(context.Context, pbs.SnapshotRef) (net.Conn, error) {
	target := &db.BackupTarget{Endpoint: fake.URL(), Fingerprint: fake.Fingerprint(), AuthToken: "root@pam!t=s"}
	return func(ctx context.Context, ref pbs.SnapshotRef) (net.Conn, error) {
		return proxy.OpenBackupSession(ctx, target, proxy.SessionParams{
			Datastore: s.Datastore, Namespace: s.Namespace,
			BackupType: s.BackupType, BackupID: s.BackupID, BackupTime: s.BackupTime,
		})
	}
}

func packBytes(t *testing.T, mirror string) int64 {
	t.Helper()
	packs, _ := filepath.Glob(filepath.Join(mirror, "objects", "pack", "*.pack"))
	var n int64
	for _, p := range packs {
		fi, err := os.Stat(p)
		if err != nil {
			t.Fatal(err)
		}
		n += fi.Size()
	}
	return n
}

func TestMirrorTreeReuse(t *testing.T) {
	h := newGitHost(t)
	apiWork, apiBare := h.repo(t, "team/api.git")
	h.repo(t, "team/infra.git")
	// An incompressible asset keeps the pack around 12 MiB: several chunks
	buf := make([]byte, 12<<20)
	if _, err := rand.Read(buf); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(apiWork, "assets.bin"), buf, 0o644); err != nil {
		t.Fatal(err)
	}
	hostGit(t, apiWork, "add", ".")
	hostGit(t, apiWork, "commit", "--quiet", "-m", "assets")
	hostGit(t, apiWork, "push", "--quiet", apiBare, "main")

	g := h.git(t, testToken)
	state := t.TempDir()
	api := g.NewMirror(filepath.Join(state, "101.git"), h.url("team/api.git"))
	infra := g.NewMirror(filepath.Join(state, "102.git"), h.url("team/infra.git"))
	fetchAll := func() {
		t.Helper()
		for _, m := range []*Mirror{api, infra} {
			if _, err := m.Fetch(ctx(t), nil); err != nil {
				t.Fatal(err)
			}
		}
	}
	fetchAll()
	bigPack := packBytes(t, api.Dir)
	if bigPack < 12<<20 {
		t.Fatalf("api pack is %d bytes", bigPack)
	}

	fake := pbstest.New(t)
	cacheRoot := t.TempDir()
	base := time.Now().Add(-time.Hour)
	type outcome struct {
		reuse  *rundetail.ReuseStats
		chunks int
	}
	run := func(step int, apiPath string) outcome {
		t.Helper()
		session := &temporal.BackupSessionInfo{
			Datastore: "store1", BackupType: "host", BackupID: "vcs-test",
			BackupTime: base.Add(time.Duration(step) * time.Minute).Unix(), PxarFormat: db.PxarFormatV2,
		}
		tree, err := BuildTree("vcs", []TreeProject{
			{Path: apiPath, Repository: api.Dir},
			{Path: "team/infra", Repository: infra.Dir},
		}, base)
		if err != nil {
			t.Fatal(err)
		}
		before := fake.ChunkCount()
		res, err := backup.Run(ctx(t), backup.Options{
			Session: session, Dial: dialFake(fake, session), ArchiveName: "vcs", Tree: tree,
			CacheDir: backup.CacheGroupDir(cacheRoot, "host", "vcs-test"),
		})
		if err != nil {
			t.Fatalf("run %d: %v", step, err)
		}
		var d rundetail.Filesystem
		if err := json.Unmarshal(res.Details, &d); err != nil || d.Reuse == nil {
			t.Fatalf("run %d details: %s (%v)", step, res.Details, err)
		}
		o := outcome{reuse: d.Reuse, chunks: fake.ChunkCount() - before}
		t.Logf("run %d: files=%d reused=%d reused_bytes=%d rejected_runs=%d scanned=%d new_chunks=%d",
			step, d.Reuse.Files, d.Reuse.ReusedFiles, d.Reuse.ReusedBytes, d.Reuse.RejectedRuns, res.BytesScanned, o.chunks)
		return o
	}

	// 1. First run reads everything
	if first := run(1, "team/api"); first.reuse.ReusedFiles != 0 || first.reuse.Files == 0 {
		t.Fatalf("first run: %+v", first.reuse)
	}

	// 2. A fetch that brings nothing new: the pack is referenced, not re-read
	fetchAll()
	second := run(2, "team/api")
	if second.reuse.ReusedBytes < uint64(bigPack) {
		t.Errorf("unchanged mirror: reused %d bytes, the %d-byte pack should have been referenced", second.reuse.ReusedBytes, bigPack)
	}
	if second.chunks > 4 {
		t.Errorf("unchanged mirror uploaded %d new chunks", second.chunks)
	}

	// 3. New commits upstream: the fetch adds a pack and repacks the refs; the old
	// pack stays byte-identical and is still referenced
	if err := os.WriteFile(filepath.Join(apiWork, "README.md"), []byte("# api\n\nchanged\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	hostGit(t, apiWork, "commit", "--quiet", "-am", "update readme")
	hostGit(t, apiWork, "tag", "v2.0.0")
	hostGit(t, apiWork, "push", "--quiet", apiBare, "main", "v2.0.0")
	fetchAll()
	third := run(3, "team/api")
	if third.reuse.ReusedBytes < uint64(bigPack) {
		t.Errorf("after a fetch: reused %d bytes, the old %d-byte pack should still be referenced", third.reuse.ReusedBytes, bigPack)
	}
	if third.chunks > 8 {
		t.Errorf("after a small fetch %d new chunks were uploaded", third.chunks)
	}

	// 4. The project is renamed: same mirror (keyed by id), new archive path. The
	// pack is read again but its chunks deduplicate.
	if fourth := run(4, "platform/api-v2"); fourth.chunks > 8 {
		t.Errorf("renamed project uploaded %d new chunks; the unchanged pack should deduplicate", fourth.chunks)
	}
	if fake.Finished() != 4 {
		t.Errorf("finished sessions = %d", fake.Finished())
	}
}
