package vcs

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// FetchRefspecs are the refs a mirror keeps: branches, tags and merge request heads.
// Not +refs/*:refs/*: GitLab also advertises refs/environments, refs/pipelines and
// refs/workloads, internal refs that can outnumber everything else by far.
var FetchRefspecs = []string{
	"+refs/heads/*:refs/heads/*",
	"+refs/tags/*:refs/tags/*",
	"+refs/merge-requests/*/head:refs/merge-requests/*/head",
}

// DefaultRepackThreshold is the pack count above which Repack merges small packs
const DefaultRepackThreshold = 16

// mirrorConfig is written into every new mirror: no automatic gc or maintenance
// (existing packfiles must stay byte-identical so the backup can reuse them), every
// fetch kept as a pack instead of loose objects, no reflogs
var mirrorConfig = [][2]string{
	{"gc.auto", "0"},
	{"gc.autoDetach", "false"},
	{"maintenance.auto", "false"},
	{"fetch.unpackLimit", "1"},
	{"transfer.unpackLimit", "1"},
	{"core.logAllRefUpdates", "false"},
}

// selectedRef reports whether a ref is one FetchRefspecs fetches (git refspec
// globbing: the single '*' matches any run of characters, slashes included)
func selectedRef(ref string) bool {
	for _, spec := range FetchRefspecs {
		src, _, _ := strings.Cut(strings.TrimPrefix(spec, "+"), ":")
		prefix, suffix, _ := strings.Cut(src, "*")
		if len(ref) > len(prefix)+len(suffix) && strings.HasPrefix(ref, prefix) && strings.HasSuffix(ref, suffix) {
			return true
		}
	}
	return false
}

// refsDigest hashes "<oid> <ref>" lines in sorted order
func refsDigest(lines []string) (string, int) {
	sort.Strings(lines)
	h := sha256.New()
	for _, l := range lines {
		h.Write([]byte(l + "\n"))
	}
	return hex.EncodeToString(h.Sum(nil)), len(lines)
}

// Mirror is one bare repository the agent keeps between runs (one per project and
// per wiki, in the job's state directory, named by project id)
type Mirror struct {
	// Dir is the bare repository
	Dir string
	// URL is the remote, rewritten into remote.origin.url before every fetch so a
	// renamed project keeps its mirror
	URL string
	git *Git
}

// NewMirror returns the mirror in dir fetching from url
func (g *Git) NewMirror(dir, url string) *Mirror {
	return &Mirror{Dir: dir, URL: url, git: g}
}

// Exists reports whether the bare repository has been created
func (m *Mirror) Exists() bool {
	_, err := os.Stat(filepath.Join(m.Dir, "HEAD"))
	return err == nil
}

// FetchResult describes one fetch
type FetchResult struct {
	// Created: the mirror did not exist before this fetch
	Created bool
	// Changed: the selected refs differ from before the fetch (always true when
	// Created)
	Changed bool
	// Refs is the number of selected refs after the fetch; Digest their digest
	Refs   int
	Digest string
}

// Fetch brings the mirror up to date, creating it on first use. A mirror created by
// a fetch that fails is removed again, so "no mirror" keeps meaning "never fetched".
// FETCH_HEAD is not written: it would change on every run.
func (m *Mirror) Fetch(ctx context.Context, progress func(string)) (res FetchResult, err error) {
	if !m.Exists() {
		if err := m.create(ctx); err != nil {
			return res, err
		}
		res.Created = true
		defer func() {
			if err != nil {
				_ = os.RemoveAll(m.Dir)
			}
		}()
	}
	before, _, err := m.LocalRefs(ctx)
	if err != nil {
		return res, err
	}
	// Only rewrite config when the URL moved: an untouched config keeps its mtime, so
	// the backup can reuse it
	current, _ := m.git.output(ctx, m.Dir, "config", "--get", "remote.origin.url")
	if strings.TrimSpace(current) != m.URL {
		if err := m.git.run(ctx, m.Dir, nil, nil, "config", "remote.origin.url", m.URL); err != nil {
			return res, err
		}
	}
	args := append([]string{"fetch", "--prune", "--no-tags", "--no-write-fetch-head", "--no-auto-maintenance",
		"--no-recurse-submodules", "--progress", "origin"}, FetchRefspecs...)
	if err := m.git.run(ctx, m.Dir, nil, progress, args...); err != nil {
		return res, err
	}
	res.Digest, res.Refs, err = m.LocalRefs(ctx)
	if err != nil {
		return res, err
	}
	res.Changed = res.Created || res.Digest != before
	if res.Changed {
		// One packed-refs file instead of a file per updated ref
		if err := m.git.run(ctx, m.Dir, nil, nil, "pack-refs", "--all", "--prune"); err != nil {
			return res, err
		}
	}
	return res, nil
}

// create initialises the bare repository with mirrorConfig
func (m *Mirror) create(ctx context.Context) error {
	if err := os.MkdirAll(filepath.Dir(m.Dir), 0o700); err != nil {
		return err
	}
	if err := m.git.run(ctx, "", nil, nil, "init", "--bare", "--quiet", m.Dir); err != nil {
		_ = os.RemoveAll(m.Dir)
		return err
	}
	for _, kv := range mirrorConfig {
		if err := m.git.run(ctx, m.Dir, nil, nil, "config", kv[0], kv[1]); err != nil {
			_ = os.RemoveAll(m.Dir)
			return err
		}
	}
	return nil
}

// FetchLFS downloads every LFS object referenced by any ref into the mirror's
// lfs/objects (a repository without LFS pointers costs a history scan and no
// requests)
func (m *Mirror) FetchLFS(ctx context.Context, progress func(string)) error {
	// The token goes to the repository's LFS API only. Its batch answer carries the
	// credentials for each download (GitLab and Gitea an Authorization header,
	// others signed URLs); sending ours as well makes GitLab refuse the download
	// with 400 (two Authorization headers).
	return m.git.runScoped(ctx, m.Dir, lfsEndpoint(m.URL), nil, progress, "lfs", "fetch", "--all", "origin")
}

// lfsEndpoint is the LFS API git-lfs derives from a remote URL: <url>/info/lfs,
// with .git appended to the URL when it lacks it
func lfsEndpoint(url string) string {
	url = strings.TrimRight(url, "/")
	if !strings.HasSuffix(url, ".git") {
		url += ".git"
	}
	return url + "/info/lfs"
}

// LocalRefs lists the mirror's selected refs and their digest (comparable with
// Git.RemoteRefs)
func (m *Mirror) LocalRefs(ctx context.Context) (digest string, count int, err error) {
	out, err := m.git.output(ctx, m.Dir, "for-each-ref", "--format=%(objectname) %(refname)")
	if err != nil {
		return "", 0, err
	}
	var lines []string
	for l := range strings.SplitSeq(out, "\n") {
		if _, ref, ok := strings.Cut(strings.TrimSpace(l), " "); ok && selectedRef(ref) {
			lines = append(lines, strings.TrimSpace(l))
		}
	}
	d, n := refsDigest(lines)
	return d, n, nil
}

// PackCount is the number of packfiles in the mirror
func (m *Mirror) PackCount() int {
	packs, _ := filepath.Glob(filepath.Join(m.Dir, "objects", "pack", "*.pack"))
	return len(packs)
}

// Repack merges small packs once there are more than threshold of them (0 =
// DefaultRepackThreshold). Geometric repacking leaves the large packs untouched, so
// most of the mirror stays byte-identical for the backup. Reports whether it ran.
func (m *Mirror) Repack(ctx context.Context, threshold int) (bool, error) {
	if threshold <= 0 {
		threshold = DefaultRepackThreshold
	}
	if m.PackCount() <= threshold {
		return false, nil
	}
	if err := m.git.run(ctx, m.Dir, nil, nil, "repack", "-d", "--geometric=2", "--quiet", "--no-write-bitmap-index"); err != nil {
		return false, fmt.Errorf("repacking %s: %w", m.Dir, err)
	}
	return true, nil
}

// Size is the size of the mirror and, within it, of its LFS objects
func (m *Mirror) Size() (total, lfs int64) {
	return dirSize(m.Dir), dirSize(filepath.Join(m.Dir, "lfs"))
}
