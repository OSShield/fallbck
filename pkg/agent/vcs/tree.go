package vcs

import (
	"bytes"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/osshield/gopbs/pxar"
	"github.com/osshield/gopbs/scan"
)

// Names inside the archive
const (
	// RepositoryDir / WikiDir hold a project's mirrors below its path. GitLab paths
	// cannot end in .git, so neither can collide with a subgroup or project.
	RepositoryDir = "repository.git"
	WikiDir       = "wiki.git"
	// RestoreReadme / RestoreScript sit at the archive root
	RestoreReadme = "RESTORE.md"
	RestoreScript = "restore.sh"
)

// TreeProject places one project's mirrors in the archive
type TreeProject struct {
	// Path is the directory in the archive: the GitLab full path (platform/api) or
	// <host>/<path> for the git provider
	Path string
	// Repository is the project's mirror on disk
	Repository string
	// Wiki is the wiki's mirror on disk ("" when none)
	Wiki string
}

// BuildTree assembles the run's virtual tree: every project's mirrors under its
// path, plus RESTORE.md and restore.sh at the root. Mirror files become stream leaves
// carrying their on-disk mode, size and mtime, which is what pxar v2 change detection
// compares: a file unchanged since the previous run is referenced from the previous
// snapshot and never opened.
func BuildTree(name string, projects []TreeProject, now time.Time) (*scan.Node, error) {
	root := &scan.Node{Name: name, Kind: scan.KindDirectory, Stat: virtualDirStat(now)}
	dirs := map[string]*scan.Node{"": root}
	var ensure func(p string) *scan.Node
	ensure = func(p string) *scan.Node {
		if n, ok := dirs[p]; ok {
			return n
		}
		parent, base := "", p
		if i := strings.LastIndexByte(p, '/'); i >= 0 {
			parent, base = p[:i], p[i+1:]
		}
		n := &scan.Node{Name: base, Kind: scan.KindDirectory, Stat: virtualDirStat(now)}
		pn := ensure(parent)
		pn.Children = append(pn.Children, n)
		dirs[p] = n
		return n
	}
	seen := map[string]bool{}
	for _, pr := range projects {
		p, err := projectPath(pr.Path)
		if err != nil {
			return nil, err
		}
		if seen[p] {
			return nil, fmt.Errorf("two projects share the archive path %s", p)
		}
		seen[p] = true
		dir := ensure(p)
		repo, err := diskNode(pr.Repository, RepositoryDir)
		if err != nil {
			return nil, fmt.Errorf("project %s: %w", p, err)
		}
		dir.Children = append(dir.Children, repo)
		if pr.Wiki != "" {
			wiki, err := diskNode(pr.Wiki, WikiDir)
			if err != nil {
				return nil, fmt.Errorf("project %s wiki: %w", p, err)
			}
			dir.Children = append(dir.Children, wiki)
		}
	}
	root.Children = append(root.Children,
		memNode(RestoreReadme, []byte(restoreReadme), 0o644, now),
		memNode(RestoreScript, []byte(restoreScript), 0o755, now))
	for _, n := range dirs {
		sort.Slice(n.Children, func(i, j int) bool { return n.Children[i].Name < n.Children[j].Name })
	}
	return root, nil
}

// projectPath cleans an archive path and refuses what would collide with the
// archive's own names or escape it
func projectPath(p string) (string, error) {
	segs := strings.Split(strings.Trim(p, "/"), "/")
	for i, s := range segs {
		switch {
		case s == "" || s == "." || s == "..":
			return "", fmt.Errorf("invalid project path %q", p)
		case s == RepositoryDir || s == WikiDir:
			return "", fmt.Errorf("project path %q uses the reserved name %s", p, s)
		case i == 0 && (s == RestoreReadme || s == RestoreScript):
			return "", fmt.Errorf("project path %q collides with %s at the archive root", p, s)
		}
		if err := pxar.ValidateFilename(s); err != nil {
			return "", fmt.Errorf("invalid project path %q: %w", p, err)
		}
	}
	return strings.Join(segs, "/"), nil
}

// skipFile reports mirror files that are left out of the archive: transient state
// git rewrites on every fetch, and lock files of an interrupted git
func skipFile(name string) bool {
	return name == "FETCH_HEAD" || strings.HasSuffix(name, ".lock")
}

// diskNode mirrors a bare repository on disk as virtual-tree nodes
func diskNode(dir, name string) (*scan.Node, error) {
	info, err := os.Lstat(dir)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("%s is not a directory", dir)
	}
	n := &scan.Node{Name: name, Kind: scan.KindDirectory, Stat: diskStat(info, scan.ModeDir)}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	for _, e := range entries {
		p := filepath.Join(dir, e.Name())
		switch {
		case e.IsDir():
			c, err := diskNode(p, e.Name())
			if err != nil {
				return nil, err
			}
			n.Children = append(n.Children, c)
		case e.Type().IsRegular():
			if skipFile(e.Name()) {
				continue
			}
			fi, err := e.Info()
			if err != nil {
				return nil, err
			}
			n.Children = append(n.Children, &scan.Node{Name: e.Name(), Kind: scan.KindStream,
				Stat: diskStat(fi, scan.ModeRegular), Stream: &fileReader{path: p}})
		default:
			// A bare repository holds directories and regular files only
			return nil, fmt.Errorf("unexpected %s in a mirror: %s", e.Type(), p)
		}
	}
	return n, nil
}

func diskStat(fi fs.FileInfo, kind uint64) scan.Stat {
	mt := fi.ModTime()
	st := scan.Stat{Mode: kind | uint64(fi.Mode().Perm()), MtimeSecs: mt.Unix(), MtimeNanos: uint32(mt.Nanosecond()), Nlink: 1}
	if kind == scan.ModeRegular {
		st.Size = fi.Size()
	}
	return st
}

func virtualDirStat(now time.Time) scan.Stat {
	return scan.Stat{Mode: scan.ModeDir | 0o755, MtimeSecs: now.Unix(), MtimeNanos: uint32(now.Nanosecond()), Nlink: 1}
}

func memNode(name string, data []byte, perm uint64, now time.Time) *scan.Node {
	return &scan.Node{Name: name, Kind: scan.KindStream,
		Stat:   scan.Stat{Mode: scan.ModeRegular | perm, Size: int64(len(data)), MtimeSecs: now.Unix(), MtimeNanos: uint32(now.Nanosecond()), Nlink: 1},
		Stream: bytes.NewReader(data)}
}

// fileReader opens its file on the first Read and closes it at EOF; a leaf reused
// from the previous snapshot is never read, so its file is never opened
type fileReader struct {
	path string
	f    *os.File
	done bool
}

func (r *fileReader) Read(p []byte) (int, error) {
	if r.done {
		return 0, io.EOF
	}
	if r.f == nil {
		f, err := os.Open(r.path)
		if err != nil {
			r.done = true
			return 0, err
		}
		r.f = f
	}
	n, err := r.f.Read(p)
	if err == io.EOF {
		r.done = true
		_ = r.f.Close()
	}
	return n, err
}

const restoreReadme = `# Restoring repositories from this backup

Every project is a directory named after its path (the GitLab full path, or
<host>/<path> for plain git repositories) holding:

- repository.git/ : a bare mirror with all branches, tags and merge request
  heads (refs/merge-requests/<iid>/head), and Git LFS objects in lfs/objects/
- wiki.git/ : the project wiki, when it has one

Issues, merge request discussions, CI/CD settings and other project data are not
part of this backup.

## Restore one project

1. Restore the project's directory from Proxmox Backup Server, for example with
   the PBS web UI (Content > File browser > Download) or:

       proxmox-backup-client restore <snapshot> vcs.pxar ./restore \
           --repository <repository>

2. Create an empty project on the git host, then run from the restored archive
   root:

       sh restore.sh <project path> <empty remote URL> [<wiki remote URL>]

   This pushes all branches and tags, then the LFS objects (git-lfs required) and,
   when given a wiki URL, the wiki. Merge request refs are read-only on GitLab and
   are not pushed; they stay in the backup for reference.

## Inspect without restoring to a server

    git clone <project path>/repository.git ./checkout
`

const restoreScript = `#!/bin/sh
# Restores one project from this backup into an empty remote repository.
# Usage: restore.sh <project path> <empty remote URL> [<wiki remote URL>]
set -eu

if [ $# -lt 2 ]; then
    echo "usage: $0 <project path> <empty remote URL> [<wiki remote URL>]" >&2
    exit 2
fi
here=$(cd "$(dirname "$0")" && pwd)
repo="$here/$1/repository.git"
if [ ! -d "$repo" ]; then
    echo "no repository at $repo" >&2
    exit 1
fi

# LFS objects first: GitLab refuses a push whose LFS objects it does not have yet
if [ -d "$repo/lfs/objects" ]; then
    if git lfs version >/dev/null 2>&1; then
        git --git-dir="$repo" lfs push --all "$2"
    else
        echo "warning: git-lfs is not installed; the LFS objects were not pushed" >&2
    fi
fi

# Branches and tags. Merge request refs are read-only on GitLab and stay in the backup.
git --git-dir="$repo" push "$2" '+refs/heads/*:refs/heads/*' '+refs/tags/*:refs/tags/*'

if [ $# -ge 3 ]; then
    wiki="$here/$1/wiki.git"
    if [ ! -d "$wiki" ]; then
        echo "no wiki at $wiki" >&2
        exit 1
    fi
    git --git-dir="$wiki" push "$3" '+refs/heads/*:refs/heads/*'
fi
`
