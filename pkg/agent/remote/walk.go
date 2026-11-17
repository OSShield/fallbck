package remote

import (
	"context"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	libfs "github.com/scheiblingco/librc/fs"

	"github.com/osshield/fallbck/pkg/agent/vtree"
	"github.com/osshield/fallbck/pkg/naming"
)

// DirMtime is the mtime of every directory in a remote snapshot. Object stores have
// no real directories and listing gives no stable time for the others, so a fixed
// one keeps directories from defeating reuse.
var DirMtime = time.Unix(0, 0).UTC()

// Warnings collects what a run should report without failing (the run ends partial)
type Warnings struct {
	mu   sync.Mutex
	list []string
}

// Add records a warning
func (w *Warnings) Add(format string, args ...any) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.list = append(w.list, fmt.Sprintf(format, args...))
}

// List returns the warnings so far
func (w *Warnings) List() []string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return append([]string(nil), w.list...)
}

// Walk lists one root of src as tree entries below prefix ("" puts them at the top).
// A path is taken when include is empty or the path or one of its parent
// directories matches it, and neither matches exclude. Files keep their size and
// mtime; every directory gets DirMtime. Objects whose keys don't make a usable path
// ("a//b", "a/./b") are skipped with a warning.
func Walk(ctx context.Context, src Source, prefix string, include, exclude []string, warn *Warnings) ([]vtree.Entry, []vtree.Dir, error) {
	var (
		mu      sync.Mutex // librc may call back from several listers
		entries []vtree.Entry
		dirs    = map[string]bool{}
	)
	full := func(p string) string {
		if prefix == "" {
			return p
		}
		return prefix + "/" + p
	}
	addParents := func(p string) {
		for i := strings.LastIndexByte(p, '/'); i > 0; i = strings.LastIndexByte(p[:i], '/') {
			dirs[full(p[:i])] = true
		}
	}
	err := src.Walk(ctx, "", func(e libfs.DirEntry) error {
		p := e.Remote()
		if !usablePath(p) {
			warn.Add("skipped %q: not a usable path", p)
			return nil
		}
		if !selected(p, include, exclude) {
			return nil
		}
		mu.Lock()
		defer mu.Unlock()
		addParents(p)
		if e.IsDir() {
			dirs[full(p)] = true
			return nil
		}
		size := e.Size()
		entries = append(entries, vtree.Entry{Path: full(p), Size: size, Mtime: e.ModTime(ctx).UTC(), Open: func() (io.ReadCloser, error) {
			rc, err := src.Open(ctx, p)
			if err != nil {
				return nil, err
			}
			return &sizeGuard{rc: rc, left: size, path: p, warn: warn}, nil
		}})
		return nil
	})
	if err != nil {
		return nil, nil, err
	}
	if prefix != "" {
		dirs[prefix] = true
		addParents(prefix)
	}
	out := make([]vtree.Dir, 0, len(dirs))
	for d := range dirs {
		out = append(out, vtree.Dir{Path: d, Mtime: DirMtime})
	}
	return entries, out, nil
}

// selected applies the job's globs to p and its parent directories
func selected(p string, include, exclude []string) bool {
	in := len(include) == 0
	for i := 0; i <= len(p); i++ {
		if i < len(p) && p[i] != '/' {
			continue
		}
		part := p[:i]
		if naming.MatchesAny(part, exclude) {
			return false
		}
		in = in || naming.MatchesAny(part, include)
	}
	return in
}

func usablePath(p string) bool {
	for _, seg := range strings.Split(p, "/") {
		if seg == "" || seg == "." || seg == ".." {
			return false
		}
	}
	return true
}

// sizeGuard delivers exactly the listed size: gopbs wrote the size into the archive
// before reading. An object that shrank since listing is padded with zeros, one
// that grew is cut; both leave a warning (the next run picks up the new content).
type sizeGuard struct {
	rc      io.ReadCloser
	left    int64
	path    string
	warn    *Warnings
	padding bool
	checked bool
}

func (g *sizeGuard) Read(p []byte) (int, error) {
	if g.left <= 0 {
		if !g.checked && !g.padding {
			g.checked = true
			var b [1]byte
			if n, _ := io.ReadFull(g.rc, b[:]); n > 0 {
				g.warn.Add("%s grew while it was read; the snapshot has its first bytes only", g.path)
			}
		}
		return 0, io.EOF
	}
	if int64(len(p)) > g.left {
		p = p[:g.left]
	}
	if g.padding {
		clear(p)
		g.left -= int64(len(p))
		return len(p), nil
	}
	n, err := g.rc.Read(p)
	g.left -= int64(n)
	if err == io.EOF {
		err = nil
		if g.left > 0 {
			g.padding = true
			g.warn.Add("%s shrank while it was read; the snapshot pads it with zeros", g.path)
		}
	}
	return n, err
}

func (g *sizeGuard) Close() error { return g.rc.Close() }
