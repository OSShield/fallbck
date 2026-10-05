package m365

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/osshield/gopbs/scan"
)

// Entry is one file of a unit's virtual tree. Open is called at most once, when
// gopbs reads the content; it is never called for an item reused from the previous
// snapshot.
type Entry struct {
	// Path is the archive path with '/' separators, no leading slash
	Path  string
	Size  int64
	Mtime time.Time
	Open  func() (io.ReadCloser, error)
}

// Dir is an explicit directory (empty folders; every parent of an entry is implied)
type Dir struct {
	Path  string
	Mtime time.Time
}

// lazyReader opens its source on the first Read and closes it at EOF
type lazyReader struct {
	open func() (io.ReadCloser, error)
	rc   io.ReadCloser
	done bool
}

func (l *lazyReader) Read(p []byte) (int, error) {
	if l.done {
		return 0, io.EOF
	}
	if l.rc == nil {
		rc, err := l.open()
		if err != nil {
			l.done = true
			return 0, err
		}
		l.rc = rc
	}
	n, err := l.rc.Read(p)
	if err == io.EOF {
		l.done = true
		_ = l.rc.Close()
	}
	return n, err
}

// BuildTree assembles the virtual directory named root from entries and explicit
// directories. Parents are created as needed; files sort with the directory
// (gopbs sorts children again). A path component that is not a valid archive name
// is rewritten by safeComponent.
func BuildTree(root string, entries []Entry, dirs []Dir, now time.Time) (*scan.Node, error) {
	nodes := map[string]*scan.Node{"": {Name: root, Kind: scan.KindDirectory, Stat: dirStat(now)}}
	var ensure func(path string, mtime time.Time) *scan.Node
	ensure = func(path string, mtime time.Time) *scan.Node {
		if n, ok := nodes[path]; ok {
			return n
		}
		parentPath, name := "", path
		if i := strings.LastIndexByte(path, '/'); i >= 0 {
			parentPath, name = path[:i], path[i+1:]
		}
		parent := ensure(parentPath, mtime)
		n := &scan.Node{Name: safeComponent(name), Kind: scan.KindDirectory, Stat: dirStat(mtime)}
		parent.Children = append(parent.Children, n)
		nodes[path] = n
		return n
	}
	for _, d := range dirs {
		if p := cleanPath(d.Path); p != "" {
			ensure(p, d.Mtime)
		}
	}
	seen := map[string]bool{}
	for _, e := range entries {
		p := cleanPath(e.Path)
		if p == "" {
			return nil, fmt.Errorf("entry with empty path")
		}
		if seen[p] {
			return nil, fmt.Errorf("duplicate archive path %s", p)
		}
		seen[p] = true
		parentPath, name := "", p
		if i := strings.LastIndexByte(p, '/'); i >= 0 {
			parentPath, name = p[:i], p[i+1:]
		}
		parent := ensure(parentPath, e.Mtime)
		open := e.Open
		if open == nil {
			open = func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(nil)), nil }
		}
		parent.Children = append(parent.Children, &scan.Node{
			Name: safeComponent(name), Kind: scan.KindStream,
			Stat:   scan.Stat{Mode: scan.ModeRegular | 0o644, Size: e.Size, MtimeSecs: e.Mtime.Unix(), MtimeNanos: uint32(e.Mtime.Nanosecond()), Nlink: 1},
			Stream: &lazyReader{open: open},
		})
	}
	// Sort directory children so duplicate names surface as an error from AddTree
	// deterministically; gopbs sorts again
	for _, n := range nodes {
		sort.Slice(n.Children, func(i, j int) bool { return n.Children[i].Name < n.Children[j].Name })
	}
	return nodes[""], nil
}

func dirStat(mtime time.Time) scan.Stat {
	return scan.Stat{Mode: scan.ModeDir | 0o755, MtimeSecs: mtime.Unix(), MtimeNanos: uint32(mtime.Nanosecond()), Nlink: 1}
}

func cleanPath(p string) string {
	parts := strings.Split(p, "/")
	out := parts[:0]
	for _, s := range parts {
		if s != "" && s != "." {
			out = append(out, s)
		}
	}
	return strings.Join(out, "/")
}

// safeComponent makes a Graph display name usable as an archive entry name: no
// slashes or NUL, not "." or "..", at most 240 bytes
func safeComponent(name string) string {
	name = strings.Map(func(r rune) rune {
		switch r {
		case '/', '\\', 0:
			return '_'
		}
		return r
	}, name)
	name = strings.TrimSpace(name)
	if name == "" || name == "." || name == ".." {
		return "_" + name
	}
	if len(name) > 240 {
		name = name[:240]
	}
	return name
}

// shortID is a stable 8-hex-digit tag of a Graph id for file names
func shortID(id string) string {
	sum := sha256.Sum256([]byte(id))
	return hex.EncodeToString(sum[:4])
}

// memEntry is an in-memory file (JSON documents): mtime now, so it is always
// re-read and never reused on equal size with different content
func memEntry(path string, data []byte, now time.Time) Entry {
	return Entry{Path: path, Size: int64(len(data)), Mtime: now, Open: func() (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(data)), nil
	}}
}
