package remote

import (
	"bytes"
	"context"
	"io"
	"os"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	libfs "github.com/scheiblingco/librc/fs"

	"github.com/osshield/fallbck/pkg/agent/vtree"
	"github.com/osshield/gopbs/scan"
)

// fakeFS is a Source over in-memory objects; a key ending in "/" is a directory
type fakeFS struct {
	objects map[string]string
	mtime   time.Time
	opened  []string
}

type fakeEntry struct {
	path  string
	dir   bool
	size  int64
	mtime time.Time
}

func (e fakeEntry) Name() string                      { return e.path[strings.LastIndexByte(e.path, '/')+1:] }
func (e fakeEntry) IsDir() bool                       { return e.dir }
func (e fakeEntry) Size() int64                       { return e.size }
func (e fakeEntry) ModTime(context.Context) time.Time { return e.mtime }
func (e fakeEntry) Info() (os.FileInfo, error)        { return nil, nil }
func (e fakeEntry) Type() os.FileMode                 { return 0 }
func (e fakeEntry) Remote() string                    { return e.path }

func (f *fakeFS) Walk(_ context.Context, _ string, fn func(libfs.DirEntry) error) error {
	keys := make([]string, 0, len(f.objects))
	for k := range f.objects {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	for _, k := range keys {
		e := fakeEntry{path: strings.TrimSuffix(k, "/"), dir: strings.HasSuffix(k, "/"), size: int64(len(f.objects[k])), mtime: f.mtime}
		if err := fn(e); err != nil {
			return err
		}
	}
	return nil
}

func (f *fakeFS) Open(_ context.Context, p string) (io.ReadCloser, error) {
	f.opened = append(f.opened, p)
	return io.NopCloser(strings.NewReader(f.objects[p])), nil
}

func paths(entries []vtree.Entry, dirs []vtree.Dir) (files, ds []string) {
	for _, e := range entries {
		files = append(files, e.Path)
	}
	for _, d := range dirs {
		ds = append(ds, d.Path)
	}
	slices.Sort(files)
	slices.Sort(ds)
	return files, ds
}

func TestWalkGlobs(t *testing.T) {
	src := &fakeFS{mtime: time.Unix(1700000000, 0), objects: map[string]string{
		"photos/2026/a.jpg": "a", "photos/2026/tmp/x.jpg": "x", "photos/b.jpg": "b",
		"docs/c.txt": "c", "readme.md": "r", "empty/": "", "Tmp/y": "y",
	}}
	for name, tc := range map[string]struct {
		include, exclude []string
		files, dirs      []string
	}{
		"everything": {nil, nil,
			[]string{"bucket/Tmp/y", "bucket/docs/c.txt", "bucket/photos/2026/a.jpg", "bucket/photos/2026/tmp/x.jpg", "bucket/photos/b.jpg", "bucket/readme.md"},
			[]string{"bucket", "bucket/Tmp", "bucket/docs", "bucket/empty", "bucket/photos", "bucket/photos/2026", "bucket/photos/2026/tmp"}},
		// A directory match takes everything below; '*' stays within one segment
		"include dir": {[]string{"photos"}, nil,
			[]string{"bucket/photos/2026/a.jpg", "bucket/photos/2026/tmp/x.jpg", "bucket/photos/b.jpg"},
			[]string{"bucket", "bucket/photos", "bucket/photos/2026", "bucket/photos/2026/tmp"}},
		"include top-level glob": {[]string{"*.md"}, nil, []string{"bucket/readme.md"}, []string{"bucket"}},
		// Exclude wins and cuts whole directories, case-insensitively
		"exclude": {[]string{"photos"}, []string{"*/*/tmp", "tmp"},
			[]string{"bucket/photos/2026/a.jpg", "bucket/photos/b.jpg"},
			[]string{"bucket", "bucket/photos", "bucket/photos/2026"}},
	} {
		entries, dirs, err := Walk(context.Background(), src, "bucket", tc.include, tc.exclude, &Warnings{})
		if err != nil {
			t.Fatal(err)
		}
		files, ds := paths(entries, dirs)
		if !slices.Equal(files, tc.files) || !slices.Equal(ds, tc.dirs) {
			t.Errorf("%s:\nfiles %v\nwant  %v\ndirs %v\nwant %v", name, files, tc.files, ds, tc.dirs)
		}
	}
}

func TestWalkSkipsUnusablePaths(t *testing.T) {
	src := &fakeFS{objects: map[string]string{"a//b": "1", "a/./c": "2", "ok": "3"}}
	w := &Warnings{}
	entries, _, err := Walk(context.Background(), src, "", nil, nil, w)
	if err != nil {
		t.Fatal(err)
	}
	if files, _ := paths(entries, nil); !slices.Equal(files, []string{"ok"}) || len(w.List()) != 2 {
		t.Errorf("files %v warnings %v", files, w.List())
	}
}

// Two walks of the same data give identical trees: directories carry DirMtime and
// files their listed mtime, mode 0644 and uid/gid 0, so gopbs reuses them. The walk
// opens nothing.
func TestWalkMetadataIsStable(t *testing.T) {
	src := &fakeFS{mtime: time.Unix(1700000000, 123), objects: map[string]string{"a/b/c": "hello", "d": "x"}}
	build := func() *scan.Node {
		entries, dirs, err := Walk(context.Background(), src, "root", nil, nil, &Warnings{})
		if err != nil {
			t.Fatal(err)
		}
		tree, err := vtree.BuildTree("remote", entries, dirs, DirMtime)
		if err != nil {
			t.Fatal(err)
		}
		return tree
	}
	strip := func(n *scan.Node) {
		var walk func(*scan.Node)
		walk = func(n *scan.Node) {
			n.Stream = nil
			for _, c := range n.Children {
				walk(c)
			}
		}
		walk(n)
	}
	a, b := build(), build()
	strip(a)
	strip(b)
	if !reflect.DeepEqual(a, b) {
		t.Error("two walks differ")
	}
	if len(src.opened) != 0 {
		t.Errorf("the walk opened %v", src.opened)
	}
	root := a.Children[0]
	if root.Name != "root" || root.Stat.MtimeSecs != 0 || root.Stat.Mode != scan.ModeDir|0o755 {
		t.Errorf("directory: %+v", root.Stat)
	}
	var file *scan.Node
	for _, c := range root.Children {
		if c.Name == "d" {
			file = c
		}
	}
	if file == nil || file.Stat.MtimeSecs != 1700000000 || file.Stat.MtimeNanos != 123 || file.Stat.Mode != scan.ModeRegular|0o644 || file.Stat.UID != 0 || file.Stat.GID != 0 {
		t.Errorf("file: %+v", file)
	}
}

// An object that changed size after listing still yields the listed size
func TestSizeGuard(t *testing.T) {
	for name, tc := range map[string]struct {
		listed  string
		now     string
		want    []byte
		warning string
	}{
		"same":   {"hello", "hello", []byte("hello"), ""},
		"grew":   {"hello", "hello, world", []byte("hello"), "grew"},
		"shrank": {"hello", "he", []byte{'h', 'e', 0, 0, 0}, "shrank"},
		"empty":  {"", "", []byte{}, ""},
	} {
		src := &fakeFS{objects: map[string]string{"f": tc.listed}}
		w := &Warnings{}
		entries, _, err := Walk(context.Background(), src, "", nil, nil, w)
		if err != nil {
			t.Fatal(err)
		}
		src.objects["f"] = tc.now
		rc, err := entries[0].Open()
		if err != nil {
			t.Fatal(err)
		}
		got, err := io.ReadAll(rc)
		_ = rc.Close()
		if err != nil || !bytes.Equal(got, tc.want) {
			t.Errorf("%s: %q %v", name, got, err)
		}
		warnings := w.List()
		if (tc.warning == "") != (len(warnings) == 0) || (tc.warning != "" && !strings.Contains(warnings[0], tc.warning)) {
			t.Errorf("%s: warnings %v", name, warnings)
		}
	}
}
