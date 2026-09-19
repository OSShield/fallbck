package fsutil

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func TestCopyTreeAndCopyMissing(t *testing.T) {
	src, dst := t.TempDir(), t.TempDir()
	if err := os.MkdirAll(filepath.Join(src, "a", "b"), 0o750); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(src, "a", "b", "f")
	if err := os.WriteFile(file, []byte("abc"), 0o640); err != nil {
		t.Fatal(err)
	}
	mtime := time.Unix(1700000000, 0)
	_ = os.Chtimes(file, mtime, mtime)
	if runtime.GOOS != "windows" {
		if err := os.Symlink("f", filepath.Join(src, "a", "b", "l")); err != nil {
			t.Fatal(err)
		}
	}
	if err := CopyTree(src, dst); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(filepath.Join(dst, "a", "b", "f"))
	if err != nil || st.Size() != 3 || st.ModTime().Unix() != mtime.Unix() {
		t.Fatalf("copied file: %v %+v", err, st)
	}
	if runtime.GOOS != "windows" {
		if st.Mode().Perm() != 0o640 {
			t.Errorf("mode %v", st.Mode().Perm())
		}
		if l, err := os.Readlink(filepath.Join(dst, "a", "b", "l")); err != nil || l != "f" {
			t.Errorf("symlink: %v %q", err, l)
		}
		if d, _ := os.Stat(filepath.Join(dst, "a", "b")); d.Mode().Perm() != 0o750 {
			t.Errorf("dir mode %v", d.Mode().Perm())
		}
	}

	// CopyMissing leaves existing files alone and only adds new ones
	if err := os.WriteFile(filepath.Join(dst, "a", "b", "f"), []byte("changed"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(src, "new"), []byte("n"), 0o600); err != nil {
		t.Fatal(err)
	}
	n, err := CopyMissing(src, dst)
	if err != nil || n != 1 {
		t.Fatalf("CopyMissing: %v, %d copied", err, n)
	}
	if data, _ := os.ReadFile(filepath.Join(dst, "a", "b", "f")); string(data) != "changed" {
		t.Errorf("existing file was overwritten: %q", data)
	}
	if n, err := CopyMissing(filepath.Join(src, "absent"), dst); err == nil || n != 0 {
		t.Errorf("missing source must fail: %v %d", err, n)
	}
}

func TestCopyFileCreatesParent(t *testing.T) {
	src := filepath.Join(t.TempDir(), "s")
	if err := os.WriteFile(src, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	dst := filepath.Join(t.TempDir(), "deep", "er", "d")
	if err := CopyFile(src, dst); err != nil {
		t.Fatal(err)
	}
	if data, err := os.ReadFile(dst); err != nil || string(data) != "x" {
		t.Errorf("copy: %v %q", err, data)
	}
}

func TestFlattenPath(t *testing.T) {
	cases := map[string]string{"/var/lib/mydir": "var-lib-mydir", "/srv/app/": "srv-app", "/": "root", `D:\data\x`: "D-data-x", "/opt": "opt"}
	for in, want := range cases {
		if got := FlattenPath(in); got != want {
			t.Errorf("FlattenPath(%q) = %q, want %q", in, got, want)
		}
	}
}
