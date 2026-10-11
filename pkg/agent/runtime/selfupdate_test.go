package runtime

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSwapBinaryKeepsOldAndRestoresOnFailure(t *testing.T) {
	dir := t.TempDir()
	exe, tmp := filepath.Join(dir, "agent"), filepath.Join(dir, "agent.new")
	_ = os.WriteFile(exe, []byte("old"), 0o755)
	_ = os.WriteFile(tmp, []byte("new"), 0o755)
	if err := swapBinary(exe, tmp); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(exe); string(b) != "new" {
		t.Fatalf("exe = %q", b)
	}
	if b, _ := os.ReadFile(exe + ".old"); string(b) != "old" {
		t.Fatalf("old = %q", b)
	}
	// Missing new file: the original is put back
	if err := swapBinary(exe, filepath.Join(dir, "missing")); err == nil {
		t.Fatal("expected an error")
	}
	if b, _ := os.ReadFile(exe); string(b) != "new" {
		t.Fatalf("exe not restored: %q", b)
	}
}
