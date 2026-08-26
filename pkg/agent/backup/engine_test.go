package backup

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/osshield/fallbck/pkg/db"
)

func TestFilesystemBackupEngine(t *testing.T) {
	// Create mock PBS proxy server
	uploadedChunks := 0
	mockProxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		uploadedChunks++
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"data":{"digest":"ok"}}`))
	}))
	defer mockProxy.Close()

	// Create test directory with files
	tempDir := t.TempDir()
	testFile1 := filepath.Join(tempDir, "file1.txt")
	testFile2 := filepath.Join(tempDir, "file2.log")
	subDir := filepath.Join(tempDir, "subdir")
	_ = os.MkdirAll(subDir, 0755)
	testFile3 := filepath.Join(subDir, "file3.data")

	_ = os.WriteFile(testFile1, []byte("Hello FallBCK Backup World!"), 0644)
	_ = os.WriteFile(testFile2, []byte("This is a log file that should be excluded"), 0644)
	_ = os.WriteFile(testFile3, []byte("Subdirectory test content with some more bytes to chunk"), 0644)

	engine := NewBackupEngine(mockProxy.URL, "test-ticket", "datastore1", "ns1")

	var heartbeats int
	onProgress := func(currentFile string, scanned, uploaded int64, chunks int) {
		heartbeats++
	}

	result, err := engine.ExecuteFilesystemBackup(context.Background(), []string{tempDir}, []string{"*.log"}, onProgress)
	if err != nil {
		t.Fatalf("ExecuteFilesystemBackup failed: %v", err)
	}

	if result.Status != db.RunStatusCompleted {
		t.Errorf("Expected status Completed, got %s", result.Status)
	}

	if result.BytesScanned <= 0 {
		t.Errorf("Expected BytesScanned > 0, got %d", result.BytesScanned)
	}

	if result.ChunkCount != 2 { // file1.txt and file3.data (file2.log was excluded)
		t.Errorf("Expected 2 chunks for 2 non-excluded files, got %d", result.ChunkCount)
	}

	if result.SnapshotID == "" {
		t.Error("Expected non-empty snapshot ID")
	}

	if uploadedChunks != 2 {
		t.Errorf("Expected 2 uploaded chunks to mock proxy, got %d", uploadedChunks)
	}
}

func TestExcludePatternMatching(t *testing.T) {
	excludes := []string{"*.log", "/var/cache", "node_modules"}

	if !isExcluded("/path/to/test.log", excludes) {
		t.Errorf("Expected *.log to match /path/to/test.log")
	}
	if !isExcluded("/project/node_modules/package.json", excludes) {
		t.Errorf("Expected node_modules to match /project/node_modules/package.json")
	}
	if isExcluded("/path/to/valid.txt", excludes) {
		t.Errorf("Expected valid.txt not to be excluded")
	}
}
