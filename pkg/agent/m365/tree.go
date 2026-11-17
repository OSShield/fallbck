package m365

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"time"

	"github.com/osshield/fallbck/pkg/agent/vtree"
)

// The virtual tree lives in vtree, shared with remote jobs
type (
	Entry = vtree.Entry
	Dir   = vtree.Dir
)

var (
	BuildTree     = vtree.BuildTree
	safeComponent = vtree.SafeComponent
)

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
