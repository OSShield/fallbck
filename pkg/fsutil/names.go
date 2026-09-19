package fsutil

import (
	"path"
	"strings"
)

// FlattenPath turns an absolute path into a single name usable as an archive entry
// (`/var/lib/mydir` → `var-lib-mydir`, `D:\data\x` → `D-data-x`, `/` → `root`). Both
// path styles are handled on every platform, so the slash-only path package is used.
func FlattenPath(p string) string {
	trimmed := strings.Trim(path.Clean(strings.ReplaceAll(p, `\`, "/")), "/")
	trimmed = strings.ReplaceAll(trimmed, ":", "")
	if trimmed == "" {
		return "root"
	}
	return strings.ReplaceAll(trimmed, "/", "-")
}
