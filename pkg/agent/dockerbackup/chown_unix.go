//go:build !windows

package dockerbackup

import (
	"os"
	"syscall"
)

// chownLike copies the owner of info onto target (best effort, needs root)
func chownLike(target string, info os.FileInfo) {
	if st, ok := info.Sys().(*syscall.Stat_t); ok {
		_ = os.Lchown(target, int(st.Uid), int(st.Gid))
	}
}
