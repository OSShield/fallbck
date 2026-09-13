//go:build !windows

package dbbackup

import "golang.org/x/sys/unix"

// freeBytes reports the free space for unprivileged users on the filesystem holding path
var freeBytes = func(path string) (uint64, error) {
	var st unix.Statfs_t
	if err := unix.Statfs(path, &st); err != nil {
		return 0, err
	}
	return st.Bavail * uint64(st.Bsize), nil
}
