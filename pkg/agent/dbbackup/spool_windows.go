//go:build windows

package dbbackup

import "golang.org/x/sys/windows"

// freeBytes reports the free space available to the caller on the volume holding path
var freeBytes = func(path string) (uint64, error) {
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return 0, err
	}
	var free, total, totalFree uint64
	if err := windows.GetDiskFreeSpaceEx(name, &free, &total, &totalFree); err != nil {
		return 0, err
	}
	return free, nil
}
