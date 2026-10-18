package backup

import (
	"strings"
	"testing"

	"github.com/osshield/gopbs/scan"
	"golang.org/x/sys/unix"
)

const sampleMountinfo = `22 1 8:1 / / rw,relatime shared:1 - ext4 /dev/sda1 rw
23 22 0:21 / /proc rw,nosuid shared:12 - proc proc rw
24 22 0:22 / /sys rw,nosuid shared:7 - sysfs sysfs rw
25 22 0:5 / /dev rw,nosuid shared:2 - devtmpfs udev rw,size=4096k
26 25 0:23 / /dev/pts rw shared:3 - devpts devpts rw
27 22 0:24 / /run rw,nosuid shared:5 - tmpfs tmpfs rw
28 22 8:17 / /srv/data rw,relatime shared:30 - xfs /dev/sdb1 rw
29 22 0:50 / /host/proc rw shared:40 opt:1 - proc proc rw
garbage line
`

func TestMountTypes(t *testing.T) {
	types := mountTypes(strings.NewReader(sampleMountinfo))
	for dev, want := range map[uint64]string{
		unix.Mkdev(8, 1): "ext4", unix.Mkdev(0, 21): "proc", unix.Mkdev(0, 5): "devtmpfs",
		unix.Mkdev(0, 24): "tmpfs", unix.Mkdev(8, 17): "xfs", unix.Mkdev(0, 50): "proc",
	} {
		if types[dev] != want {
			t.Errorf("device %d: %q, want %q", dev, types[dev], want)
		}
	}
}

func TestMountFilter(t *testing.T) {
	types := mountTypes(strings.NewReader(sampleMountinfo))
	root, data := unix.Mkdev(8, 1), unix.Mkdev(8, 17)
	devOf := func(p string) (uint64, bool) {
		if p == "/srv/data" {
			return data, true
		}
		return root, true
	}
	st := func(dev uint64) scan.Stat { return scan.Stat{Dev: dev, Mode: 0o040755} }
	cases := []struct {
		roots []string
		oneFS bool
		path  string
		dev   uint64
		want  bool
	}{
		{[]string{"/"}, false, "/etc", root, true},
		{[]string{"/"}, false, "/proc", unix.Mkdev(0, 21), false},
		{[]string{"/"}, false, "/sys", unix.Mkdev(0, 22), false},
		{[]string{"/"}, false, "/dev", unix.Mkdev(0, 5), false},
		{[]string{"/"}, false, "/run", unix.Mkdev(0, 24), true}, // tmpfs is not a kernel filesystem
		{[]string{"/host"}, false, "/host/proc", unix.Mkdev(0, 50), false},
		{[]string{"/"}, false, "/srv/data", data, true}, // other filesystems stay by default
		{[]string{"/"}, true, "/srv/data", data, false},
		{[]string{"/"}, true, "/run", unix.Mkdev(0, 24), false},
		{[]string{"/", "/srv/data"}, true, "/srv/data/x", data, true}, // its own root
		{[]string{"/"}, true, "/etc/hosts", root, true},
		{[]string{"/"}, false, "/btrfs-subvol", unix.Mkdev(0, 99), true}, // unknown device: kept
	}
	for _, tc := range cases {
		f := newMountFilter(tc.roots, tc.oneFS, types, devOf)
		if got := f(tc.path, "", st(tc.dev)); got != tc.want {
			t.Errorf("roots %v oneFS %v %s: %v, want %v", tc.roots, tc.oneFS, tc.path, got, tc.want)
		}
	}
}

// TestMountFilterRealProc runs the filter against this machine's /proc and /etc
func TestMountFilterRealProc(t *testing.T) {
	var procSt, etcSt unix.Stat_t
	if unix.Lstat("/proc/self", &procSt) != nil || unix.Lstat("/etc", &etcSt) != nil {
		t.Skip("no /proc")
	}
	f := mountFilter([]string{"/"}, false)
	if f("/proc", "proc", scan.Stat{Dev: uint64(procSt.Dev)}) {
		t.Error("the real /proc was not recognised as a kernel filesystem")
	}
	if !f("/etc", "etc", scan.Stat{Dev: uint64(etcSt.Dev)}) {
		t.Error("/etc was left out")
	}
}
