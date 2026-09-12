package pvebackup

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	dbrun "github.com/osshield/fallbck/pkg/agent/dbbackup"
	pvespec "github.com/osshield/fallbck/pkg/pvebackup"
)

// fakeRunner answers commands from a table keyed by tool name; unknown tools are absent
type fakeRunner struct {
	outputs map[string]string
	calls   []string
}

func (f *fakeRunner) LookPath(name string) (string, error) {
	if _, ok := f.outputs[name]; ok {
		return "/usr/bin/" + name, nil
	}
	return "", os.ErrNotExist
}

func (f *fakeRunner) Run(_ context.Context, c dbrun.Command) (dbrun.Result, error) {
	f.calls = append(f.calls, c.Name+" "+strings.Join(c.Args, " "))
	out, ok := f.outputs[c.Name]
	if !ok {
		return dbrun.Result{ExitCode: 127}, os.ErrNotExist
	}
	if c.Name == "sgdisk" {
		// sgdisk --backup=<file> writes the file itself
		for _, a := range c.Args {
			if strings.HasPrefix(a, "--backup=") {
				_ = os.WriteFile(strings.TrimPrefix(a, "--backup="), []byte("gpt"), 0o600)
			}
		}
	}
	if c.Stdout != nil {
		_, _ = c.Stdout.Write([]byte(out))
	}
	return dbrun.Result{}, nil
}

const storageCfg = `dir: local
        path /var/lib/vz
        content iso,vztmpl,backup

zfspool: local-zfs
        pool rpool/data
        content images,rootdir
        sparse 1

nfs: nas
        export /volume1/pve
        path /mnt/pve/nas
        server 10.0.0.5
        content backup,iso
        shared 1
        disable 1
`

func TestParseStorageCfg(t *testing.T) {
	st := parseStorageCfg(storageCfg)
	if len(st) != 3 {
		t.Fatalf("expected 3 storages, got %d: %+v", len(st), st)
	}
	if st[0].ID != "local" || st[0].Type != "dir" || st[0].Path != "/var/lib/vz" || len(st[0].Content) != 3 {
		t.Errorf("local: %+v", st[0])
	}
	if st[1].Pool != "rpool/data" || st[1].Type != "zfspool" {
		t.Errorf("local-zfs: %+v", st[1])
	}
	if !st[2].Shared || !st[2].Disabled || st[2].Server != "10.0.0.5" || st[2].Export != "/volume1/pve" {
		t.Errorf("nas: %+v", st[2])
	}
}

func TestParsePVEVersionAndPackages(t *testing.T) {
	v, major, kernel := parsePVEVersion("proxmox-ve: 8.2.0 (running kernel: 6.8.8-2-pve)\npve-manager/8.2.4/faa83925c9641325 (running kernel: 6.8.8-2-pve)\n")
	if v != "8.2.4" || major != 8 || kernel != "6.8.8-2-pve" {
		t.Errorf("got %q %d %q", v, major, kernel)
	}
	if n := countPackages("a\t1\tinstalled\tamd64\nb\t2\tdeinstall\tamd64\nc\t3\tinstalled\tall\n"); n != 2 {
		t.Errorf("installed count %d", n)
	}
	if parseOSRelease("NAME=\"Debian GNU/Linux\"\nPRETTY_NAME=\"Debian GNU/Linux 12 (bookworm)\"\n") != "Debian GNU/Linux 12 (bookworm)" {
		t.Error("os-release")
	}
	disks := parseLsblk([]byte(`{"blockdevices":[{"name":"sda","path":"/dev/sda","size":1000204886016,"type":"disk","model":"WD","serial":"S1","children":[{"name":"sda1","type":"part"}]},{"name":"zd0","path":"/dev/zd0","size":10,"type":"disk"},{"name":"loop0","type":"loop","size":1}]}`))
	if len(disks) != 2 || disks[0].Path != "/dev/sda" || disks[0].SizeBytes != 1000204886016 || disks[0].Model != "WD" {
		t.Errorf("disks %+v", disks)
	}
}

// fixturePVE builds a fake /etc/pve tree with two guests and a storage.cfg
func fixturePVE(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	must := func(err error) {
		if err != nil {
			t.Fatal(err)
		}
	}
	must(os.MkdirAll(filepath.Join(dir, "nodes", "pve01", "qemu-server"), 0o755))
	must(os.MkdirAll(filepath.Join(dir, "nodes", "pve01", "lxc"), 0o755))
	must(os.WriteFile(filepath.Join(dir, "storage.cfg"), []byte(storageCfg), 0o640))
	must(os.WriteFile(filepath.Join(dir, ".version"), []byte("1"), 0o640))
	must(os.WriteFile(filepath.Join(dir, "nodes", "pve01", "qemu-server", "100.conf"), []byte("boot: order=scsi0\nname: web-01\nmemory: 2048\n\n[snap1]\nname: old\n"), 0o640))
	must(os.WriteFile(filepath.Join(dir, "nodes", "pve01", "lxc", "101.conf"), []byte("arch: amd64\nhostname: ct-db\n"), 0o640))
	must(os.Symlink("nodes/pve01/qemu-server", filepath.Join(dir, "qemu-server")))
	return dir
}

func TestGuestConfigs(t *testing.T) {
	guests := guestConfigs(fixturePVE(t))
	if len(guests) != 2 {
		t.Fatalf("guests %+v", guests)
	}
	if guests[0].VMID != 100 || guests[0].Type != "qemu" || guests[0].Name != "web-01" || guests[0].ConfigFile != "nodes/pve01/qemu-server/100.conf" {
		t.Errorf("qemu guest %+v", guests[0])
	}
	if guests[1].VMID != 101 || guests[1].Type != "lxc" || guests[1].Name != "ct-db" {
		t.Errorf("lxc guest %+v", guests[1])
	}
}

func TestCollect(t *testing.T) {
	pveDir := fixturePVE(t)
	dbFile := filepath.Join(t.TempDir(), "config.db")
	if err := os.WriteFile(dbFile, []byte("sqlite"), 0o600); err != nil {
		t.Fatal(err)
	}
	osRelease := filepath.Join(t.TempDir(), "os-release")
	_ = os.WriteFile(osRelease, []byte("PRETTY_NAME=\"Debian GNU/Linux 12 (bookworm)\"\n"), 0o644)
	mounts := filepath.Join(t.TempDir(), "mounts")
	_ = os.WriteFile(mounts, []byte("/dev/sda1 / ext4 rw 0 0\n"), 0o644)
	oldCfg, oldDB, oldOS, oldMounts := pveConfigDir, pveClusterDB, osReleasePath, procMountsPath
	pveConfigDir, pveClusterDB, osReleasePath, procMountsPath = pveDir, dbFile, osRelease, mounts
	t.Cleanup(func() { pveConfigDir, pveClusterDB, osReleasePath, procMountsPath = oldCfg, oldDB, oldOS, oldMounts })

	runner := &fakeRunner{outputs: map[string]string{
		"pveversion": "pve-manager/8.2.4/faa83925c9641325 (running kernel: 6.8.8-2-pve)\n",
		"dpkg-query": "pve-manager\t8.2.4\tinstalled\tamd64\nzfsutils-linux\t2.2\tinstalled\tamd64\n",
		"apt-mark":   "pve-manager\nzfsutils-linux\nvim\n",
		"pvesh":      "{}",
		"pvesm":      "Name Type Status\nlocal dir active\n",
		"lsblk":      `{"blockdevices":[{"name":"sda","path":"/dev/sda","size":100,"type":"disk","model":"WD"}]}`,
		"pvs":        "", "vgs": "", "lvs": "",
		"sgdisk": "",
		// no blkid: recorded as a failed collector; no zpool: the ZFS collectors are
		// skipped; no sqlite3: the plain copy path is taken
	}}
	dir := t.TempDir()
	inv := collect(context.Background(), runner, dir)

	if inv.Host.PVEVersion != "8.2.4" || inv.Host.PVEMajor != 8 || inv.Host.Kernel != "6.8.8-2-pve" || inv.Host.OS == "" {
		t.Errorf("host %+v", inv.Host)
	}
	if inv.Packages.Installed != 2 || inv.Packages.Manual != 3 {
		t.Errorf("packages %+v", inv.Packages)
	}
	if len(inv.Storages) != 3 || len(inv.Guests) != 2 {
		t.Errorf("storages %d guests %d", len(inv.Storages), len(inv.Guests))
	}
	if len(inv.Disks) != 1 || inv.Disks[0].PartitionTable == "" {
		t.Errorf("disks %+v", inv.Disks)
	}
	for _, f := range []string{"pveversion.txt", "packages.tsv", "packages-manual.txt", "pve/network.json", "pve/storage.json", "disks/lsblk.json", "disks/mounts.txt", "pve/etc-pve/storage.cfg", "pve/etc-pve/nodes/pve01/qemu-server/100.conf", "pve/config.db", inv.Disks[0].PartitionTable} {
		if _, err := os.Stat(filepath.Join(dir, f)); err != nil {
			t.Errorf("collected file %s missing: %v", f, err)
		}
	}
	if link, err := os.Readlink(filepath.Join(dir, "pve/etc-pve/qemu-server")); err != nil || link != "nodes/pve01/qemu-server" {
		t.Errorf("symlink not preserved: %q %v", link, err)
	}
	// config.db without sqlite3 is a plain copy with a warning
	warned := false
	for _, w := range inv.Warnings {
		if strings.Contains(w, "sqlite3") {
			warned = true
		}
	}
	if !warned {
		t.Errorf("expected the plain-copy warning, got %v", inv.Warnings)
	}
	// a missing tool is recorded as a failed collector (and a warning), never fatal;
	// the ZFS collectors are skipped entirely when zpool is absent
	var blkid, pvever *pvespec.Collected
	for i := range inv.Records {
		switch inv.Records[i].Name {
		case "blkid":
			blkid = &inv.Records[i]
		case "pveversion":
			pvever = &inv.Records[i]
		case "zpool-status":
			t.Error("ZFS collectors must be skipped without zpool")
		}
	}
	if blkid == nil || blkid.Error == "" || blkid.File != "" {
		t.Errorf("blkid record %+v", blkid)
	}
	if pvever == nil || pvever.Error != "" || pvever.File != "pveversion.txt" {
		t.Errorf("pveversion record %+v", pvever)
	}
}

func TestRestoreScript(t *testing.T) {
	m := &pvespec.Manifest{
		Host:     pvespec.HostInfo{Hostname: "pve01.example.com", Node: "pve01", PVEVersion: "8.2.4", PVEMajor: 8, Kernel: "6.8"},
		Snapshot: pvespec.ManifestSnapshot{Type: "host", ID: "pve01-pve", Time: time.Date(2026, 9, 11, 2, 0, 0, 0, time.UTC)},
		Packages: pvespec.PackageInfo{Installed: 900, Manual: 40},
		Entries: []pvespec.ArchiveEntry{
			{Name: "etc", Source: "/etc", Kind: "etc"}, {Name: "collect", Source: "/spool/collect", Kind: "collect"},
			{Name: "vz", Source: "/var/lib/vz", Kind: "data"},
		},
		FinishedAt: time.Now(),
	}
	script := restoreScript(m, "prod")
	for _, want := range []string{
		"#!/usr/bin/env bash", "set -euo pipefail",
		`SNAPSHOT="host/pve01-pve/2026-09-11T02:00:00Z"`, `PBS_NS="prod"`,
		"proxmox-backup-client restore", "apt-get install -y", "systemctl stop pve-cluster",
		"/var/lib/pve-cluster/config.db", "pmxcfs -l", `"network/interfaces"`, `"ssh/ssh_host_ed25519_key"`,
		"pvesh get /version", `rsync -aHAX --numeric-ids "$RESTORE_DIR/vz/" "/var/lib/vz/"`, "--dry-run",
		`"/etc/pve/nodes/pve01/."`,
	} {
		if !strings.Contains(script, want) {
			t.Errorf("script lacks %q", want)
		}
	}
	cmds := restoreCommands(m, "prod")
	if len(cmds) < 5 || !strings.Contains(strings.Join(cmds, "\n"), "restore host/pve01-pve/2026-09-11T02:00:00Z pve.pxar /var/tmp/fallbck-pve-restore --ns prod") {
		t.Errorf("commands %v", cmds)
	}
}
