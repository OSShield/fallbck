// Package pvebackup runs Proxmox VE host backups from the filesystem agent: it
// collects the node's configuration and inventory into a spool directory, archives it
// together with /etc, /root and optional data paths, and generates a restore runbook.
package pvebackup

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	dbrun "github.com/osshield/fallbck/pkg/agent/dbbackup"
	pvespec "github.com/osshield/fallbck/pkg/pvebackup"
)

// Host locations (variables so tests can point them at fixtures)
var (
	pveConfigDir   = "/etc/pve"
	pveClusterDB   = "/var/lib/pve-cluster/config.db"
	osReleasePath  = "/etc/os-release"
	procMountsPath = "/proc/mounts"
)

// collectTimeout bounds one collector command
const collectTimeout = 2 * time.Minute

// collected is what the collectors gathered, feeding the manifest
type collected struct {
	Host     pvespec.HostInfo
	Packages pvespec.PackageInfo
	Storages []pvespec.Storage
	Guests   []pvespec.Guest
	Disks    []pvespec.Disk
	Records  []pvespec.Collected
	Warnings []string
}

// collector runs commands and records files under dir (the collect/ archive entry)
type collector struct {
	ctx    context.Context
	runner dbrun.Runner
	dir    string
	out    *collected
}

func (c *collector) record(name, command, file string, err error) {
	rec := pvespec.Collected{Name: name, Command: command, File: file}
	if err != nil {
		rec.Error = err.Error()
		rec.File = ""
		c.out.Warnings = append(c.out.Warnings, fmt.Sprintf("%s: %v", name, err))
		slog.Warn("PVE collector failed", "collector", name, "error", err)
	}
	c.out.Records = append(c.out.Records, rec)
}

// run executes a command and returns its stdout; the tool must be on PATH
func (c *collector) run(name string, args ...string) ([]byte, error) {
	path, err := c.runner.LookPath(name)
	if err != nil {
		return nil, fmt.Errorf("%s not found", name)
	}
	var out bytes.Buffer
	ctx, cancel := context.WithTimeout(c.ctx, collectTimeout)
	defer cancel()
	_, err = c.runner.Run(ctx, dbrun.Command{Name: name, Path: path, Args: args, Env: toolEnv(), Stdout: &out})
	if err != nil {
		return out.Bytes(), err
	}
	return out.Bytes(), nil
}

// capture runs a command and stores its output as a file in collect/
func (c *collector) capture(label, file string, name string, args ...string) []byte {
	out, err := c.run(name, args...)
	cmd := name + " " + strings.Join(args, " ")
	if err != nil {
		c.record(label, cmd, "", err)
		return nil
	}
	if werr := c.write(file, out); werr != nil {
		c.record(label, cmd, "", werr)
		return nil
	}
	c.record(label, cmd, file, nil)
	return out
}

func (c *collector) write(file string, data []byte) error {
	full := filepath.Join(c.dir, filepath.FromSlash(file))
	if err := os.MkdirAll(filepath.Dir(full), 0o700); err != nil {
		return err
	}
	return os.WriteFile(full, data, 0o600)
}

func toolEnv() []string {
	env := []string{"LANG=C", "LC_ALL=C", "TZ=UTC"}
	for _, k := range []string{"PATH", "HOME", "TMPDIR"} {
		if v := os.Getenv(k); v != "" {
			env = append(env, k+"="+v)
		}
	}
	if os.Getenv("PATH") == "" {
		env = append(env, "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin")
	}
	return env
}

// collect gathers the host inventory into dir. Every collector is best effort: a
// missing tool or a failing command becomes a warning in the manifest.
func collect(ctx context.Context, runner dbrun.Runner, dir string) *collected {
	out := &collected{}
	c := &collector{ctx: ctx, runner: runner, dir: dir, out: out}

	hostname, _ := os.Hostname()
	out.Host.Hostname = hostname
	out.Host.Node = strings.Split(hostname, ".")[0]
	if data, err := os.ReadFile(osReleasePath); err == nil {
		out.Host.OS = parseOSRelease(string(data))
	}

	if data := c.capture("pveversion", "pveversion.txt", "pveversion", "-v"); data != nil {
		out.Host.PVEVersion, out.Host.PVEMajor, out.Host.Kernel = parsePVEVersion(string(data))
	}
	if out.Host.Kernel == "" {
		if data, err := c.run("uname", "-r"); err == nil {
			out.Host.Kernel = strings.TrimSpace(string(data))
		}
	}

	// Packages: the full dpkg state and the manually selected set (what to reinstall)
	if data := c.capture("packages", "packages.tsv", "dpkg-query", "-W", "-f=${binary:Package}\t${Version}\t${db:Status-Status}\t${Architecture}\n"); data != nil {
		out.Packages.Installed = countPackages(string(data))
		out.Packages.ListFile = "packages.tsv"
	}
	if data := c.capture("packages-manual", "packages-manual.txt", "apt-mark", "showmanual"); data != nil {
		out.Packages.Manual = countLines(string(data))
		out.Packages.ManualFile = "packages-manual.txt"
	}

	// PVE inventory through the API (JSON), plus the human-readable storage status
	node := out.Host.Node
	c.capture("pve-node-status", "pve/node-status.json", "pvesh", "get", "/nodes/"+node+"/status", "--output-format", "json")
	c.capture("pve-network", "pve/network.json", "pvesh", "get", "/nodes/"+node+"/network", "--output-format", "json")
	c.capture("pve-storage", "pve/storage.json", "pvesh", "get", "/storage", "--output-format", "json")
	c.capture("pve-resources", "pve/resources.json", "pvesh", "get", "/cluster/resources", "--output-format", "json")
	c.capture("pvesm-status", "pve/pvesm-status.txt", "pvesm", "status")

	// Block devices, filesystems, LVM, ZFS
	if data := c.capture("lsblk", "disks/lsblk.json", "lsblk", "-J", "-b", "-o", "NAME,PATH,SIZE,TYPE,FSTYPE,MOUNTPOINT,MODEL,SERIAL,UUID,PARTUUID"); data != nil {
		out.Disks = parseLsblk(data)
	}
	c.capture("blkid", "disks/blkid.txt", "blkid")
	if data, err := os.ReadFile(procMountsPath); err == nil {
		c.record("mounts", "", "disks/mounts.txt", c.write("disks/mounts.txt", data))
	}
	c.capture("lvm-pvs", "disks/lvm-pvs.txt", "pvs", "--units", "b")
	c.capture("lvm-vgs", "disks/lvm-vgs.txt", "vgs", "--units", "b")
	c.capture("lvm-lvs", "disks/lvm-lvs.txt", "lvs", "--units", "b", "-o", "+devices")
	if _, err := runner.LookPath("zpool"); err == nil {
		c.capture("zpool-status", "disks/zpool-status.txt", "zpool", "status")
		c.capture("zpool-list", "disks/zpool-list.txt", "zpool", "list", "-v")
		c.capture("zfs-list", "disks/zfs-list.txt", "zfs", "list", "-o", "name,used,avail,refer,mountpoint,canmount")
		c.capture("zfs-props", "disks/zfs-props.txt", "zfs", "get", "-s", "local,received", "all")
	}
	// Partition tables: small and essential for rebuilding the same layout
	for i := range out.Disks {
		d := &out.Disks[i]
		file := "disks/partitions/" + strings.TrimPrefix(strings.ReplaceAll(d.Path, "/", "_"), "_") + ".sgdisk"
		full := filepath.Join(dir, filepath.FromSlash(file))
		if err := os.MkdirAll(filepath.Dir(full), 0o700); err != nil {
			c.record("partition-table "+d.Path, "", "", err)
			continue
		}
		if _, err := c.run("sgdisk", "--backup="+full, d.Path); err != nil {
			c.record("partition-table "+d.Path, "sgdisk --backup "+d.Path, "", err)
			continue
		}
		d.PartitionTable = file
		c.record("partition-table "+d.Path, "sgdisk --backup "+d.Path, file, nil)
	}

	// /etc/pve: the cluster filesystem is a FUSE mount with unusual semantics, so it is
	// copied file by file into collect/pve rather than archived in place
	pveCopy := filepath.Join(dir, "pve", "etc-pve")
	if err := copyTree(pveConfigDir, pveCopy); err != nil {
		c.record("etc-pve", "", "", fmt.Errorf("copying %s: %w", pveConfigDir, err))
	} else {
		c.record("etc-pve", "", "pve/etc-pve", nil)
		if data, err := os.ReadFile(filepath.Join(pveCopy, "storage.cfg")); err == nil {
			out.Storages = parseStorageCfg(string(data))
		}
		out.Guests = guestConfigs(pveCopy)
	}

	// The pmxcfs database behind /etc/pve: a consistent copy via sqlite3's online
	// backup when available, a plain copy otherwise (still fine for a quiescent node)
	if _, err := os.Stat(pveClusterDB); err == nil {
		target := filepath.Join(dir, "pve", "config.db")
		if sqlite, err := runner.LookPath("sqlite3"); err == nil {
			_ = os.MkdirAll(filepath.Dir(target), 0o700)
			cctx, cancel := context.WithTimeout(ctx, collectTimeout)
			_, err := runner.Run(cctx, dbrun.Command{Name: "sqlite3", Path: sqlite, Args: []string{pveClusterDB, ".backup " + target}, Env: toolEnv(), Stdout: io.Discard})
			cancel()
			c.record("config-db", "sqlite3 .backup", "pve/config.db", err)
		} else if err := copyFile(pveClusterDB, target); err != nil {
			c.record("config-db", "", "", err)
		} else {
			c.record("config-db", "cp (sqlite3 not installed; copy taken without a lock)", "pve/config.db", nil)
			out.Warnings = append(out.Warnings, "config.db was copied without sqlite3's online backup; install sqlite3 for a guaranteed-consistent copy")
		}
	}
	return out
}

// copyTree copies a directory recursively, keeping modes, mtimes and symlinks
func copyTree(src, dst string) error {
	return filepath.WalkDir(src, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(src, path)
		target := filepath.Join(dst, rel)
		info, err := d.Info()
		if err != nil {
			return err
		}
		switch {
		case d.IsDir():
			if err := os.MkdirAll(target, 0o700); err != nil {
				return err
			}
			return nil
		case info.Mode()&os.ModeSymlink != 0:
			link, err := os.Readlink(path)
			if err != nil {
				return err
			}
			return os.Symlink(link, target)
		case info.Mode().IsRegular():
			if err := copyFile(path, target); err != nil {
				return err
			}
			_ = os.Chmod(target, info.Mode().Perm())
			_ = os.Chtimes(target, info.ModTime(), info.ModTime())
			return nil
		}
		return nil
	})
}

func copyFile(src, dst string) error {
	if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
		return err
	}
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}
