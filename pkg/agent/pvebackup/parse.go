package pvebackup

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	pvespec "github.com/osshield/fallbck/pkg/pvebackup"
)

// parseStorageCfg reads /etc/pve/storage.cfg: blocks start with "<type>: <id>" and
// continue with indented "<key> <value>" lines
func parseStorageCfg(data string) []pvespec.Storage {
	var out []pvespec.Storage
	var cur *pvespec.Storage
	for _, line := range strings.Split(data, "\n") {
		if strings.TrimSpace(line) == "" || strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue
		}
		if !strings.HasPrefix(line, " ") && !strings.HasPrefix(line, "\t") {
			typ, id, ok := strings.Cut(line, ":")
			if !ok {
				continue
			}
			out = append(out, pvespec.Storage{ID: strings.TrimSpace(id), Type: strings.TrimSpace(typ)})
			cur = &out[len(out)-1]
			continue
		}
		if cur == nil {
			continue
		}
		key, value, _ := strings.Cut(strings.TrimSpace(line), " ")
		value = strings.TrimSpace(value)
		switch key {
		case "path":
			cur.Path = value
		case "pool":
			cur.Pool = value
		case "server":
			cur.Server = value
		case "export":
			cur.Export = value
		case "content":
			cur.Content = strings.Split(value, ",")
		case "shared":
			cur.Shared = value == "1"
		case "disable":
			cur.Disabled = value == "1"
		}
	}
	return out
}

// guestConfigs lists the VM/CT configurations under a /etc/pve copy (every node dir)
func guestConfigs(pveDir string) []pvespec.Guest {
	var guests []pvespec.Guest
	nodes, _ := filepath.Glob(filepath.Join(pveDir, "nodes", "*"))
	for _, node := range nodes {
		for _, kind := range []struct{ dir, typ, nameKey string }{{"qemu-server", "qemu", "name"}, {"lxc", "lxc", "hostname"}} {
			confs, _ := filepath.Glob(filepath.Join(node, kind.dir, "*.conf"))
			for _, conf := range confs {
				vmid, err := strconv.Atoi(strings.TrimSuffix(filepath.Base(conf), ".conf"))
				if err != nil {
					continue
				}
				rel, _ := filepath.Rel(pveDir, conf)
				g := pvespec.Guest{VMID: vmid, Type: kind.typ, ConfigFile: filepath.ToSlash(rel)}
				if f, err := os.Open(conf); err == nil {
					sc := bufio.NewScanner(f)
					for sc.Scan() {
						line := sc.Text()
						if strings.HasPrefix(line, "[") { // snapshot sections follow the current config
							break
						}
						if v, ok := strings.CutPrefix(line, kind.nameKey+":"); ok {
							g.Name = strings.TrimSpace(v)
							break
						}
					}
					f.Close()
				}
				guests = append(guests, g)
			}
		}
	}
	sort.Slice(guests, func(i, j int) bool { return guests[i].VMID < guests[j].VMID })
	return guests
}

// parseOSRelease returns PRETTY_NAME from /etc/os-release content
func parseOSRelease(data string) string {
	for _, line := range strings.Split(data, "\n") {
		if v, ok := strings.CutPrefix(line, "PRETTY_NAME="); ok {
			return strings.Trim(strings.TrimSpace(v), `"`)
		}
	}
	return ""
}

// parsePVEVersion extracts the pve-manager version from "pveversion -v" output
// (first line: pve-manager/8.2.4/faa83925c9641325 (running kernel: 6.8.8-2-pve))
func parsePVEVersion(data string) (version string, major int, kernel string) {
	for _, line := range strings.Split(data, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "pve-manager/") {
			continue
		}
		parts := strings.Split(line, "/")
		if len(parts) >= 2 {
			version = strings.Fields(parts[1])[0]
			if maj, _, ok := strings.Cut(version, "."); ok {
				major, _ = strconv.Atoi(maj)
			}
		}
		if i := strings.Index(line, "running kernel:"); i >= 0 {
			kernel = strings.TrimSuffix(strings.TrimSpace(line[i+len("running kernel:"):]), ")")
		}
		return
	}
	return
}

// countPackages counts installed packages in dpkg-query output
// (<package>\t<version>\t<status>\t<arch> per line)
func countPackages(data string) int {
	n := 0
	for _, line := range strings.Split(data, "\n") {
		f := strings.Split(line, "\t")
		if len(f) >= 3 && f[2] == "installed" {
			n++
		}
	}
	return n
}

func countLines(data string) int {
	n := 0
	for _, line := range strings.Split(data, "\n") {
		if strings.TrimSpace(line) != "" {
			n++
		}
	}
	return n
}

// lsblkDevice mirrors the fields requested from lsblk -J
type lsblkDevice struct {
	Name     string        `json:"name"`
	Path     string        `json:"path"`
	Size     int64         `json:"size"`
	Type     string        `json:"type"`
	Model    string        `json:"model"`
	Serial   string        `json:"serial"`
	Children []lsblkDevice `json:"children"`
}

// parseLsblk returns the whole disks from lsblk -J -b output
func parseLsblk(data []byte) []pvespec.Disk {
	var doc struct {
		Devices []lsblkDevice `json:"blockdevices"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil
	}
	var disks []pvespec.Disk
	for _, d := range doc.Devices {
		if d.Type != "disk" {
			continue
		}
		path := d.Path
		if path == "" {
			path = "/dev/" + d.Name
		}
		disks = append(disks, pvespec.Disk{Path: path, Model: strings.TrimSpace(d.Model), Serial: strings.TrimSpace(d.Serial), SizeBytes: d.Size})
	}
	return disks
}
