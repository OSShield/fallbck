package pvebackup

import (
	"cmp"
	"fmt"
	"strings"

	pvespec "github.com/osshield/fallbck/pkg/pvebackup"
)

// etcRestoreList is what the script restores from the archived /etc onto a fresh
// install: identity, network, package sources, SSH host keys, scheduled tasks and the
// PVE-related system configuration. Everything else stays available under the
// restore directory for manual inspection.
var etcRestoreList = []string{
	"hostname", "hosts", "mailname", "resolv.conf", "timezone", "localtime",
	"network/interfaces", "network/interfaces.d", "network/if-up.d", "network/if-down.d",
	"apt/sources.list", "apt/sources.list.d", "apt/apt.conf.d", "apt/auth.conf.d",
	"ssh/ssh_host_ecdsa_key", "ssh/ssh_host_ecdsa_key.pub", "ssh/ssh_host_ed25519_key", "ssh/ssh_host_ed25519_key.pub",
	"ssh/ssh_host_rsa_key", "ssh/ssh_host_rsa_key.pub", "ssh/sshd_config", "ssh/sshd_config.d",
	"cron.d", "crontab", "cron.daily", "cron.hourly", "cron.weekly", "cron.monthly",
	"default/pveproxy", "default/grub", "default/grub.d", "kernel/cmdline",
	"modprobe.d", "modules-load.d", "sysctl.conf", "sysctl.d", "udev/rules.d",
	"vzdump.conf", "pve-firewall.conf", "multipath.conf", "multipath", "iscsi", "lvm/lvm.conf",
	"zfs", "smartd.conf", "chrony/chrony.conf", "ntp.conf", "postfix/main.cf", "aliases",
	"fstab",
}

// dataRestoreHint names the flag that restores data entries
const dataRestoreHint = "--data"

// restoreCommands is the short runbook shown in the UI
func restoreCommands(m *pvespec.Manifest, namespace string) []string {
	snapshot := fmt.Sprintf("%s/%s/%s", m.Snapshot.Type, m.Snapshot.ID, m.Snapshot.Time.UTC().Format("2006-01-02T15:04:05Z"))
	ns := ""
	if namespace != "" {
		ns = " --ns " + namespace
	}
	return []string{
		fmt.Sprintf("# 1. Install Proxmox VE %s on the new host, then fetch the archive with PBS credentials", pveMajorString(m)),
		"#    (fallbck-ctl targets credentials <target> prints these exports):",
		"export PBS_REPOSITORY='<token id>@<pbs host>:<datastore>' PBS_PASSWORD='<token secret>' PBS_FINGERPRINT='<sha256 fingerprint>'",
		fmt.Sprintf("proxmox-backup-client restore %s %s.pxar /var/tmp/fallbck-pve-restore%s", snapshot, pvespec.ArchiveName, ns),
		"# 2. Review, then run the generated restore script (dry run first):",
		fmt.Sprintf("bash /var/tmp/fallbck-pve-restore/%s/%s --dry-run", pvespec.CollectEntry, pvespec.RestoreScriptName),
		fmt.Sprintf("bash /var/tmp/fallbck-pve-restore/%s/%s --yes            # add %s to also restore the data entries", pvespec.CollectEntry, pvespec.RestoreScriptName, dataRestoreHint),
	}
}

func pveMajorString(m *pvespec.Manifest) string {
	if m.Host.PVEMajor > 0 {
		return fmt.Sprintf("%d", m.Host.PVEMajor)
	}
	return "(same major as the backup)"
}

// restoreScript renders the bash runbook stored in collect/. It is deliberately
// plain and interactive: every step prints what it does, --dry-run only prints,
// --yes skips the confirmations.
func restoreScript(m *pvespec.Manifest, namespace string) string {
	var b strings.Builder
	w := func(format string, args ...any) { fmt.Fprintf(&b, format+"\n", args...) }
	snapshot := fmt.Sprintf("%s/%s/%s", m.Snapshot.Type, m.Snapshot.ID, m.Snapshot.Time.UTC().Format("2006-01-02T15:04:05Z"))

	w("#!/usr/bin/env bash")
	w("# fallbck Proxmox VE host restore runbook")
	w("# Generated %s for %s (pve-manager %s, kernel %s)", m.FinishedAt.UTC().Format("2006-01-02 15:04 UTC"), m.Host.Hostname, cmp.Or(m.Host.PVEVersion, "-"), cmp.Or(m.Host.Kernel, "-"))
	w("# Snapshot: %s   Archive: %s.pxar", snapshot, pvespec.ArchiveName)
	w("#")
	w("# Run on a FRESH Proxmox VE %s install as root. Steps:", pveMajorString(m))
	w("#   1. fetch the archive (needs PBS_REPOSITORY / PBS_PASSWORD / PBS_FINGERPRINT unless RESTORE_DIR is already populated)")
	w("#   2. reinstall the manually selected packages (never downgrades)")
	w("#   3. restore the cluster configuration (/etc/pve) from config.db, or file by file")
	w("#   4. restore selected /etc files (identity, network, apt, ssh host keys, cron, PVE settings)")
	w("#   5. restart the PVE services and verify")
	w("#   6. with %s: restore the data entries to their original paths", dataRestoreHint)
	w("set -euo pipefail")
	w("")
	w("SNAPSHOT=%q", snapshot)
	w("ARCHIVE=%q", pvespec.ArchiveName+".pxar")
	w("PBS_NS=%q", namespace)
	w("RESTORE_DIR=\"${RESTORE_DIR:-/var/tmp/fallbck-pve-restore}\"")
	w("COLLECT=\"$RESTORE_DIR/%s\"", pvespec.CollectEntry)
	w("YES=0; DRY=0; DATA=0")
	w("for arg in \"$@\"; do case \"$arg\" in --yes) YES=1;; --dry-run) DRY=1;; %s) DATA=1;; *) echo \"usage: $0 [--dry-run] [--yes] [%s]\"; exit 2;; esac; done", dataRestoreHint, dataRestoreHint)
	w("")
	w("log()  { printf '\\n==> %%s\\n' \"$*\"; }")
	w("run()  { if [ \"$DRY\" = 1 ]; then printf '    [dry-run] %%s\\n' \"$*\"; else printf '    %%s\\n' \"$*\"; \"$@\"; fi; }")
	w("ask()  { [ \"$YES\" = 1 ] || [ \"$DRY\" = 1 ] && return 0; read -r -p \"    $1 [y/N] \" a; [ \"$a\" = y ] || [ \"$a\" = Y ]; }")
	w("")
	w("[ \"$(id -u)\" = 0 ] || { echo 'run as root'; exit 1; }")
	w("command -v pveversion >/dev/null || { echo 'this is not a Proxmox VE host (pveversion missing)'; exit 1; }")
	w("CUR_MAJOR=$(pveversion | sed -n 's#^pve-manager/\\([0-9]*\\).*#\\1#p')")
	if m.Host.PVEMajor > 0 {
		w("if [ \"$CUR_MAJOR\" != %q ]; then echo \"WARNING: backup is from PVE %d, this host runs PVE $CUR_MAJOR\"; ask 'continue anyway?' || exit 1; fi", fmt.Sprintf("%d", m.Host.PVEMajor), m.Host.PVEMajor)
	}
	w("")
	w("log \"1/6 archive\"")
	w("if [ ! -d \"$COLLECT\" ]; then")
	w("  : \"${PBS_REPOSITORY:?set PBS_REPOSITORY (token id@host:datastore), PBS_PASSWORD and PBS_FINGERPRINT, or populate $RESTORE_DIR yourself}\"")
	w("  NSARG=(); [ -n \"$PBS_NS\" ] && NSARG=(--ns \"$PBS_NS\")")
	w("  run proxmox-backup-client restore \"$SNAPSHOT\" \"$ARCHIVE\" \"$RESTORE_DIR\" \"${NSARG[@]}\"")
	w("fi")
	w("[ \"$DRY\" = 1 ] || [ -f \"$COLLECT/%s\" ] || { echo \"manifest not found under $COLLECT\"; exit 1; }", pvespec.ManifestFileName)
	w("")
	w("log \"2/6 packages (%d manually selected; existing newer versions are kept)\"", m.Packages.Manual)
	w("if [ -f \"$COLLECT/packages-manual.txt\" ] && ask 'reinstall the package set?'; then")
	w("  run apt-get update")
	w("  PKGS=()")
	w("  while read -r p; do [ -n \"$p\" ] || continue; dpkg-query -W -f='${db:Status-Status}' \"$p\" 2>/dev/null | grep -q installed || PKGS+=(\"$p\"); done < \"$COLLECT/packages-manual.txt\"")
	w("  [ \"${#PKGS[@]}\" = 0 ] && echo '    nothing to install' || run env DEBIAN_FRONTEND=noninteractive apt-get install -y \"${PKGS[@]}\"")
	w("fi")
	w("")
	w("log \"3/6 cluster configuration (/etc/pve)\"")
	w("if ask 'stop the PVE services and restore /etc/pve?'; then")
	w("  run systemctl stop pvedaemon pveproxy pvestatd pve-ha-lrm pve-ha-crm 2>/dev/null || true")
	w("  run systemctl stop pve-cluster")
	w("  if [ -f \"$COLLECT/pve/config.db\" ]; then")
	w("    run cp -a /var/lib/pve-cluster/config.db \"/var/lib/pve-cluster/config.db.pre-restore.$(date +%%s)\" 2>/dev/null || true")
	w("    run install -m 0600 \"$COLLECT/pve/config.db\" /var/lib/pve-cluster/config.db")
	w("    run rm -f /var/lib/pve-cluster/config.db-wal /var/lib/pve-cluster/config.db-shm")
	w("  else")
	w("    # no database copy: start pmxcfs in local mode and copy the files in")
	w("    run pmxcfs -l")
	w("    run cp -a \"$COLLECT/pve/etc-pve/.\" /etc/pve/")
	w("    run killall pmxcfs; sleep 2")
	w("  fi")
	w("  run systemctl start pve-cluster")
	w("  sleep 3")
	w("  NODE=$(hostname -s)")
	if m.Host.Node != "" {
		w("  if [ \"$NODE\" != %q ] && [ ! -d \"/etc/pve/nodes/$NODE\" ]; then", m.Host.Node)
		w("    echo \"    NOTE: this host is $NODE, the backup came from %s; copying the node directory so guests appear here\"", m.Host.Node)
		w("    run cp -a \"/etc/pve/nodes/%s/.\" \"/etc/pve/nodes/$NODE/\" || true", m.Host.Node)
		w("  fi")
	}
	w("fi")
	w("")
	w("log \"4/6 system files from /etc\"")
	w("if ask 'restore the selected /etc files (hostname, network, apt, ssh host keys, cron, PVE settings)?'; then")
	w("  for f in \\")
	for _, f := range etcRestoreList {
		w("    %q \\", f)
	}
	w("  ; do")
	w("    src=\"$RESTORE_DIR/etc/$f\"; [ -e \"$src\" ] || continue")
	w("    run cp -a \"$src\" \"/etc/$(dirname \"$f\")/\"")
	w("  done")
	w("  echo '    the full archived /etc remains under '\"$RESTORE_DIR/etc\"' for anything else you need'")
	w("fi")
	w("")
	w("log \"5/6 services\"")
	w("run systemctl daemon-reload")
	w("run systemctl restart pve-cluster pvedaemon pveproxy pvestatd")
	w("run pvesh get /version")
	w("run pvesm status || true")
	w("[ \"$DRY\" = 1 ] || { echo; echo '    guests known to this node:'; ls /etc/pve/qemu-server /etc/pve/lxc 2>/dev/null || true; }")
	w("")
	var data []pvespec.ArchiveEntry
	for _, e := range m.Entries {
		if e.Kind == "data" {
			data = append(data, e)
		}
	}
	w("log \"6/6 data entries (%d)\"", len(data))
	if len(data) == 0 {
		w("echo '    none in this backup'")
	} else {
		w("if [ \"$DATA\" = 1 ]; then")
		for _, e := range data {
			w("  run mkdir -p %q && run rsync -aHAX --numeric-ids \"$RESTORE_DIR/%s/\" %q", e.Source, e.Name, e.Source+"/")
		}
		w("else")
		w("  echo \"    skipped; rerun with %s to restore:\"", dataRestoreHint)
		for _, e := range data {
			w("  echo \"      %s  ->  %s\"", e.Name, e.Source)
		}
		w("fi")
	}
	w("")
	w("log \"done\"")
	w("echo '    Review /etc/pve/storage.cfg (storages must exist before guests start), reboot to pick up kernel/network changes,'")
	w("echo '    then start the guests. Guest disks are restored separately (vzdump backups on PBS).'")
	return b.String()
}
