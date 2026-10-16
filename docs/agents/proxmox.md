# Proxmox VE hosts

This backs up the **node's config**, not your guests. vzdump to PBS already handles guests. This covers everything you'd otherwise rebuild by hand after a dead boot disk.

## Setup

Install `fallbck-agent` on the PVE node. On its next heartbeat it reports itself as a PVE host. Then create a **Proxmox VE host** job in onboarding.

## What's in the snapshot

Each run writes one `pve.pxar` into the group `host/<backup_id>-pve` (the job's `backup_id`, by default the agent ID; jobs from before 0.15 keep the hostname):

- `/etc`, with `/etc/pve` copied out of the cluster filesystem and a consistent copy of `config.db`
- `/root`
- installed and manually-selected package lists
- `pvesh` dumps of storage, network and node status, and `pvesm status`
- LVM / ZFS / blkid / lsblk inventories, and every disk's partition table (`sgdisk --backup`)
- guest configs, parsed for the run detail page

**Data paths** are optional: mounted storages like `/var/lib/vz`, archived file by file. Guest disk images under them (`images/`, `private/`, `subvol-*`) are skipped unless the job says otherwise. Guest disks are never part of this backup.

## Restore

Restore onto a **fresh install of the same PVE major version**. Pull the archive with PBS's client and run the generated runbook that's inside it:

```bash
eval "$(fallbck-ctl targets credentials pbs-main)"     # sets PBS_REPOSITORY / PBS_PASSWORD / PBS_FINGERPRINT
proxmox-backup-client restore host/pve01-pve/2026-09-11T02:00:00Z pve.pxar /var/tmp/fallbck-pve-restore
bash /var/tmp/fallbck-pve-restore/collect/fallbck-pve-restore.sh --dry-run
bash /var/tmp/fallbck-pve-restore/collect/fallbck-pve-restore.sh --yes    # add --data for the data paths too
```

The script:

1. reinstalls the manually selected packages (it never downgrades)
2. stops the PVE services
3. restores the cluster config from `config.db` (or file by file through `pmxcfs -l`)
4. restores identity, network, apt, SSH host keys, cron and PVE settings from the archived `/etc`
5. restarts everything and checks with `pvesh get /version`

The run detail page has a summary of the runbook too. `fallbck-ctl targets credentials` gets logged on the server, because it hands out the PBS token.

!!! warning
    Single nodes only. PVE clusters aren't supported.
