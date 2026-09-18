# fallbck
Backup filesystems, databases, kubernetes and more.

FallBCK is a single-binary backup server (with an embedded [Temporal](https://temporal.io) engine and Web UI) plus lightweight agents. See [STRUCTURE.md](STRUCTURE.md) for the architecture.

## Quick start (local, no login)

```bash
cd deploy
docker compose up -d --build          # postgres + fallbck-server (admin auth disabled, --dev)
open http://localhost:8080            # Web UI; Temporal UI at http://localhost:8080/temporal/
```

Enroll an example agent container:

```bash
TOKEN=$(curl -s -X POST http://localhost:8080/api/v1/tokens -H 'Content-Type: application/json' -d '{"name":"compose-agent"}' | jq -r .raw_token)
FALLBCK_AGENT_ENROLLMENT_KEY=$TOKEN docker compose --profile agent up -d
```

## With single sign-on and TLS (like production)

```bash
cd deploy
docker compose -f docker-compose.yml -f compose.sso.yml up -d --build
open https://fallbck.localhost        # accept Caddy's local CA; sign in as admin@example.com / password
```

Caddy terminates TLS and forwards HTTP + gRPC to the server over h2c; dex is the OIDC provider. In production point `public_url` at your reverse proxy and configure `auth.oidc.*` for your identity provider (`deploy/server.yaml.example`, `deploy/caddy/Caddyfile.production.example`, `deploy/nginx.conf.example`).

## Agents

```bash
fallbck-agent enroll --server https://backup.example.com --token <enrollment token>
fallbck-agent run
```

Exclude patterns use `proxmox-backup-client --exclude` syntax (`*.tmp`, `/var/cache` anchored to the backup path, `**/node_modules`) and are recorded in the archive exactly as the official client records them; `.pxarexclude` files inside the tree are honoured too. A job with several paths matches patterns against archive-relative paths (so `/etc-mydir/...` for a root stored as `etc-mydir`).

A job with several paths produces one `root.pxar` archive with each path at the top level under its basename (`/etc` → `etc`); paths that share a basename are named after their full path instead (`/etc/mydir` → `etc-mydir`, `/var/lib/mydir` → `var-lib-mydir`). A single-path job archives that directory directly, named after it.

If the server (or the reverse proxy in front of it) uses a private or self-signed certificate, pass `--ca-cert <pem bundle>` (or, for testing only, `--insecure-skip-verify`) to `enroll`; the setting is used for the enrollment request itself and persisted in `agent.yaml` (`server_ca_cert_path` / `insecure_skip_verify`). The Kubernetes agent takes the same settings from the Helm values `server.caCert` / `server.insecureSkipVerify`.

With a **pxar v2** target the filesystem agent uses **metadata change detection** like `proxmox-backup-client --change-detection-mode metadata`: it keeps a copy of each upload's metadata stream under `<data_dir>/pxar-cache/`, validates it against the previous snapshot's index on PBS at the next run, and then skips reading files whose size and metadata (mode, owner, mtime, xattrs, ACLs) are unchanged, referencing the previous snapshot's chunks instead. Runs of unchanged files are re-read only when the boundary chunks would carry more than 10 % of unrelated bytes. The run detail page shows how many files were reused. A missing or stale cache (first run, pruned snapshot, different agent) simply means a full read.

The agent needs exactly one endpoint: the server's public URL. It receives a bearer token at enrollment, polls its own Temporal task queue through the server's gateway, and streams backups into PBS through a session the server opens on its behalf (the agent never holds PBS credentials). A job can instead be set to **direct PBS access** (server-side job option `direct_pbs`): the agent then fetches the target's connection details and API token for that run and talks to PBS itself — useful when the agent has a better path to PBS than the server does.

### Windows agent

`fallbck-agent` also runs on **Windows** (x64 and arm64) as a Windows service. Install with the MSI from the release page. Run interactively (double-click), it asks for the server URL and the enrollment key (plus an optional CA bundle) and enrolls the agent before starting the service. Unattended, pass them as properties or use the PowerShell one-liner the Agents page's guided installation (*Files* then *Windows*) prints:

```powershell
& ([scriptblock]::Create((iwr -useb https://backup.example.com/install-agent.ps1).Content)) -Token <enrollment token>
# or by hand: msiexec /i fallbck-agent_Windows_x86_64.msi /qn SERVER_URL=https://backup.example.com TOKEN=<token>
```

The service runs as LocalSystem, keeps its state (`agent.yaml`, caches, logs) in `%%ProgramData%%\fallbck\agent`, and can also be managed with `fallbck-agent.exe service install|uninstall|start|stop|status` after a manual `enroll`. Backup paths are Windows paths (`C:\Users`, `D:\data`, or a whole volume `C:\`); the archive names them `C`, `D-data`, … Every run first takes a **Volume Shadow Copy** of each volume involved (set `vss: false` in `agent.yaml` or `FALLBCK_AGENT_VSS=false` to read the live filesystem instead), so open and locked files are read consistently; leftover shadow copies are removed at the next agent start. The archive records file types, sizes, modification times, hardlinks and symlinks/junctions with synthesised POSIX modes (read-only files become 0444); NTFS ACLs and alternate data streams are not included yet. Metadata change detection works on Windows as on Linux.

### Database backups

`fallbck-agent` backs up **PostgreSQL** (`pg_dump` per database + `pg_dumpall --globals-only`, and/or `pg_basebackup` with streamed WAL), **MySQL/MariaDB** (`mysqldump`/`mariadb-dump --single-transaction` with the binlog position, one `--all-databases` file or one file per database, optionally the binary logs written since the previous run) and **MongoDB** (`mongodump --oplog`, restorable with `--oplogReplay`) on every host where the vendor client tools are installed. The agent detects the tools at start and every ten minutes and reports them with its heartbeat (`db_tools`, shown as a *DB tools* badge on the Agents page); database jobs can then be assigned to it. Nothing else changes: same enrollment, same service, same data directory as the filesystem backups.

```bash
apt install fallbck-agent postgresql-client mariadb-client   # or the tools for the engines you back up
fallbck-agent tools      # shows the detected client tools (pg_dump, mariadb-dump, mongodump, ...)
```

The standalone `fallbck-db-agent` (agent type `database`, running as the unprivileged user `fallbck`) is **deprecated** but keeps working: the server still accepts it and its package is still built. To retire one, install the client tools next to `fallbck-agent` on the host, wait for its heartbeat, then run `fallbck-agent migrate-db-agent` (copies the WAL/binlog chain state and the credential profiles from `/var/lib/fallbck/db-agent` into the agent's data directory) and `fallbck-ctl agents merge <db-agent> --into <agent>` (moves the jobs and run history, deletes the old agent record); finally stop and remove the `fallbck-db-agent` package. Dumps then run as root; PostgreSQL profiles that relied on unix-socket peer authentication as `fallbck` need a password or a peer mapping for root. Because the agent runs as root, credential profiles in `agent.yaml` are readable by root only.

Database jobs are created in the Web UI (job type *Database*: engine, host, user, databases, TLS and engine options) and can be assigned to any agent that reports the client tools, or to a Kubernetes agent. The password is either stored on the server — handed to the agent per run over the agent's authenticated API, never through Temporal — or left blank, in which case the agent resolves it from a named **credential profile** in `db_backup.profiles` of its `agent.yaml` (`deploy/db-agent.yaml.example`; in containers `FALLBCK_AGENT_DB_PROFILE_<NAME>_PASSWORD`). Each run dumps into `<data_dir>/spool/<run>/` (the spool needs room for the largest dump; runs refuse to start below `db_backup.min_free_bytes`), uploads the directory as `db.pxar` together with a `fallbck-db.json.blob` manifest (tool and server versions, files and checksums, WAL range / binlog position and files / oplog, ready-to-run restore commands) and deletes the spool. Snapshots use the PBS group `host/db-<engine>-<host>` (override per job with *backup group id*), so they are pruned independently of the host's filesystem backups.

Restore: `proxmox-backup-client restore <snapshot> db.pxar <dir>` (or download the manifest blob first) and follow `restore.commands` in `fallbck-db.json`. The `oci.fi/fallbck/agent:tools` image (target `tools` of `Dockerfile.agent`) ships the client tools; the Linux packages rely on the distribution's `postgresql-client`, `mariadb-client`/`mysql-client` (binary-log fetching additionally needs `mysqlbinlog`/`mariadb-binlog`, which Alpine only ships in the `mariadb` package) and `mongodb-database-tools`. `pg_dump` must be at least as new as the server; the agent looks in the usual per-version directories (`/usr/lib/postgresql/*/bin`, `/usr/pgsql-*/bin`, `/usr/libexec/postgresql*`) or `db_backup.tools.postgres_bindir`.

### Kubernetes agent

`fallbck-k8s-agent` runs **inside** the target cluster (agent type `kubernetes`, one identity per install) and backs up **all API resources** plus **PVC data**: with CSI snapshots it takes a `VolumeSnapshot`, clones it to a temporary PVC and uploads the files; without snapshot support it mounts the live volume read-only (crash-consistent). Install with the Helm chart:

```bash
helm install fallbck-k8s-agent deploy/helm/fallbck-k8s-agent \
  --namespace fallbck --create-namespace \
  --set server.url=https://backup.example.com \
  --set clusterName=prod \
  --set enrollment.key=<enrollment token>
```

The agent enrolls as `k8s-<clusterName>` and keeps its identity in a Secret (delete it to re-enroll; `helm upgrade` never touches it). Jobs are created in the **Kubernetes** section of the UI: namespace/label/resource selection, Secrets on or off, volume mode (all / labeled / none), storage-class filters, snapshot-class overrides, live-mount fallback, parallelism. Each run writes one PBS snapshot per volume (`host/k8s-<cluster>-pvc-<ns>-<name>`, uploaded in parallel by short-lived worker pods in the volume's namespace) plus a resources snapshot `host/k8s-<cluster>` carrying every selected object as YAML and a `k8s-manifest.blob` (plan, per-volume outcomes, restore commands). Retention prunes every group the cluster writes — including groups of PVCs that no longer exist — and can optionally forget orphaned groups after N days.

**Databases inside the cluster** are backed up by the same agent: create a job of type *Database* on the Backup Jobs page and assign it to the `k8s-<cluster>` agent. Besides the usual engine settings it takes the Kubernetes target: the namespace, the Service to connect to (or an explicit host), optionally a Secret holding the password (and user), and an optional tools-image override. Each run spawns a dump pod in that namespace whose main container is the engine's own image (`postgres:<major>`, `mariadb:<major>` / `mysql:<major>`, `mongo:<major>`, templates in the chart's `worker.db.images`; the agent probes the server version to pick the tag, MongoDB uses `latest`) with the agent binary injected by an init container, so `pg_dump`/`mariadb-dump`/`mongodump` always match the server. The dump is spooled in an emptyDir (`worker.db.spoolSizeLimit`) and uploaded as `db.pxar` + `fallbck-db.json.blob` exactly like the native database agent; the binlog/WAL chain state is kept per job in the Secret `stateSecretName` in the agent namespace, so binlog and WAL continuation works across runs. Credential profiles and TLS certificate files are not available for in-cluster targets.

Notes: the ClusterRole reads all resources (Secrets included — that is what a DR backup is) and may create pods/PVCs/VolumeSnapshots cluster-wide, because workers must run in each volume's namespace; worker pods carry short-lived credentials (2h ticket, 6h token) in their pod spec and have no Kubernetes API access; annotate a PVC `fallbck.io/skip: "true"` to exclude it. Restore is manual: `proxmox-backup-client restore host/k8s-<cluster>/<time> resources.pxar ./out`, `kubectl apply` in the order described by the manifest, and per volume restore `pvc.pxar` from its group into a pod mounting the recreated PVC.

### Proxmox VE host backup

Install `fallbck-agent` on a Proxmox VE node (it reports itself as a PVE host with its next heartbeat) and create a job of type **Proxmox VE host** on the Backup Jobs page. Every run archives the node's configuration into one `pve.pxar` snapshot in the group `host/<hostname>-pve`: `/etc` (with `/etc/pve` copied out of the cluster filesystem and a consistent copy of `config.db`), `/root`, the installed and manually selected package lists, `pvesh` dumps of storage, network and node status, `pvesm status`, LVM/ZFS/blkid/lsblk inventories and the partition table of every disk (`sgdisk --backup`), plus the guest configurations parsed for the run detail page. Optional **data paths** (mounted data storages such as `/var/lib/vz`) are archived file by file; guest disk images under them (`images/`, `private/`, `subvol-*`) are excluded unless the job says otherwise, since vzdump to PBS already covers guests. Guest disks are never part of this backup.

Restore onto a **fresh install of the same PVE major**: fetch the archive with PBS's own client and run the generated runbook stored in the archive (`collect/fallbck-pve-restore.sh`, also summarised on the run detail page). `fallbck-ctl targets credentials <target>` prints the `PBS_REPOSITORY` / `PBS_PASSWORD` / `PBS_FINGERPRINT` exports the client needs (the call is logged on the server).

```bash
eval "$(fallbck-ctl targets credentials pbs-main)"
proxmox-backup-client restore host/pve01-pve/2026-09-11T02:00:00Z pve.pxar /var/tmp/fallbck-pve-restore
bash /var/tmp/fallbck-pve-restore/collect/fallbck-pve-restore.sh --dry-run
bash /var/tmp/fallbck-pve-restore/collect/fallbck-pve-restore.sh --yes            # --data also restores the data paths
```

The script reinstalls the manually selected packages (never downgrading), stops the PVE services, restores the cluster configuration from `config.db` (or file by file through `pmxcfs -l`), restores identity/network/apt/SSH host keys/cron/PVE settings from the archived `/etc`, restarts the services and verifies with `pvesh get /version`. Single nodes only; clusters are not supported.

### Docker host backup

Install `fallbck-agent` on a Docker host (as the OS package, running as root, or as the `oci.fi/fallbck/agent` container image run as root with the Docker socket mounted; the Agents page's guided installation, *Docker host*, prints both) and create a job of type **Docker host** on the Backup Jobs page once the agent has reported a reachable daemon with its heartbeat. Every run writes one `docker.pxar` snapshot into the group `host/<hostname>-docker` with a `collect` entry holding `docker inspect` of every container, network and volume, the compose config files named in the `com.docker.compose.*` labels (plus `.env`), `/etc/docker/daemon.json`, image references with digests (per job also `docker save` tarballs of locally built or all images), the manifest `fallbck-docker.json` and a generated restore runbook, plus one `vol-<name>` entry per named volume archived file by file and, when the job lists **additional host paths** (compose project directories, bind-mounted data), one `host-<path>` entry each (`/srv/app` → `host-srv-app`). Bind mounts are listed in the manifest but only archived when added as host paths; Swarm services, remote daemons and database dumps from inside containers are out of scope (use the database agent against a published port).

Volumes are copied live by default. Label a container `fallbck.io/pause=true` (or list it in the job) to `docker pause` it while the volumes it mounts are copied; label a container or volume `fallbck.io/skip=true` to leave it out. The agent reads volumes directly from `/var/lib/docker/volumes` when that directory is visible (package install, or the container with it mounted) and otherwise streams them through short-lived helper containers (`docker_backup.volume_access: auto|direct|helper`, `docker_backup.helper_image`, default `alpine:3.20`); paused and helper-read volumes are staged in the agent's spool directory first, so size it for the largest such volume. The daemon is reached on `DOCKER_HOST` (unix sockets only) or `/var/run/docker.sock` (`docker_backup.socket`).

Restore onto a host with Docker and the compose plugin: fetch the archive with PBS's own client and run the runbook stored in the archive (`collect/fallbck-docker-restore.sh`, also summarised on the run detail page):

```bash
export PBS_REPOSITORY=... PBS_PASSWORD=... PBS_FINGERPRINT=...   # fallbck-ctl targets credentials <target>
proxmox-backup-client restore host/dock01-docker/2026-09-17T02:00:00Z docker.pxar /var/tmp/fallbck-docker-restore
bash /var/tmp/fallbck-docker-restore/collect/fallbck-docker-restore.sh --dry-run
bash /var/tmp/fallbck-docker-restore/collect/fallbck-docker-restore.sh --yes   # --containers also recreates standalone containers
```

The script restores `daemon.json`, recreates user-defined networks and volumes, copies each `vol-<name>` back in with a helper container, loads saved images and pulls the rest by digest, puts the compose files back and runs `docker compose up -d` per project, and prints a best-effort `docker run` for every container that is not part of a compose project (executed only with `--containers`).

## Scheduling

A job with a cron expression gets a **Temporal Schedule** (managed by the server, visible under `/temporal/` → Schedules): standard 5-field cron plus `@daily` / `@every 6h`, evaluated in the **server's timezone** (`timezone:` in `server.yaml` or `FALLBCK_TIMEZONE`; auto-detected from `TZ`/the host zone, UTC when undetectable — set `TZ` on the Docker container). DST is handled by Temporal: `0 2 * * *` stays 02:00 local year round. A firing starts the same workflow as "Run Now"; a firing that lands while the previous run of the job is still going is **skipped**, and after server downtime one missed firing within the last hour is caught up. Disabling a job pauses its schedule; clearing the cron or deleting the job removes it. The server reconciles schedules with the jobs table at every start. The jobs page shows the next fire time.

## CLI

Create an API key in the Web UI (API Keys), then:

```bash
export FALLBCK_SERVER_URL=https://backup.example.com FALLBCK_API_KEY=fbk_...
fallbck-ctl token create --name web-01
fallbck-ctl agents list
fallbck-ctl agents merge db01 --into db01-fs     # retire a fallbck-db-agent into the combined agent (id, id prefix or hostname)
```

## Troubleshooting

Set `DEBUG=true` (or `FALLBCK_LOG_LEVEL=debug`) on the server or agent for verbose logs; agents also take `log_level: debug` in `agent.yaml`. For a running agent you can flip debug logging **from the web UI** (Agents page, "Debug" button) — it is delivered with the next heartbeat (~30s), applied live, and needs no restart.

Each run has a detailed status page at **/runs/<id>** that **updates live while the backup runs** (it polls every few seconds, showing the current phase and, for Kubernetes, a per-PVC table filling in as volumes finish, then switches to the finished view) (the **Details** button in the history list): timing and transfer stats, the full error, the agent log, and a type-specific section — per-archive sizes/chunks for filesystem backups, per-database entries and WAL/binlog/oplog info for database backups, and a per-PVC table plus resource counts and warnings for Kubernetes backups — with the raw details JSON downloadable. Every backup activity heartbeats its current phase every 15s; a run that fails records the phase it was in plus the agent's recent log lines (all levels, even without debug enabled) — open **Details** on the run in the history list. A "heartbeat timeout" now reports the last phase the agent was in before it went silent. On the server this shows every PBS session handshake — the upgrade request (datastore, snapshot, token id without the secret) and PBS's answer — plus the embedded Temporal's info logs. On the agent it shows tunnel setup and credential fetches.

PBS API tokens must be entered as `user@realm!tokenid:secret` (the `=` spelling from the PBS token dialog is accepted and normalised); the token needs `Datastore.Backup` on the datastore/namespace. A `401 authentication failed` from PBS means the token or secret is wrong; `403` means missing privileges.

## Linux packages

Releases ship `.deb`, `.rpm` and `.apk` packages for `fallbck-server`, `fallbck-agent` and `fallbck-db-agent` (built by [GoReleaser](.goreleaser.yml) from the `Release` GitHub Action on `v*` tags; every push to `main` and every PR produces a snapshot build as a workflow artifact).

| Package | Service | Config |
|---|---|---|
| `fallbck-server` | systemd `fallbck-server` (deb/rpm) / OpenRC `fallbck-server` (apk), runs as user `fallbck` | `/etc/fallbck/server.yaml`, secrets in `/etc/fallbck/server.env` |
| `fallbck-agent` | systemd `fallbck-agent` / OpenRC `fallbck-agent`, runs as root | `/etc/fallbck/agent.env` (optional self-enrollment), state in `/var/lib/fallbck/agent` |
| `fallbck-db-agent` | systemd `fallbck-db-agent` / OpenRC `fallbck-db-agent`, runs as user `fallbck` | `/etc/fallbck/db-agent.env`, credential profiles + spool in `/var/lib/fallbck/db-agent` (client tools from the distribution) |

```bash
# server
apt install ./fallbck_server_Linux_amd64.deb      # or rpm -i / apk add --allow-untrusted
$EDITOR /etc/fallbck/server.yaml /etc/fallbck/server.env
systemctl enable --now fallbck-server              # OpenRC: rc-update add fallbck-server default && rc-service fallbck-server start

# agent
apt install ./fallbck_agent_Linux_amd64.deb
fallbck-agent enroll --server https://backup.example.com --token <enrollment token>
systemctl enable --now fallbck-agent

# database agent
apt install ./fallbck_db_agent_Linux_amd64.deb postgresql-client mariadb-client
sudo -u fallbck fallbck-db-agent enroll --server https://backup.example.com --token <enrollment token> --data-dir /var/lib/fallbck/db-agent
systemctl enable --now fallbck-db-agent
```

Upgrading a package (`apt install ./…deb`, `rpm -U`, `apk add`) restarts the service if it is running, so the new binary takes effect immediately; a service that is stopped or not yet enrolled is left alone and the post-install hint is printed instead. Data, enrollment and configuration files are never touched by an upgrade. A running backup on that host is interrupted by the restart and retried by the server on its normal schedule.

Publishing to the package repositories needs the `PKG_UPLOAD_PASSWORD` repository secret (the `linux_push` user of `*.pkg.lv`).

## Development

```bash
go build ./... && go test ./...
go test -tags sqlite ./pkg/temporal/embedded/ ./pkg/integration/   # boots the real Temporal server in-process
```

`go.mod` currently `replace`s `github.com/osshield/gopbs` with a sibling checkout (`../gopbs-fallbck`, branch `fallbck-session-dialer`) that adds `pbs.Config.DialSession`; until that change is merged and tagged, Docker and CI builds need the replace pointed at a published version.

Requires Go 1.26+. The server binary is large (~175 MB) because it embeds the Temporal server and Web UI; the Dockerfiles use BuildKit cache mounts to keep rebuilds fast.
