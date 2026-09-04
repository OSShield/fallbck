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

The agent needs exactly one endpoint: the server's public URL. It receives a bearer token at enrollment, polls its own Temporal task queue through the server's gateway, and streams backups into PBS through a session the server opens on its behalf (the agent never holds PBS credentials). A job can instead be set to **direct PBS access** (server-side job option `direct_pbs`): the agent then fetches the target's connection details and API token for that run and talks to PBS itself — useful when the agent has a better path to PBS than the server does.

### Database agent

`fallbck-db-agent` backs up **PostgreSQL** (`pg_dump` per database + `pg_dumpall --globals-only`, and/or `pg_basebackup` with streamed WAL), **MySQL/MariaDB** (`mysqldump`/`mariadb-dump --single-transaction` with the binlog position, optionally the binary logs written since the previous run) and **MongoDB** (`mongodump --oplog`, restorable with `--oplogReplay`). It enrolls like the filesystem agent but as agent type `database`, with its own data directory:

```bash
fallbck-db-agent enroll --server https://backup.example.com --token <enrollment token>
fallbck-db-agent tools      # shows the detected client tools (pg_dump, mariadb-dump, mongodump, ...)
fallbck-db-agent run
```

Database jobs are created in the Web UI (job type *Database*: engine, host, user, databases, TLS and engine options) and can only be assigned to database agents. The password is either stored on the server — handed to the agent per run over the agent's authenticated API, never through Temporal — or left blank, in which case the agent resolves it from a named **credential profile** in `db_backup.profiles` of its `agent.yaml` (`deploy/db-agent.yaml.example`; in containers `FALLBCK_AGENT_DB_PROFILE_<NAME>_PASSWORD`). Each run dumps into `<data_dir>/spool/<run>/` (the spool needs room for the largest dump; runs refuse to start below `db_backup.min_free_bytes`), uploads the directory as `db.pxar` together with a `fallbck-db.json.blob` manifest (tool and server versions, files and checksums, WAL range / binlog position and files / oplog, ready-to-run restore commands) and deletes the spool. Snapshots use the PBS group `host/db-<engine>-<host>` (override per job with *backup group id*), so they are pruned independently of the host's filesystem backups.

Restore: `proxmox-backup-client restore <snapshot> db.pxar <dir>` (or download the manifest blob first) and follow `restore.commands` in `fallbck-db.json`. The Docker image (`Dockerfile.db-agent`) ships the client tools; the Linux packages rely on the distribution's `postgresql-client`, `mariadb-client`/`mysql-client` (binary-log fetching additionally needs `mysqlbinlog`/`mariadb-binlog`, which Alpine only ships in the `mariadb` package) and `mongodb-database-tools`. `pg_dump` must be at least as new as the server; the agent looks in the usual per-version directories (`/usr/lib/postgresql/*/bin`, `/usr/pgsql-*/bin`, `/usr/libexec/postgresql*`) or `db_backup.tools.postgres_bindir`.

## Scheduling

A job with a cron expression gets a **Temporal Schedule** (managed by the server, visible under `/temporal/` → Schedules): standard 5-field cron plus `@daily` / `@every 6h`, evaluated in **UTC**. A firing starts the same workflow as "Run Now"; a firing that lands while the previous run of the job is still going is **skipped**, and after server downtime one missed firing within the last hour is caught up. Disabling a job pauses its schedule; clearing the cron or deleting the job removes it. The server reconciles schedules with the jobs table at every start. The jobs page shows the next fire time.

## CLI

Create an API key in the Web UI (API Keys), then:

```bash
export FALLBCK_SERVER_URL=https://backup.example.com FALLBCK_API_KEY=fbk_...
fallbck-ctl token create --name web-01
fallbck-ctl agents list
```

## Troubleshooting

Set `DEBUG=true` (or `FALLBCK_LOG_LEVEL=debug`) on the server or agent for verbose logs; agents also take `log_level: debug` in `agent.yaml`. For a running agent you can flip debug logging **from the web UI** (Agents page, "Debug" button) — it is delivered with the next heartbeat (~30s), applied live, and needs no restart.

Every backup activity heartbeats its current phase every 15s; a run that fails records the phase it was in plus the agent's recent log lines (all levels, even without debug enabled) — open **Details** on the run in the history list. A "heartbeat timeout" now reports the last phase the agent was in before it went silent. On the server this shows every PBS session handshake — the upgrade request (datastore, snapshot, token id without the secret) and PBS's answer — plus the embedded Temporal's info logs. On the agent it shows tunnel setup and credential fetches.

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
sudo -u fallbck fallbck-db-agent enroll --server https://backup.example.com --token <enrollment token>
systemctl enable --now fallbck-db-agent
```

Publishing to the package repositories needs the `PKG_UPLOAD_PASSWORD` repository secret (the `linux_push` user of `*.pkg.lv`).

## Development

```bash
go build ./... && go test ./...
go test -tags sqlite ./pkg/temporal/embedded/ ./pkg/integration/   # boots the real Temporal server in-process
```

`go.mod` currently `replace`s `github.com/osshield/gopbs` with a sibling checkout (`../gopbs-fallbck`, branch `fallbck-session-dialer`) that adds `pbs.Config.DialSession`; until that change is merged and tagged, Docker and CI builds need the replace pointed at a published version.

Requires Go 1.26+. The server binary is large (~175 MB) because it embeds the Temporal server and Web UI; the Dockerfiles use BuildKit cache mounts to keep rebuilds fast.
