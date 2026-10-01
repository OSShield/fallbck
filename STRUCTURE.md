# FallBCK
FallBCK is a backup solution designed to provide reliable, deduplicated and validated backups for your data.

## General structure
There is one central server binary, `fallbck-server`, backed by a PostgreSQL database. The server **embeds** the Temporal orchestration engine and the Temporal Web UI, so a deployment is just `fallbck-server` + PostgreSQL behind a TLS-terminating reverse proxy. An external Temporal cluster is still supported (`temporal.mode: external`).

The server is responsible for managing the backup jobs, storing the metadata, orchestrating backups through Temporal workflows, and providing a web UI and REST API for administrators.

There will be multiple types of agents that can be installed depending on the type of data to be backed up. The agents perform the backup operations and communicate with the backup target through a proxy on the server, so that not all clients need direct access to the backup target.

## Single public port
Everything is served on one plaintext HTTP/2 (h2c) port on the server, meant to sit behind a reverse proxy that terminates TLS (Caddy, Traefik, nginx — see `deploy/`):

| Path / protocol | Who | Authentication |
|---|---|---|
| `/`, `/dashboard`, … (Web UI), `/temporal/` (embedded Temporal UI) | administrators | OIDC login → session cookie |
| `/api/v1/*` | administrators, `fallbck-ctl`, automation | session cookie or API key (`Authorization: Bearer fbk_…`) |
| `POST /api/v1/agents/enroll` | new agents | one-time enrollment token |
| `POST /api/v1/agents/heartbeat`, `…/token/rotate` | agents | agent bearer token (JWT) |
| gRPC `fallbck.pbs.v1.BackupTunnel` | agents during a backup | agent bearer token + short-lived backup ticket (JWT) |
| gRPC (`Content-Type: application/grpc`) | agents (Temporal SDK workers) | agent bearer token, via the gateway |

## Agent gateway
Agents are Temporal activity workers, but they never reach Temporal directly. gRPC requests on the public port are routed to `pkg/gateway`, which authenticates the agent's bearer token, exposes only the handful of `WorkflowService` methods an activity-only worker needs (`GetSystemInfo`, `DescribeNamespace`, `PollActivityTaskQueue`, `RecordActivityTaskHeartbeat`, `RespondActivityTask*`, `ShutdownWorker`), pins polling to the agent's own task queue and namespace, and forwards the call to the Temporal frontend (embedded loopback or external). The gateway is the authorization boundary in both modes; the embedded Temporal services bind to `127.0.0.1` only.

## Authentication
* **Administrators** sign in through an OpenID Connect provider (`auth.oidc.*`); optional `allowed_groups` / `allowed_emails` restrict who may administer. Sessions are HS256 JWT cookies (`SameSite=Lax`, `HttpOnly`); state-changing requests from the browser must carry `X-Requested-With: fallbck`.
* **API keys** (`fbk_…`, hashed at rest) are created by a signed-in administrator for `fallbck-ctl` (`FALLBCK_API_KEY`) and automation.
* **Agents** receive a long-lived bearer token at enrollment; it is bound to the agent's task queue and a token version, checked against the database (revocation/deletion) with a 30 s cache, and rotated automatically by the agent before expiry.
* All server-issued JWTs share one secret but carry distinct audiences (`fallbck-session`, `fallbck-agent`, `fallbck-ticket`, `fallbck-login`).

## Web UI
A simple web UI with a light/dark theme choice, and functions for managing agents (along with guided instructions on installation and registration), enrollment tokens and API keys. The embedded Temporal Web UI is reachable under `/temporal/` for signed-in administrators.

## Backup targets
The primary backup target is Proxmox Backup Server, driven by the Proxmox Backup Server Go library [gopbs](https://github.com/osshield/gopbs) (pxar v1 and v2 archives; the format is chosen per target).

### How a backup reaches PBS
1. `PrepareBackupSession` (server) mints a **backup ticket**: a short-lived JWT naming the agent, target, datastore, namespace and the snapshot identity (`host/<hostname>/<time>`).
2. The agent opens a gRPC byte stream to the server's public port (`pkg/proxy`, service `fallbck.pbs.v1.BackupTunnel`) presenting its agent token and the ticket.
3. The server validates both, loads the target, connects to PBS with the target's **API token** (TLS chain verification or certificate fingerprint pin), performs the `proxmox-backup-protocol-v1` upgrade for exactly the snapshot named in the ticket, and pipes bytes between PBS and the agent.
4. The agent hands that stream to gopbs (`pbs.Config.DialSession`), which chunks, deduplicates and uploads the pxar archive, catalog and manifest, then finishes the snapshot.

Agents never see PBS credentials or choose the datastore/namespace/snapshot; the server does not parse the backup protocol, it only transports it.

Targets can encrypt client-side: the server keeps one key per target (sealed with its master key), `PrepareBackupSession` flags the session `encrypted`, the agent fetches the key with its ticket (`GET /api/v1/agents/encryption-key`) and gopbs encrypts chunks and blobs and signs the manifest (`pkg/agent/backup.Options.Crypt`); a session flagged encrypted refuses to run without a key. Keys are exported to administrators only as passphrase-protected key files (`POST /api/v1/targets/{id}/encryption/export`).

Database jobs (`job_type: database`, `db_config`) follow the same path with `fallbck-agent` (it reports `db_tools` when the vendor client tools are installed; agents of the retired type `database` still running the old standalone binary are accepted too): `PrepareBackupSession` names the group `host/db-<engine>-<host>` and passes the job spec with the password redacted; the agent fetches a server-stored password with its ticket (`GET /api/v1/agents/db-credentials`), uses a local credential profile, or, with neither configured and running as root on the database host, falls back to passwordless local authentication (PostgreSQL peer as the `postgres` OS user over the socket, MySQL/MariaDB `auth_socket` as root, MongoDB unauthenticated; `pkg/agent/dbbackup/local.go`), dumps with the vendor tools into a spool directory, and uploads it through the same tunnel/direct path as archive `db.pxar` plus a `fallbck-db.json.blob` manifest (versions, checksums, WAL/binlog/oplog positions, restore commands). Per job, an administrator can enable `direct_pbs`: the agent then obtains the target's endpoint, fingerprint and API token for that run (`GET /api/v1/agents/pbs-credentials`, agent token + backup ticket, only honoured for jobs with the flag) and connects to PBS directly with gopbs. Retention is a PBS datastore prune job; FallBCK never prunes or deletes on PBS. Restore is done with PBS's own tools (GUI / `proxmox-backup-client`) since the snapshots are standard pxar.

## Code map
| Package | Purpose |
|---|---|
| `cmd/fallbck-server` | server entry point: config, database, embedded Temporal, worker, gateway, UI, single h2c listener |
| `cmd/fallbck-agent` | agent: enrollment, activity worker through the gateway (filesystem, PVE, Docker and database activities), heartbeats with capability flags (`pve_host`, `docker_host`, `db_tools`), token rotation, `tools` and `migrate-db-agent` |
| `cmd/fallbck-ctl` | admin CLI (API key authenticated) |
| `pkg/auth` | JWT token manager, agent tokens + verifier, sessions, API keys, OIDC, HTTP middleware |
| `pkg/secrets` | server master key (AES-256-GCM sealer) protecting stored secrets at rest: PBS API tokens and per-target backup encryption keys (`target_keys`) |
| `pkg/pbs` | PBS helpers shared by server and agents: API token parsing, backup encryption keys (generate, fingerprint, export/import as `proxmox-backup-client` key files, RSA master public key validation) |
| `pkg/gateway` | authenticating, task-queue-scoped Temporal gRPC gateway for agents |
| `pkg/temporal/embedded` | in-process Temporal server (config, Postgres schema bootstrap, lifecycle) |
| `pkg/temporal/ui` | embedded Temporal Web UI (loopback ui-server, proxied under `/temporal/`) |
| `pkg/temporal` | SDK client helpers, server worker, workflows and activities |
| `pkg/temporal/scheduler` | Temporal Schedules for cron jobs (sync on job changes, reconcile at startup) |
| `pkg/api`, `web` | REST API and server-rendered Web UI (`/onboarding` guided agent + backup setup, the only place jobs are created; `/jobs` lists every job type with client-side filters and edits them; form fieldsets shared as `templates/partials/`) |
| `pkg/proxy` | PBS backup-session tunnel (gRPC byte stream, server-side protocol upgrade, TLS pinning); `pbstest` fake PBS for tests |
| `pkg/agent/runtime` | shared agent daemon skeleton (config + self-enrollment, gateway connections, worker, heartbeat/token rotation) |
| `pkg/agent/backup` | agent backup engine on top of gopbs (pxar upload, blobs) |
| `pkg/dbbackup` | database job spec, credential profiles, manifest (shared by server, agent and config) |
| `pkg/agent/credstore` | encrypted credential store on the agent host (AES-256-GCM, key file 0600, DPAPI-wrapped on Windows); `fallbck-agent database profile ...` manages it |
| `pkg/inventory` | what an agent reports about its host: the periodic summary (profile names, tools, disk, counts) and the on-demand detail (settings, containers, namespaces, PVE node), shared by agents and server |
| `pkg/agenthealth` | server-side alerts for the agent status page (stale heartbeat, version behind, low spool, jobs the agent cannot run, failed last runs) |
| `pkg/agent/dbbackup` | database engines (PostgreSQL, MySQL/MariaDB, MongoDB by their client tools; Microsoft SQL Server natively over the built-in driver with full/differential/log chains): tool detection, prechecks, dumps, spool, state |
| `cmd/fallbck-k8s-agent` | in-cluster Kubernetes agent (Helm-installed; `worker` mode uploads one volume, `db-worker` mode dumps one database on the engine image) |
| `pkg/k8sbackup` | kubernetes job spec, discovery plan, run manifest (shared) |
| `pkg/pvebackup` | Proxmox VE host job spec and run manifest (shared) |
| `pkg/agent/pvebackup` | PVE host collectors (/etc/pve copy, packages, storage/network/disks), restore runbook, run flow |
| `pkg/fsutil` | standard-library-only filesystem helpers shared by the agents and job specs: `CopyTree` / `CopyMissing` / `CopyFile` (modes, times, ownership, symlinks) and `FlattenPath` for archive entry names |
| `pkg/dockerbackup` | Docker host job spec, agent-side settings (socket, volume access), run manifest, daemon detection (shared) |
| `pkg/agent/dockerbackup` | Engine API client over the unix socket, definition/compose/image collectors, direct and helper-container volume reads, pause bracket, restore runbook, run flow |
| `pkg/agent/vss` | Windows Volume Shadow Copies for backup runs (no-op elsewhere) |
| `deploy/windows` | WiX source of the Windows MSI (service + enrollment on install) |
| `pkg/agent/k8sbackup` | resource dump, PVC snapshot/clone, worker pods, Secret identity, orphan sweep |
| `pkg/rundetail` | type-specific per-run detail blob (archives / databases / PVCs) stored on the run and rendered by the /runs/<id> page |
| `pkg/db` | pgx pool, versioned migrations, repositories |
| `pkg/integration` | end-to-end test: embedded Temporal + gateway + agent worker (`go test -tags sqlite`) |
