# Architecture

How the pieces fit together, for when you need to know why something works the way it does.

## The big picture

There's one server binary, `fallbck-server`, with Postgres behind it. It **embeds** the Temporal server and the Temporal Web UI, so a deployment is just `fallbck-server` + Postgres + a TLS-terminating reverse proxy. You can still point it at an external Temporal cluster (`temporal.mode: external`) if you already run one.

The server keeps the jobs and metadata, drives backups as Temporal workflows, and serves the Web UI and REST API. Agents do the actual work. They reach PBS through a tunnel on the server, so your clients don't all need a route to the backup box.

## One port for everything

The server listens on a single plaintext HTTP/2 (h2c) port, meant for a reverse proxy that does TLS:

| Path / protocol | Who | Auth |
|---|---|---|
| `/`, `/dashboard`, … (Web UI), `/temporal/` | admins | OIDC login → session cookie |
| `/api/v1/*` | admins, `fallbck-ctl`, automation | session cookie or API key (`Bearer fbk_…`) |
| `POST /api/v1/agents/enroll` | new agents | one-time enrollment token |
| `POST /api/v1/agents/heartbeat`, `…/token/rotate` | agents | agent bearer token (JWT) |
| gRPC `fallbck.pbs.v1.BackupTunnel` | agents, mid-backup | agent token + short-lived backup ticket (JWT) |
| gRPC (`Content-Type: application/grpc`) | agents (Temporal workers) | agent token, via the gateway |

## The agent gateway

Agents are Temporal activity workers, but they never talk to Temporal directly. gRPC on the public port lands in `pkg/gateway`, which:

- checks the agent's bearer token,
- only allows the handful of `WorkflowService` calls an activity-only worker needs (`GetSystemInfo`, `DescribeNamespace`, `PollActivityTaskQueue`, `RecordActivityTaskHeartbeat`, `RespondActivityTask*`, `ShutdownWorker`),
- pins polling to the agent's own task queue and namespace,
- forwards to the Temporal frontend, embedded or external.

The gateway is the security boundary in both modes. Embedded Temporal only binds to `127.0.0.1`.

## Who authenticates how

- **Admins** sign in through OIDC (`auth.oidc.*`), optionally limited with `allowed_groups` / `allowed_emails`. Sessions are HS256 JWT cookies (`SameSite=Lax`, `HttpOnly`). State-changing browser requests need `X-Requested-With: fallbck`.
- **API keys** (`fbk_…`, hashed at rest) are made by a signed-in admin, for `fallbck-ctl` and automation.
- **Agents** get a long-lived bearer token at enrollment. It's bound to the agent's task queue and a token version, checked against the database for revocation (30s cache), and rotated by the agent before it expires.
- All server-issued JWTs share one secret but have different audiences (`fallbck-session`, `fallbck-agent`, `fallbck-ticket`, `fallbck-login`), so you can't swap one for another.

## How a backup gets to PBS

PBS is the target, driven by the [gopbs](https://github.com/osshield/gopbs) library (pxar v1 and v2, picked per target).

1. `PrepareBackupSession` on the server mints a **backup ticket**: a short-lived JWT naming the agent, target, datastore, namespace and snapshot (`host/<hostname>/<time>`).
2. The agent opens a gRPC byte stream to the server (`pkg/proxy`, `fallbck.pbs.v1.BackupTunnel`) with its agent token and the ticket.
3. The server checks both, loads the target, connects to PBS with the target's **API token** (TLS chain verification or fingerprint pin), does the `proxmox-backup-protocol-v1` upgrade for exactly the snapshot in the ticket, and pipes bytes both ways.
4. The agent hands the stream to gopbs (`pbs.Config.DialSession`), which chunks, dedups and uploads the pxar archive, catalog and manifest, then finishes the snapshot.

The agent never sees PBS credentials and can't pick the datastore, namespace or snapshot. The server doesn't parse the backup protocol, it just moves the bytes.

### Variations on that theme

- **Encryption.** One key per target, sealed with the master key. `PrepareBackupSession` flags the session `encrypted`, the agent fetches the key with its ticket (`GET /api/v1/agents/encryption-key`), and gopbs encrypts chunks and blobs and signs the manifest. An encrypted session won't run without a key. Admins only ever get keys out as passphrase-protected key files.
- **Databases.** Same path. The group becomes `host/db-<engine>-<host>`, and the job spec goes to the agent with the password redacted. The agent gets the password with its ticket (`GET /api/v1/agents/db-credentials`), from a local profile, or by passwordless local auth (`pkg/agent/dbbackup/local.go`). It dumps to a spool and uploads `db.pxar` plus `fallbck-db.json.blob`.
- **Direct PBS.** With `direct_pbs` on a job, the agent gets the target's endpoint, fingerprint and token for that run (`GET /api/v1/agents/pbs-credentials`, which needs agent token + ticket and is only allowed for flagged jobs) and connects to PBS itself.
- **Microsoft 365 and Kubernetes volumes.** Several snapshots per run. The agent mints a sub-ticket per unit (`POST /api/v1/agents/sub-ticket`). The sub-ticket's group has to extend the job's group, so an agent can't write outside its lane. M365 units are uploaded as caller-built virtual trees (`backup.Options.Tree`, gopbs `Archive.AddTree`), where unchanged items get reused without being fetched.

Retention is a PBS prune job. FallBCK never prunes or deletes on PBS. Restores use PBS's own tools, since the snapshots are standard pxar.

## Code map

| Package | What's in it |
|---|---|
| `cmd/fallbck-server` | Server entry point: config, DB, embedded Temporal, worker, gateway, UI, the h2c listener |
| `cmd/fallbck-agent` | The agent: enrollment, activity worker (files, PVE, Docker, M365, DB), heartbeats with capability flags, token rotation, self-update, `tools`, `migrate-db-agent` |
| `cmd/fallbck-k8s-agent` | In-cluster agent. `worker` mode uploads one volume, `db-worker` mode dumps one database on the engine image |
| `cmd/fallbck-ctl` | Admin CLI (API key auth) |
| `pkg/api`, `web` | REST API and server-rendered Web UI (`/onboarding` is the only place jobs get created; `/jobs` lists and edits them; shared form bits in `templates/partials/`) |
| `pkg/auth` | JWTs, agent tokens and verifier, sessions, API keys, OIDC, middleware |
| `pkg/secrets` | Master key (AES-256-GCM sealer) for PBS tokens and target keys at rest |
| `pkg/pbs` | PBS helpers: token parsing, encryption keys (generate, fingerprint, export/import as `proxmox-backup-client` key files, RSA master key checks) |
| `pkg/gateway` | The authenticating, queue-scoped Temporal gRPC gateway |
| `pkg/proxy` | PBS backup tunnel (gRPC stream, server-side protocol upgrade, TLS pinning); `pbstest` is a fake PBS for tests |
| `pkg/temporal` | SDK helpers, server worker, workflows and activities |
| `pkg/temporal/embedded` | In-process Temporal server (config, Postgres schema bootstrap, lifecycle) |
| `pkg/temporal/ui` | Embedded Temporal Web UI, proxied under `/temporal/` |
| `pkg/temporal/scheduler` | Temporal Schedules for cron jobs (synced on job changes, reconciled at startup) |
| `pkg/agentupdate` | Server-side mirror of the agent release binaries for self-update |
| `pkg/agent/runtime` | Shared agent daemon skeleton: config, self-enrollment, gateway connections, worker, heartbeat, token rotation, self-update |
| `pkg/agent/backup` | Agent backup engine on gopbs (pxar upload, blobs) |
| `pkg/agent/credstore` | Encrypted credential store on the agent (AES-256-GCM, 0600 key file, DPAPI on Windows) |
| `pkg/agent/vss` | Windows shadow copies (no-op elsewhere) |
| `pkg/dbbackup`, `pkg/agent/dbbackup` | DB job spec, profiles and manifest; the engines (PostgreSQL, MySQL/MariaDB, MongoDB via client tools, SQL Server natively) |
| `pkg/k8sbackup`, `pkg/agent/k8sbackup` | Kubernetes job spec and manifest; resource dump, PVC snapshot/clone, worker pods, orphan sweep |
| `pkg/pvebackup`, `pkg/agent/pvebackup` | PVE job spec and manifest; collectors, restore runbook |
| `pkg/dockerbackup`, `pkg/agent/dockerbackup` | Docker job spec and settings; Engine API client, collectors, volume reads, pause, runbook |
| `pkg/m365`, `pkg/agent/m365` | M365 job spec, tenant model, Graph auth; Graph client, delta index, virtual tree, collectors |
| `pkg/inventory` | What agents report about their host (periodic summary and on-demand detail) |
| `pkg/agenthealth` | The alerts on the agent status page |
| `pkg/rundetail` | Type-specific per-run detail shown on `/runs/<id>` |
| `pkg/fsutil` | Stdlib-only file helpers (`CopyTree`, `CopyMissing`, `CopyFile`, `FlattenPath`) |
| `pkg/db` | pgx pool, migrations, repositories |
| `pkg/integration` | End-to-end test: embedded Temporal + gateway + agent worker |
| `deploy/windows` | WiX source of the Windows MSI |
