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
| `/pbs-proxy/*` | agents during a backup | short-lived backup ticket (JWT) |
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
The primary backup target is going to be Proxmox Backup Server, with the help of the Proxmox Backup Server Go library (https://github.com/osshield/gopbs). Use the V2 format for backups.

## Code map
| Package | Purpose |
|---|---|
| `cmd/fallbck-server` | server entry point: config, database, embedded Temporal, worker, gateway, UI, single h2c listener |
| `cmd/fallbck-agent` | agent: enrollment, activity worker through the gateway, heartbeats, token rotation |
| `cmd/fallbck-ctl` | admin CLI (API key authenticated) |
| `pkg/auth` | JWT token manager, agent tokens + verifier, sessions, API keys, OIDC, HTTP middleware |
| `pkg/gateway` | authenticating, task-queue-scoped Temporal gRPC gateway for agents |
| `pkg/temporal/embedded` | in-process Temporal server (config, Postgres schema bootstrap, lifecycle) |
| `pkg/temporal/ui` | embedded Temporal Web UI (loopback ui-server, proxied under `/temporal/`) |
| `pkg/temporal` | SDK client helpers, server worker, workflows and activities |
| `pkg/api`, `web` | REST API and server-rendered Web UI |
| `pkg/proxy` | PBS proxy (`/pbs-proxy/*`) |
| `pkg/db` | pgx pool, versioned migrations, repositories |
| `pkg/integration` | end-to-end test: embedded Temporal + gateway + agent worker (`go test -tags sqlite`) |
