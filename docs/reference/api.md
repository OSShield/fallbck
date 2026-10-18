# REST API

Everything the Web UI and `fallbck-ctl` do goes through `/api/v1` on the server's public URL. It's plain JSON over HTTPS. There's no OpenAPI spec yet, so this page is the map.

## Auth

Create an API key under **API Keys** in the Web UI and send it as a bearer token:

```bash
curl -H "Authorization: Bearer fbk_..." https://backup.example.com/api/v1/agents
```

Keys are hashed at rest, and you only see the raw one once, when you create it. Browser sessions work too, but then state-changing requests need `X-Requested-With: fallbck`. That's CSRF protection, so scripts should just use a key.

Errors come back as `{"error": "<message>"}` with a sensible status code.

Every admin route needs a permission (see [Access control](../operations/access.md)). Without it anywhere you get a `403`. Objects outside your scope come back as `404`, exactly like missing ones, and lists leave them out. A `403` on an object means you can see it but not do that to it.

### Labels

Agents, targets, jobs, tenants, key rings and enrollment tokens take `"labels": {"team": "web"}` on create and update. On update, leaving `labels` out keeps the stored ones, and `{}` clears them. Changing them needs the write permission on both the old and the new labels.

## Health

| Method | Path | Notes |
|---|---|---|
| `GET` | `/health` | No auth. Use it for load balancer checks. |
| `GET` | `/auth/me` | Who you're authenticated as: `kind`, `subject`, `email`, `name`, plus `permissions` (the union over all your bindings) and `bindings`. |

## Enrollment tokens

| Method | Path | Notes |
|---|---|---|
| `POST` | `/tokens` | Create one. Returns `raw_token` exactly once. |
| `GET` | `/tokens` | List. |
| `GET` | `/tokens/{id}` | |
| `DELETE` | `/tokens/{id}` | |

```json
POST /api/v1/tokens
{ "name": "web-01", "max_uses": 1, "expires_at": "2026-12-31T00:00:00Z", "labels": {"team": "web"} }
```

`max_uses: 0` means unlimited, and it defaults to 1. Agents enrolled with the token get its labels.

## API keys

| Method | Path | Notes |
|---|---|---|
| `POST` | `/apikeys` | `{"name": "...", "expires_at": "...", "role": "viewer", "selector": "team=web"}`. Expiry is optional; role defaults to `admin`, selector to everything. Returns `raw_key` once. |
| `GET` | `/apikeys` | |
| `GET` | `/apikeys/roles` | The roles a key can take. |
| `DELETE` | `/apikeys/{id}` | Revokes the key. |

A key can't reach further than whoever creates it: you need every permission of the role on a selector the key's selector narrows, or you get a `403`.

## Agents

| Method | Path | Notes |
|---|---|---|
| `GET` | `/agents` | |
| `GET` | `/agents/{id}` | |
| `DELETE` | `/agents/{id}` | |
| `PUT` | `/agents/{id}/labels` | `{"labels": {"team": "web"}}`. Replaces the agent's labels. |
| `POST` | `/agents/{id}/debug` | `{"enabled": true}` turns on live debug logging. |
| `POST` | `/agents/{id}/auto-update` | `{"enabled": true}` opts the agent into [self-update](../operations/agent-status.md#agent-updates). |
| `POST` | `/agents/{id}/update` | Update to the server's version on the next heartbeat. |
| `POST` | `/agents/{id}/merge` | `{"into": "<agent id>"}`. Moves jobs and runs, then deletes this agent. |
| `POST` | `/agents/{id}/logs` | Fetches the agent's buffered log lines. The agent has to be online. |
| `POST` | `/agents/{id}/inventory` | Asks for the full inventory. The agent has to be online. |

## PBS targets

| Method | Path | Notes |
|---|---|---|
| `POST` | `/targets` | Create. |
| `GET` | `/targets` | |
| `GET` | `/targets/{id}` | |
| `PUT` | `/targets/{id}` | Same body as create. |
| `DELETE` | `/targets/{id}` | |
| `POST` | `/targets/{id}/clone` | `{"name", "namespace", "pxar_format"}`. Copies the token server-side. |
| `GET` | `/targets/{id}/credentials` | `PBS_*` exports for `proxmox-backup-client`. **Logged.** |
| `POST` | `/targets/{id}/token-check` | Asks PBS what the target's token may do and stores the verdict: `ok`, `excess`, `missing` or `error`, with findings. `targets:write`. Targets carry the last result as `token_check`. |

```json
POST /api/v1/targets
{
  "name": "pbs-main",
  "target_type": "pbs",
  "endpoint": "https://pbs.example.com:8007",
  "datastore": "store1",
  "namespace": "prod",
  "auth_token": "backup@pbs!fallbck:xxxxxxxx-xxxx-...",
  "fingerprint": "AA:BB:...",
  "tls_verify": true,
  "pxar_format": "v2",
  "encryption_mode": "none"
}
```

The token is stored sealed and is never returned. Pin a self-signed PBS with `fingerprint`, or use `tls_verify` with a proper chain.

### Encryption

| Method | Path | Notes |
|---|---|---|
| `GET` | `/targets/{id}/encryption` | Mode, fingerprint, master key status. |
| `PUT` | `/targets/{id}/encryption` | `{"mode": "encrypt" \| "none", "key_ring_id": "<ring or empty>", "master_public_key": "<PEM or empty>"}`. Empty ring with `encrypt` creates one named after the target. |
| `POST` | `/targets/{id}/encryption/rotate` | Rotates the target's ring: new key for every target on it. The old one gets retired, not deleted. |
| `POST` | `/targets/{id}/encryption/export` | `{"passphrase", "hint", "key_id"}`. Returns a `proxmox-backup-client` key file. Leave `key_id` empty for the active key. |
| `POST` | `/targets/{id}/encryption/import` | `{"keyfile", "passphrase"}`, onto the target's ring. |

Key rings hold the keys; targets attach to a ring and share its key (and PBS dedup) with every other target on it. `key_ring_id` is also accepted on `POST /targets` and `PUT /targets/{id}`.

| Method | Path | Notes |
|---|---|---|
| `GET` | `/keyrings` | Rings with fingerprint and attached targets. |
| `POST` | `/keyrings` | `{"name", "master_public_key"}`. Generates the first key. |
| `GET` | `/keyrings/{id}` | Ring plus key history. |
| `PUT` | `/keyrings/{id}` | `{"name", "master_public_key"}` |
| `DELETE` | `/keyrings/{id}` | Only when no target uses it. Deletes its keys. |
| `POST` | `/keyrings/{id}/rotate` | |
| `POST` | `/keyrings/{id}/export` | As for targets. |
| `POST` | `/keyrings/{id}/import` | As for targets. |

See [Encryption](../operations/encryption.md) for what all of this means.

## Microsoft 365 tenants

| Method | Path | Notes |
|---|---|---|
| `POST` | `/m365/tenants` | Create. |
| `GET` | `/m365/tenants` | |
| `GET` | `/m365/tenants/{id}` | |
| `PUT` | `/m365/tenants/{id}` | |
| `DELETE` | `/m365/tenants/{id}` | Refused while jobs still use it. |
| `POST` | `/m365/tenants/{id}/test` | Gets a token and reads `/organization`. |

```json
{
  "name": "contoso",
  "tenant_id": "00000000-0000-0000-0000-000000000000",
  "client_id": "11111111-1111-1111-1111-111111111111",
  "auth_method": "secret",
  "secret": "..."
}
```

For certificate auth, use `"auth_method": "certificate"` with `certificate_pem` and `key_pem`. Secrets are write-only.

## Jobs

| Method | Path | Notes |
|---|---|---|
| `POST` | `/jobs` | Create. |
| `GET` | `/jobs` | |
| `GET` | `/jobs/{id}` | Passwords are never returned (`has_password` tells you one is set). |
| `PUT` | `/jobs/{id}` | |
| `DELETE` | `/jobs/{id}` | Removes its schedule too. |
| `POST` | `/jobs/{id}/run` | Run now. |

Common fields:

```json
{
  "name": "web-01 etc",
  "agent_id": "<uuid>",
  "target_id": "<uuid>",
  "job_type": "filesystem",
  "schedule_cron": "0 2 * * *",
  "enabled": true,
  "direct_pbs": false,
  "backup_paths": ["/etc", "/srv"],
  "exclude_paths": ["*.tmp"]
}
```

`job_type` is one of `filesystem`, `database`, `kubernetes`, `pve`, `docker` or `m365`. Every type besides `filesystem` takes its settings in a matching object: `db_config`, `k8s_config`, `pve_config`, `docker_config` or `m365_config`. A database job, for example:

```json
{
  "job_type": "database",
  "db_config": {
    "engine": "postgres",
    "host": "localhost",
    "user": "",
    "profile": "",
    "databases": [],
    "postgres": { "mode": "dump" }
  }
}
```

!!! tip "Easiest way to get a type-specific body right"
    Set one job up in the Web UI, `GET /jobs/{id}` it, and use that as your template. The per-type specs have quite a few knobs, and they map one-to-one to the job form.

## Runs

| Method | Path | Notes |
|---|---|---|
| `GET` | `/runs` | Recent runs. |
| `GET` | `/runs/{id}` | Includes the type-specific detail blob. |
| `POST` | `/runs/{id}/cancel` | |

Runs follow their job: `jobs:read` on the job's labels to see them, `jobs:run` to cancel.

## Access control

All of these need `rbac:manage`, except the audit log.

| Method | Path | Notes |
|---|---|---|
| `GET` | `/rbac/permissions` | The permission catalog, grouped by resource, plus the global-only ones. |
| `GET` | `/rbac/roles` | Roles with their permissions and how many bindings and keys use them. |
| `POST` | `/rbac/roles` | `{"name": "backup-op", "description": "...", "permissions": ["jobs:read", "jobs:run"]}` |
| `PUT` | `/rbac/roles/{name}` | Same body. Built-in roles are refused. |
| `DELETE` | `/rbac/roles/{name}` | Refused while anything is bound to it. |
| `GET` | `/rbac/bindings` | |
| `POST` | `/rbac/bindings` | `{"kind": "group", "subject": "web-team", "role": "operator", "selector": "team in (web, api)"}`. `kind` is `user` (email), `group`, or `claim` with subject `claim=value` for a claim in `oidc.binding_claims`. |
| `DELETE` | `/rbac/bindings/{id}` | Refused for the last binding with `rbac:manage` on everything. |
| `GET` | `/rbac/subjects` | Emails, groups and claim values seen at sign-in, with when, plus the configured binding claims. |
| `GET` | `/rbac/selector?q=...` | Parses a selector and returns its canonical form and clauses. `rbac:manage` or `apikeys:manage`. |

Selectors are strings in [Kubernetes label selector syntax](../operations/access.md#selectors), and responses always use the canonical string. Requests may still send the older object form, `{"team": "web"}`, which means `team=web`. Bindings come back with `last_seen` (the subject's last sign-in, or null) and `stale` (not seen for 90 days).
| `GET` | `/audit` | `audit:read`. Query: `actor` (substring), `action` (prefix), `resource`, `from`, `to` (RFC 3339 or `YYYY-MM-DD`), `limit` (max 5000), `format=csv`. |

## Agent-only endpoints

These are what agents call, authenticated with their own bearer token. You won't need them unless you're writing an agent, but they're listed here so nothing's a mystery:

`POST /agents/enroll` (enrollment token), `POST /agents/heartbeat`, `POST /agents/token/rotate`, `POST /agents/token/worker`, `POST /agents/ticket/refresh`, `POST /agents/sub-ticket`, `POST /agents/volume-ticket`, `POST /agents/run-progress`, `GET /agents/pbs-credentials`, `GET /agents/encryption-key`, `GET /agents/db-credentials`, `GET /agents/m365-credentials`, `GET /agents/update/{os}/{arch}`.

The credential endpoints also need a valid backup ticket in `X-Fallbck-Backup-Ticket`. The [Architecture](../architecture.md) page explains the flow.
