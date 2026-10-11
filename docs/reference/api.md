# REST API

Everything the Web UI and `fallbck-ctl` do goes through `/api/v1` on the server's public URL. It's plain JSON over HTTPS. There's no OpenAPI spec yet, so this page is the map.

## Auth

Create an API key under **API Keys** in the Web UI and send it as a bearer token:

```bash
curl -H "Authorization: Bearer fbk_..." https://backup.example.com/api/v1/agents
```

Keys are hashed at rest, and you only see the raw one once, when you create it. Browser sessions work too, but then state-changing requests need `X-Requested-With: fallbck`. That's CSRF protection, so scripts should just use a key.

Errors come back as `{"error": "<message>"}` with a sensible status code.

## Health

| Method | Path | Notes |
|---|---|---|
| `GET` | `/health` | No auth. Use it for load balancer checks. |
| `GET` | `/auth/me` | Who you're authenticated as: `kind`, `subject`, `email`, `name`. |

## Enrollment tokens

| Method | Path | Notes |
|---|---|---|
| `POST` | `/tokens` | Create one. Returns `raw_token` exactly once. |
| `GET` | `/tokens` | List. |
| `GET` | `/tokens/{id}` | |
| `DELETE` | `/tokens/{id}` | |

```json
POST /api/v1/tokens
{ "name": "web-01", "max_uses": 1, "expires_at": "2026-12-31T00:00:00Z" }
```

`max_uses: 0` means unlimited, and it defaults to 1.

## API keys

| Method | Path | Notes |
|---|---|---|
| `POST` | `/apikeys` | `{"name": "...", "expires_at": "..."}` (expiry optional). Returns `raw_key` once. |
| `GET` | `/apikeys` | |
| `DELETE` | `/apikeys/{id}` | Revokes the key. |

## Agents

| Method | Path | Notes |
|---|---|---|
| `GET` | `/agents` | |
| `GET` | `/agents/{id}` | |
| `DELETE` | `/agents/{id}` | |
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
| `PUT` | `/targets/{id}/encryption` | `{"mode": "encrypt" \| "none", "master_public_key": "<PEM or empty>"}` |
| `POST` | `/targets/{id}/encryption/rotate` | New key. The old one gets retired, not deleted. |
| `POST` | `/targets/{id}/encryption/export` | `{"passphrase", "hint", "key_id"}`. Returns a `proxmox-backup-client` key file. Leave `key_id` empty for the active key. |
| `POST` | `/targets/{id}/encryption/import` | `{"keyfile", "passphrase"}` |

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

## Agent-only endpoints

These are what agents call, authenticated with their own bearer token. You won't need them unless you're writing an agent, but they're listed here so nothing's a mystery:

`POST /agents/enroll` (enrollment token), `POST /agents/heartbeat`, `POST /agents/token/rotate`, `POST /agents/token/worker`, `POST /agents/ticket/refresh`, `POST /agents/sub-ticket`, `POST /agents/volume-ticket`, `POST /agents/run-progress`, `GET /agents/pbs-credentials`, `GET /agents/encryption-key`, `GET /agents/db-credentials`, `GET /agents/m365-credentials`, `GET /agents/update/{os}/{arch}`.

The credential endpoints also need a valid backup ticket in `X-Fallbck-Backup-Ticket`. The [Architecture](../architecture.md) page explains the flow.
