# Server config

`fallbck-server --config /etc/fallbck/server.yaml`. Every setting has a default, and most have a `FALLBCK_*` env var that **wins over the file**. Env vars are the way to go for secrets and containers. There's a commented example at [`deploy/server.yaml.example`](https://github.com/osshield/fallbck/blob/main/deploy/server.yaml.example).

Durations use Go syntax: `12h`, `90s`, `8760h`.

## General

| Key | Env | Default | What it does |
|---|---|---|---|
| `http_port` | `FALLBCK_HTTP_PORT` | `8080` | The one plaintext h2c port. Everything goes through it. |
| `http_bind` | `FALLBCK_HTTP_BIND` | `0.0.0.0` | Listen address. |
| `public_url` | `FALLBCK_PUBLIC_URL` | `http://localhost:8080` | Your reverse proxy's URL. Used for the OIDC redirect, install scripts and enrollment. |
| `trusted_proxies` | `FALLBCK_TRUSTED_PROXIES` | loopback | CIDRs allowed to set `X-Forwarded-For`. Add your reverse proxy when it isn't on the same host, e.g. its container network. |
| `jwt_secret` | `FALLBCK_JWT_SECRET` | generated | Signs sessions, agent tokens and tickets. Leave it empty and the server writes one to `<data_dir>/jwt.secret` on first start; set your own (32+ chars) if you'd rather manage it. Losing it signs every agent out. |
| `data_dir` | `FALLBCK_DATA_DIR` | `/var/lib/fallbck/server` | Master key, JWT secret, agent release cache. |
| `agent_ca_bundle_path` | `FALLBCK_AGENT_CA_BUNDLE` | | PEM bundle handed to agents at enrollment. Only for private CAs on `public_url`. |
| `timezone` | `FALLBCK_TIMEZONE` | `TZ` / host zone, else UTC | IANA zone for [cron schedules](../operations/scheduling.md). |

## `security`

| Key | Env | Default | What it does |
|---|---|---|---|
| `master_key_file` | `FALLBCK_MASTER_KEY_FILE` | `<data_dir>/master.key` | Seals PBS tokens and encryption keys. Generated on first start. **Back it up.** |
| `master_key` | `FALLBCK_MASTER_KEY` | | The key itself (64 hex chars), for containers. Beats the file. |

## `auth`

| Key | Env | Default | What it does |
|---|---|---|---|
| `oidc.issuer` | `FALLBCK_OIDC_ISSUER` | | Your IdP's issuer URL. |
| `oidc.client_id` | `FALLBCK_OIDC_CLIENT_ID` | | |
| `oidc.client_secret` | `FALLBCK_OIDC_CLIENT_SECRET` | | |
| `oidc.scopes` | `FALLBCK_OIDC_SCOPES` | | e.g. `[openid, profile, email, groups]` |
| `oidc.allowed_groups` | `FALLBCK_OIDC_ALLOWED_GROUPS` | anyone | Only these groups may sign in. Signing in still needs a [role binding](../operations/access.md). |
| `oidc.allowed_emails` | `FALLBCK_OIDC_ALLOWED_EMAILS` | anyone | Only these emails may sign in. Same deal. |
| `oidc.groups_claim` | | `groups` | ID token claim that carries groups. |
| `oidc.binding_claims` | `FALLBCK_OIDC_BINDING_CLAIMS` | `[roles]` | Further claims that `claim` role bindings can match (string or list values). `[]` turns claim bindings off. |
| `session_ttl` | `FALLBCK_SESSION_TTL` | `12h` | Admin session lifetime. |
| `insecure_disable` | `FALLBCK_AUTH_INSECURE_DISABLE` | `false` | No login at all. Refused unless the server runs with `--dev`. |

Register `<public_url>/auth/callback` as the redirect URI. List env vars are comma-separated.

## `agent_tokens`

| Key | Env | Default | What it does |
|---|---|---|---|
| `ttl` | `FALLBCK_AGENT_TOKEN_TTL` | `8760h` (a year) | Agent bearer token lifetime. Agents rotate well before it runs out. |

## `database`

| Key | Env | Default | What it does |
|---|---|---|---|
| `url` | `FALLBCK_DB_URL` | `postgres://fallbck:…@localhost:5432/fallbck` | Postgres DSN. |
| `max_open_conns` | | `25` | |
| `max_idle_conns` | | `5` | |
| `conn_max_lifetime` | | `5m` | |
| `auto_migrate` | | `true` | Run schema migrations on start. |

## `temporal`

| Key | Env | Default | What it does |
|---|---|---|---|
| `mode` | `FALLBCK_TEMPORAL_MODE` | `embedded` | `embedded` or `external`. |
| `namespace` | `FALLBCK_TEMPORAL_NAMESPACE` | `default` | |
| `embedded.bind_ip` | | `127.0.0.1` | Loopback only. Agents get in through the gateway, never directly. |
| `embedded.port_base` | `FALLBCK_TEMPORAL_PORT_BASE` | `7233` | The other services use +1 … +6. |
| `embedded.database_url` | `FALLBCK_TEMPORAL_DB_URL` | `database.url` with dbs `temporal` / `temporal_visibility` | |
| `embedded.history_shards` | | `4` | **Can't be changed after first start.** |
| `embedded.retention` | | `72h` | Workflow history retention. |
| `embedded.cluster_name` | `FALLBCK_TEMPORAL_CLUSTER_NAME` | `fallbck` | **Can't be changed after first start.** Set it to `active` to adopt DBs from `temporalio/auto-setup`. |
| `external.host_port` | `FALLBCK_TEMPORAL_HOST` | `localhost:7233` | For `mode: external`. |
| `external.enable_tls` | `FALLBCK_TEMPORAL_TLS` | `false` | |
| `external.ca_cert_path` | `FALLBCK_TEMPORAL_CA_CERT` | | |
| `external.client_cert_path` | `FALLBCK_TEMPORAL_CLIENT_CERT` | | |
| `external.client_key_path` | `FALLBCK_TEMPORAL_CLIENT_KEY` | | |
| `ui.enabled` | `FALLBCK_TEMPORAL_UI_ENABLED` | `true` | Temporal Web UI under `/temporal/`, for roles with `temporal:ui`. |
| `ui.port` | `FALLBCK_TEMPORAL_UI_PORT` | `8233` | Loopback. |
| `ui.read_only` | `FALLBCK_TEMPORAL_UI_READ_ONLY` | `true` | Hides terminate, cancel, signal, reset and schedule edits. The UI isn't label-scoped, so with this off anyone who can open it can stop any team's backups. Cancel runs from FallBCK instead. |

## `audit`

| Key | Env | Default | What it does |
|---|---|---|---|
| `retention` | `FALLBCK_AUDIT_RETENTION` | `8760h` | How long audit entries stay. A daily prune deletes older ones. `0` keeps everything. |
| `export` | `FALLBCK_AUDIT_EXPORT` | | Where entries go right before they're pruned: an absolute file path (JSON lines, appended), `http(s)://...` (POSTed as `application/x-ndjson`), `udp://host:port` or `tcp://host:port` (syslog), or `syslog:` for the local daemon. Empty: pruned entries are gone. See [Access control](../operations/access.md#retention-and-export). |
| `export_headers` | | | Extra headers for an HTTP export, e.g. `Authorization`. |

## Flags and other env

- `--config <path>`: the YAML file. Without it you get defaults plus env.
- `--dev`: allows `insecure_disable`. Never in production.
- `DEBUG=true` / `FALLBCK_LOG_LEVEL=debug`: verbose logs.
