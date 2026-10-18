# Agent config

`fallbck-agent enroll` writes `agent.yaml` into the data dir for you, so you rarely need to touch it. Packaged installs keep it in `/var/lib/fallbck/agent/agent.yaml`. On Windows it's `%ProgramData%\fallbck\agent`. Env vars win over the file. There's a commented example at [`deploy/agent.yaml.example`](https://github.com/osshield/fallbck/blob/main/deploy/agent.yaml.example).

The `db_backup` section belongs to you: it survives re-enrollment. The easier way to change it is `fallbck-agent database config <key> <value>`.

## Identity and connection

Mostly written at enrollment.

| Key | Env | What it does |
|---|---|---|
| `agent_id` | `FALLBCK_AGENT_ID` | Set at enrollment. |
| `hostname` | `FALLBCK_AGENT_HOSTNAME` | Defaults to the OS hostname. |
| `server_url` | `FALLBCK_AGENT_SERVER_URL` | The server's public URL. The only endpoint the agent uses. |
| `data_dir` | `FALLBCK_AGENT_DATA_DIR` | `/var/lib/fallbck/agent` as root, `~/.fallbck/agent` otherwise. |
| `task_queue` | `FALLBCK_AGENT_TASK_QUEUE` | Set at enrollment. |
| `namespace` | `FALLBCK_AGENT_NAMESPACE` | Set at enrollment. |
| `auth_token` | `FALLBCK_AGENT_AUTH_TOKEN` | Bearer token. The file has to be `0600`. |
| `token_expires_at` | | Rotated automatically. |
| `server_ca_cert_path` | `FALLBCK_AGENT_SERVER_CA` | Private CA for `server_url`. |
| `insecure_skip_verify` | `FALLBCK_AGENT_INSECURE_SKIP_VERIFY` | Testing only. |
| `enrollment_key` | `FALLBCK_AGENT_ENROLLMENT_KEY` | Self-enroll on first start. |
| `log_level` | `FALLBCK_AGENT_LOG_LEVEL` | `debug`, `info`, `warn` or `error`. `DEBUG=true` overrides it. |
| `vss` | `FALLBCK_AGENT_VSS` | Windows only. Shadow copies, default `true`. |

## `db_backup`

See [Databases](../agents/databases.md).

| Key | Env | Default | What it does |
|---|---|---|---|
| `spool_dir` | `FALLBCK_AGENT_DB_SPOOL_DIR` | `<data_dir>/spool` | Dumps get staged here before upload. |
| `state_dir` | `FALLBCK_AGENT_DB_STATE_DIR` | `<data_dir>/state/db` | Last WAL / binlog position per job. |
| `min_free_bytes` | `FALLBCK_AGENT_DB_MIN_FREE_BYTES` | | A run won't start below this much free spool. |
| `keep_failed_spool` | `FALLBCK_AGENT_DB_KEEP_FAILED_SPOOL` | `false` | Keep failed runs' spool around for a post-mortem. |
| `tools.postgres_bindir` | `FALLBCK_AGENT_DB_POSTGRES_BINDIR` | auto | Pin a `pg_dump` at least as new as the server. |
| `tools.mysql_bindir` | `FALLBCK_AGENT_DB_MYSQL_BINDIR` | auto | |
| `tools.mongo_bindir` | `FALLBCK_AGENT_DB_MONGO_BINDIR` | auto | |
| `profiles.<name>` | `FALLBCK_AGENT_DB_PROFILE_<NAME>_{ENGINE,USER,PASSWORD,PASSWORD_FILE,HOST,PORT}` | | Plain-text credential profiles. Use the encrypted store instead (`fallbck-agent database profile ...`). |

A file profile looks like this:

```yaml
db_backup:
  profiles:
    postgres:
      engine: postgres
      user: backup
      password_file: /etc/fallbck/pg-backup.pass
      tls: { mode: verify-full, ca_file: /etc/ssl/certs/corp-ca.pem }
```

## `docker_backup`

See [Docker hosts](../agents/docker.md).

| Key | Env | Default | What it does |
|---|---|---|---|
| `volume_access` | `FALLBCK_AGENT_DOCKER_VOLUME_ACCESS` | `auto` | `auto`, `direct` or `helper`. |
| `helper_image` | `FALLBCK_AGENT_DOCKER_HELPER_IMAGE` | `alpine:3.24` | Image for helper containers. |
| `socket` | `FALLBCK_AGENT_DOCKER_SOCKET` | `DOCKER_HOST` or `/var/run/docker.sock` | Unix sockets only. |
