# Databases

`fallbck-agent` dumps **PostgreSQL**, **MySQL/MariaDB** and **MongoDB** on any host that has the vendor client tools installed. It doesn't need a separate agent, service or data dir: install the tools and the agent picks them up. SQL Server is different enough to get [its own page](sql-server.md).

```bash
apt install fallbck-agent postgresql-client mariadb-client   # whatever engines you back up
fallbck-agent tools                                          # what did it find?
```

The agent looks for tools at startup and every ten minutes after, and reports what it can back up with its heartbeat. You'll see a badge on the Agents page, like *DB: postgres, mssql*. A database job can go to any agent that reports the job's engine.

## What each engine does

| Engine | How |
|---|---|
| PostgreSQL | `pg_dump` per database plus `pg_dumpall --globals-only`, and/or `pg_basebackup` with streamed WAL |
| MySQL / MariaDB | `mysqldump` / `mariadb-dump --single-transaction` with the binlog position. One `--all-databases` file or one file per database, optionally plus the binlogs written since the last run |
| MongoDB | `mongodump --oplog`, restorable with `--oplogReplay` |

!!! warning "pg_dump has to be at least as new as the server"
    The agent hunts through the usual per-version dirs (`/usr/lib/postgresql/*/bin`, `/usr/pgsql-*/bin`, `/usr/libexec/postgresql*`). If it still grabs the wrong one, pin it with `db_backup.tools.postgres_bindir`.

Fetching binlogs also needs `mysqlbinlog` / `mariadb-binlog`. On Alpine that only comes in the full `mariadb` package. MongoDB needs `mongodb-database-tools`. If you'd rather not install any of this, the `oci.fi/fallbck/agent:tools` image ships all of it.

## Setting up a job

Create a *Database* job in onboarding: engine, host, user, databases, TLS and engine options. For the password you've got three choices.

### 1. Store it on the server

Type it into the job. The agent fetches it over its authenticated API for each run. It never goes through Temporal, and the API never hands it back out.

### 2. Keep it on the agent (credential profiles)

Leave the password blank and name a **credential profile**. Profiles live in the agent's encrypted store: `<data_dir>/credentials.enc`, AES-256-GCM, with the key in `credentials.key` (mode 0600, and wrapped with DPAPI on Windows). Passwords never leave the host. The agent only tells the server the profile names, engine, user and host, so the job form can offer them in a dropdown.

```bash
fallbck-agent database profile create --name prod --engine postgres --user backup --ask-password
fallbck-agent database profile create --name shop --engine mysql --user backup --host db2 \
  --tls-mode verify-full --tls-ca /etc/ssl/corp-ca.pem
fallbck-agent database profile list            # never shows passwords
fallbck-agent database profile delete --name shop
```

Old-style plain-text profiles in `agent.yaml` (`db_backup.profiles`) and `FALLBCK_AGENT_DB_PROFILE_<NAME>_PASSWORD` env vars still work. The agent nags about them at startup, and `fallbck-agent database profile import` moves them into the store. If both exist, the stored profile wins.

### 3. No credentials at all

If the agent runs as root **on the database host** and the job points at that machine (socket path, `localhost`, its own hostname or IP), leave user, password and profile empty. The agent falls back to what the engine gives the local superuser for free:

- **PostgreSQL**: runs the tools as the `postgres` OS user over the unix socket (peer auth, which is the default `pg_hba.conf`). Set a user on the job to use a different role and the matching OS user.
- **MySQL/MariaDB**: connects as `root@localhost` over the socket, which `auth_socket` / `unix_socket` accepts. That's the default on Debian, Ubuntu and MariaDB. If your MySQL root has a password, you still need a profile.
- **MongoDB**: connects without auth.

Dumps are written through file descriptors the agent opens, so the `postgres` user doesn't need access to the spool. The exception is `postgres.mode: basebackup` / `both`, which writes there directly. Then `db_backup.spool_dir` has to be reachable by `postgres`, and the default data dir is `0700`.

## Agent-side settings

```bash
fallbck-agent database config spool_dir /srv/spool   # also state_dir, min_free_bytes, keep_failed_spool,
                                                     # postgres_bindir, mysql_bindir, mongo_bindir; "-" resets
fallbck-agent database config                        # print what's in effect
```

The full list is in [Agent config](../reference/agent-config.md).

## What lands on PBS

Each run dumps into `<data_dir>/spool/<run>/`, so give the spool room for your biggest dump. Runs refuse to start when free space is below `db_backup.min_free_bytes`. The agent uploads the spool as `db.pxar` plus a `fallbck-db.json.blob` manifest, then deletes it. The manifest has tool and server versions, files and checksums, WAL range / binlog position / oplog, and ready-to-run restore commands.

Snapshots go into the group `host/db-<engine>-<host>`. You can override that per job with *backup group id*. Either way they prune separately from the host's file backups.

## Restore

```bash
proxmox-backup-client restore <snapshot> db.pxar ./restore
```

Then follow `restore.commands` in `fallbck-db.json`. Or grab just the manifest blob first if you want to read the plan before pulling the whole thing.

## Coming from `fallbck-db-agent`?

The standalone DB agent is gone. `fallbck-agent` does its job now. Old installs keep working but don't get updates. To move a host over:

1. Install the client tools next to `fallbck-agent` and wait for a heartbeat.
2. `fallbck-agent migrate-db-agent` copies the WAL/binlog chain state and credential profiles from `/var/lib/fallbck/db-agent`.
3. `fallbck-ctl agents merge <db-agent> --into <agent>` moves the jobs and run history and deletes the old agent record.
4. Remove the old package.

Heads up: dumps now run as root. PostgreSQL profiles that relied on peer auth as `fallbck` need a password or a peer mapping for root.
