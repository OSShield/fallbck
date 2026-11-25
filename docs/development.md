# Development

You need Go 1.27+.

```bash
go build ./... && go test ./...
go test -tags sqlite ./pkg/temporal/embedded/ ./pkg/integration/   # boots a real Temporal in-process
```

Some things are best tested against a real PBS instance - e.g. whether `proxmox-backup-client` restores what the agent encrypted, whether dedup and incremental reuse hold up. The `pbse2e` tests start a throwaway [ephemeral-pbs](https://github.com/osshield/ephemeral-pbs) container per package (needs Docker) and run the agent activity through the tunnel against it:

```bash
go test -tags pbse2e -count=1 ./pkg/tokencheck/ ./pkg/agent/
```

Set `FALLBCK_E2E_PBS_IMAGE` to try a local build of the image. Users, tokens and namespaces are configured in `pkg/pbse2e/pbs-config.yml`.

The server binary is big (about 175 MB) because the whole Temporal server and Web UI are baked in. The Dockerfiles use BuildKit cache mounts, so rebuilds stay quick.

For a local stack to poke at, see [Try it locally](getting-started/quick-start.md).

## Dev container

`.devcontainer/` runs the server and an agent from your checkout, next to the demo's throwaway PBS and a Postgres. Open the repo in VS Code and pick **Reopen in Container**. The first start builds both binaries, which takes a couple of minutes. After that:

- The UI is on <http://localhost:8080>, with no login. The PBS target `Demo Level1` is set up, and the agent `fallbck-dev` is enrolled. It has the PostgreSQL, MariaDB and MongoDB client tools, so database jobs work, for example against the dev Postgres (`postgres:5432`, `fallbck` / `fallbck`).
- With the Docker socket mounted (see below), a second agent, `fallbck-dev-docker`, runs as root on it, the same as on a real Docker host. Docker host jobs go there.
- After a code change, run `.devcontainer/fallbck.sh`. It rebuilds the binaries and restarts everything, which takes about 15 seconds. If the build fails, the running ones are left alone.
- `.devcontainer/fallbck.sh logs` follows all the logs. `.devcontainer/fallbck.sh stop` stops everything.
- PBS is forwarded on 8007 (`root` / `demo`), and the Temporal UI on 8233. If something on your machine already uses one of those ports, VS Code picks another and shows it under **Ports**.
- The live DB tests have their own database, so `go test ./...` runs them without touching your dev data.

### More things to back up

`.devcontainer/compose.yml` has optional services behind compose profiles. Name the ones you want in `.devcontainer/.env` (gitignored), then **Rebuild Container**. The volumes are kept.

```bash
COMPOSE_PROFILES=mariadb,mongodb,remote
MYSQL_TAG=8.4      # optional: another version; also MARIADB_TAG, MONGO_TAG, MSSQL_TAG
```

| Profile | What | Job settings |
|---|---|---|
| `mariadb` | MariaDB 11.4 with binary logging | host `mariadb`, `root` / `fallbck` |
| `mysql` | MySQL 8.0 | host `mysql`, `root` / `fallbck` |
| `mongodb` | MongoDB 4.4, a one-node replica set | host `mongodb`, no auth |
| `mssql` | SQL Server 2022 | host `mssql`, `sa` / `Fallbck-dev1`, backup dir `/var/opt/mssql/backup`, agent dir `/mnt/mssql-backup` |
| `remote` | S3, SFTP, SMB and WebDAV servers | all `fallbck` / `fallbck`; endpoints are in the compose file |

The defaults are the versions that work. MySQL 8.4 and later fail, because the MariaDB `mariadb-dump` runs `SHOW MASTER STATUS`, which 8.4 removed. MongoDB 5.0 and later need a CPU with AVX.

### Docker socket

The socket mount in `.devcontainer/compose.yml` is commented out. Uncomment it and rebuild to get `fallbck-dev-docker`. That gives the container root on your host, and a Docker host job reads every container and volume on it unless the job excludes them, so put exclusions on test jobs.

### State

Server and agent state (master key, JWT secret, Temporal, the agents' identities) lives in a volume. It goes together with the Postgres volume: delete one and you have to delete the other, because a new master key can't open the old secrets. To start over, remove the container and its volumes.

PBS forgets everything when its container restarts, so the snapshots go with it.

## Releases

[GoReleaser](https://github.com/osshield/fallbck/blob/main/.goreleaser.yml) builds everything from the `Release` GitHub Action when a `v*` tag is pushed. Every push to `main` and every PR gets a snapshot build as a workflow artifact, so packaging can't quietly rot.

## Docs

This site is in `docs/` and gets built with [Zensical](https://zensical.org) from `mkdocs.yml`. Preview it locally:

```bash
pip install zensical
zensical serve
```

Pushes to `main` that touch `docs/` or `mkdocs.yml` deploy to GitHub Pages automatically.
