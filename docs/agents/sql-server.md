# SQL Server

SQL Server doesn't need any client tools. The agent runs `BACKUP DATABASE` / `BACKUP LOG ... TO DISK` over its built-in driver, SQL Server writes the files, and the agent moves them into its spool, uploads them as `db.pxar` and deletes them. That means every `fallbck-agent` reports `mssql`. The normal setup is the agent on the SQL Server box itself, either the Windows service or the Linux package.

## Job options

- **Mode**
    - `auto`: does a full when there isn't one, when the chain broke, or when the last full is older than *full every N days*. Otherwise a differential.
    - `full`, `differential`
    - `log`: transaction log only. Run it as its own job on a tight schedule.
- **Also back up the log** after each full/differential, for databases in FULL or BULK_LOGGED recovery.
- **Compression**: off by default. PBS dedups uncompressed backups way better, and Express can't compress anyway.
- **Copy-only.**

`master` always gets a full and `tempdb` never gets backed up. Offline databases and snapshots are skipped, with a note in the run.

## Keeping the chain honest

The agent tracks the chain it holds for each database (last full, last diff, logs since) and checks it against `msdb` before every run:

- If the server's newest full isn't the one FallBCK holds (another tool took one, or a run died after the backup), the next diff becomes a full. That's a **chain reset**.
- If a log backup doesn't start where the previous one ended, it's flagged as a **log chain gap**.

The run page lists every backup set with its LSNs and why it got that type.

## Where the files go

By default they go to the instance's **default backup path** (`InstanceDefaultBackupPath`). SQL Server can write there, and an agent on the same host can read it.

If SQL Server runs somewhere else or in a container, give both views of one shared directory:

- `backup_dir`: the path as SQL Server sees it
- `agent_dir`: the same place as the agent sees it (UNC share, bind mount)

Before any backup runs, the agent writes a probe file to check that the two really are the same place.

## Auth

- **SQL login**: password on the job or in a [credential profile](databases.md#2-keep-it-on-the-agent-credential-profiles).
- **Windows integrated auth**: leave the user blank on Windows and the agent connects as its service account. LocalSystem needs a login with backup rights, e.g. `db_backupoperator` in every database, or `sysadmin`.

There's no passwordless option for SQL Server on Linux. Use `host\instance` for named instances.

!!! note
    SQL Server jobs can't run on the Kubernetes agent. The backup file would land inside the SQL Server pod.

## Restore

The restore commands in the manifest give you the chain in order:

1. `RESTORE DATABASE ... WITH NORECOVERY` for the full and the newest differential
2. `RESTORE LOG ...` for each log backup
3. finish `WITH RECOVERY`. Add `STOPAT` for point-in-time.
