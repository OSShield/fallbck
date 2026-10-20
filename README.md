# fallbck

Application-aware backups for filesystems, databases, Kubernetes, Proxmox VE and Docker hosts, and Microsoft 365, straight into Proxmox Backup Server.

FallBCK is built in Go with an integrated [Temporal](https://temporal.io) server for the agent handling/coordination of jobs. All snapshots are saved as plain (or encrypted) PXAR archives in format V1 or V2 (better deduplication, more efficient storage but requires PBS at version 2.5 or later). Everything can be restored from these archives manually using PBS or via the scripts included in the backups themselves.

By design, FallBCK only holds the DatastoreBackup permission which eliminates the risk of connecting it to a PBS instance since it can't touch settings or delete backups or files. Retention policies are configured in and enforced by PBS.

## Background
We have been using PBS pretty much since it came out as a beta around 2020, and over time we have built internal tools and workflows to manage all kinds of backups into it. FallBCK is the end product resulting from all of those hours, scripts and manual backups we've done over the last few years. We have one other developer to thank for a lot of the initial work on decoding the first specification, building a whole library around it, getting Windows VSS snapshots to work and much more: [@tizbac](https://github.com/tizbac) and their project [proxmoxbackupclient_go](https://github.com/tizbac/proxmoxbackupclient_go). If you are looking for a command-line tool similar to proxmox-backup-client (but cross-platform, built in Go), that's the project you want!

After recently showing FallBCK to some former colleagues who expressed an interest in using it, we decided to package it into a more formal project that others can use and contribute to as well, and now that we have reached 1.0.0 we are finally ready to release it to the world.


## Features

- Backup Targets
  - Supports backing up to a PBS datastore or namespace in a datastore
  - Requires only the DatastoreBackup permission for its tokens (and will warn you if you are using a token with higher privileges)
  - Supports both plain and encrypted PXAR archives in format V1 or V2
  - Can be combined with other targets like tizbac's `pmoxs3backuproxy` to back up straight to any S3-compatible storage
  - Stores files in the original format(s), no proprietary data structures.

- Agent Features
  - Deployment via Docker Compose, Kubernetes, Package repositories (APK, DEB, RPM, WinGet) or as a standalone binary
  - The agent connects to the server to receive and execute backup jobs, no firewalls have to be opened from server to client
  - Can back up directly to PBS, or via a tunnel via FallBCK to a PBS instance
  - Secure client-side credential storage (databases, kubernetes, ms365) as an option so database credentials never touch the server side

- Server Features
  - Integrated Temporal server for job coordination
  - Proxy for backup communication in case some clients can't reach PBS server directly
  - Web UI for managing agents, backup jobs, runs and logs
  - Role-based access control for different user permissions
  - OpenID Connect authentication as the standard method for user login (no SSO tax here)
  - Audit logging for tracking user actions and system events
  - Onboarding workflow for new servers/targets

## Backup Sources

| Kind | Type | Description | Restore Workflow |
|------|------|-------------|-----------------|
| Filesystem | Local | Local filesystem backup (Windows, Linux, MacOS) | Restore files directly via PBS UI or CLI |
| Database | MariaDB/MySQL | Backup of MariaDB/MySQL databases with binary log archival for PITR | Restore archive from PBS UI or CLI and run the script included in the backup for automatic restore |
| Database | PostgreSQL | Backup of PostgreSQL databases with WAL archival for PITR | Restore archive from PBS UI or CLI and run the script included in the backup for automatic restore |
| Database | SQL Server | Backup of SQL Server databases with transaction log archival for PITR | Restore archive from PBS UI or CLI and run the script included in the backup for automatic restore |
| Database | MongoDB | Backup of MongoDB databases with oplog archival for PITR | Restore archive from PBS UI or CLI and run the script included in the backup for automatic restore |
| Virtualization | PVE | Backup of Proxmox Virtual Environment (PVE) hosts for easier restore during DR (not VM/CT backup or storage backup, PVE handles that by itself just fine) | Restore the archive to a freshly installed PVE server and run the included script or copy files manually as needed |
| Containers | Docker | Backup of Docker images, containers, volumes, networks and compose definitions | Restore archive from PBS UI or CLI and run the script included in the backup for automatic restore, or copy/restore files manually as needed |
| Containers | Kubernetes | Backup of Kubernetes API resources, volumes/volume snapshots, cluster state | Restore archive from PBS UI or CLI and run the script included in the backup for automatic restore, or copy/restore files manually as needed |
| Containers | Databases | Supports application-aware backups of databases inside containers, same databases as above | Restore files or archives from PBS UI or CLI and run the script included in the backup for automatic restore, or copy/restore files manually as needed |
| Cloud | Microsoft 365 [Beta] | Backup of Microsoft 365 data including Outlook, OneDrive, Sharepoint, Teams and Entra data | Saved as much as possible as the native format, automatic restore functionality and documentation is still under active development |


## LLM Usage
The product itself does not use any AI technologies for any of its functionality. It does not connect to any external services at runtime except for PBS and whatever workload you choose to use it to back up (e.g. Microsoft 365).

During the course of the project, and for ongoing maintenance, AI coding assistants have been used to help with code generation, refactoring, combination of various scripts, review of our code and other development tasks. All AI-generated suggestions have been reviewed and approved by the development team before being included in the project.


📖 **Docs: <https://osshield.github.io/fallbck/>**

## Quick start (with PBS included)
You can run our demo instance from the compose.yml in the `demo` directory. It will set up FallBCK, register a single agent in a container, connect to an ephemeral (single-use) PBS instance and allow you to click around and see the functionality without any risk to your existing environment.

## Quick start (local, no login)
If you want to set up a fresh instance, use the compose file in the `deploy` directory instead. Do note that PBS provides no functionality for username/password login, and requires an OpenID Connect server to handle authentication. It can also be switched off entirely.

```bash
cd deploy
docker compose -f docker-compose.yml -f compose.dev.yml up -d   # postgres + fallbck-server, admin login off (dev only)
open http://localhost:8080            # Web UI; Temporal UI at http://localhost:8080/temporal/
```

Enroll the example agent container:

```bash
TOKEN=$(curl -s -X POST http://localhost:8080/api/v1/tokens -H 'Content-Type: application/json' -d '{"name":"compose-agent"}' | jq -r .raw_token)
FALLBCK_AGENT_ENROLLMENT_KEY=$TOKEN docker compose --profile agent up -d
```

For a real install (TLS, SSO, reverse proxy), see [Production install](https://docs.fallbck.eu/getting-started/production/).

## Hacking on it

```bash
go build ./... && go test ./...
```

More in [Development](https://docs.fallbck.eu/development/). The docs source is in [`docs/`](docs/).


## Roadmap
### Easier restore functionality
The plan is to provide a more user-friendly restore tool (likely a standalone CLI), which will simplify the process of restoring backups and data from PBS back into the respective source.

### Backup Sources
These are the future backup sources that are currently planned. If you miss any, feel free to open an issue or contribute with a pull request:

- VCS (Github, Gitlab, Gitea, Forgejo, etc.)
- Cloud storage (via RClone, so all/most supported providers)
- Google Workspace (Gmail, Drive, Calendar, Contacts, etc.)
- Build a better, responsive UI for the web interface
- Other hypervisors
  - Here I need some community feedback on what would be the most useful. We only use proxmox in-house.

### Better integration with Proxmox Backup Server
Once PBS supports a plugin system, we plan to integrate parts of or the entire backup workflow directly into PBS.