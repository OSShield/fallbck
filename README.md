<picture>
    <source
    srcset="./docs/assets/fallbck-horizontal-dark.svg"
    alt="FallBCK Dark Logo"
    media="(prefers-color-scheme: dark)"
    width="300" height="100"
    />
    <img
    src="./docs/assets/fallbck-horizontal.svg"
    alt="FallBCK Light Logo"
    width="300" height="100"
    />
  </picture>

Application-aware backups for filesystems, databases, Kubernetes, Proxmox VE and Docker hosts, and Microsoft 365, straight into Proxmox Backup Server.

FallBCK sits as a backup orchestrator between Proxmox Backup Server and a few custom agents, and coordinates backups, schedules, targets and monitors the jobs. Traffic either goes from the agents directly into PBS, or you can route it via a tunnel built in to FallBCK Server.

All data is saved as plain (or encrypted) PXAR archives just like container- or VM backups, meaning you restore everything from the PBS ui just like you're used to. We do include a few helpful scripts in the backups to make restoring easier, but FallBCK Server never requires anything more than DatastoreBackup permissions, meaning it can't alter or delete existing backups. Retention policies are handled by PBS.


## Background
We have been using PBS pretty much since it came out as a beta around 2020, and over time we have built internal scripts and workflows to upload all kinds of backups into it. FallBCK is the end product resulting from all of those hours, scripts and manual backups we've done over the last few years, startin from around 6 months ago when we got the approval to package it into a proper program. We have one other developer to thank for a lot of the initial work on decoding the first specification, building a whole library around it, getting Windows VSS snapshots to work and much more: [@tizbac](https://github.com/tizbac) and their project [proxmoxbackupclient_go](https://github.com/tizbac/proxmoxbackupclient_go). If you are looking for a command-line tool similar to proxmox-backup-client (but cross-platform, built in Go), that's the project you want!

After recently showing FallBCK to some former colleagues who expressed an interest in using it, we decided to package it into a more formal project that others can use and contribute to as well, and now that we have reached 1.0.0 we are finally ready to release it to the world.

## Features
All below features are free and open source. There is no enterprise plan, there never will be. Our primary motive for developing this is to use it ourselves internally, and while we might start to provide support, backup storage or managed hosting around it sometime in the future (with the same model as Maurer does for Proxmox itself), you will never find a BSL license file in this repository.

- Server Features
  - Integrated Temporal server for job coordination
  - Proxy for backup communication in case some clients can't reach PBS server directly
  - Web UI for managing agents, backup jobs, runs and logs
  - Role-based access control for different user permissions
  - Audit logging for tracking user actions and system events
  - Onboarding workflow for new servers/targets
  - OpenID Connect authentication as the standard method for user login (no SSO tax here).

- Backup Targets
  - Supports backing up to a PBS datastore or namespace in a datastore
  - Requires only the DatastoreBackup permission for its tokens (and will warn you if you are using a token with higher privileges, we encourage separation of duties)
  - Supports both plain and encrypted PXAR archives in format V1 or V2 (the latter has more efficient deduplication)
  - Can be combined with other targets like tizbac's `pmoxs3backuproxy` to back up straight to any S3-compatible storage without an actual PBS server in the middle.
  - Stores files in the original format(s), no proprietary data structures, we'll never lock you in.
  
- Agent Features
  - Deployment via Docker Compose, Kubernetes, Package repositories (APK, DEB, RPM, WinGet) or as a standalone binary
  - The agent connects to the server to receive and execute backup jobs, no firewalls have to be opened from server to client
  - Can back up directly to PBS, or through a tunnel via FallBCK to a PBS instance
  - Secure client-side credential storage (databases, kubernetes, ms365) as an option so database credentials never touch the server side


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
| Containers | Databases | Supports backups of databases inside containers, same databases as above, with the credentials fetched from a kubernetes secret | Restore files or archives from PBS UI or CLI and run the script included in the backup for automatic restore, or copy/restore files manually as needed |
| Cloud | Microsoft 365 [Beta] | Backup of Microsoft 365 data including Outlook, OneDrive, Sharepoint, Teams and Entra data | Saved as much as possible as the native format, automatic restore functionality and documentation is still under active development |
| Code | Git repositories [Beta] | Mirrors of git repositories over HTTPS: all branches, tags, merge request heads and Git LFS objects, one snapshot per run | Restore the archive from PBS UI or CLI and run the included script to push a repository into an empty one |


## LLM Usage
The product itself does not use any AI technologies for any of its functionality. It does not connect to any external services at runtime except for PBS and whatever workload you choose to use it to back up (e.g. Microsoft 365). It doesn't have an MCP server, and we don't need one internally, but we can consider adding one if the demand is there.

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
The plan is to provide a more user-friendly restore tool (via a fully local standalone CLI, not integrated into the server), which will simplify the process of restoring backups and data from PBS back into the respective source.

### Backup Sources
These are the future backup sources that are currently planned. If you miss any, feel free to open an issue or contribute with a pull request:

- VCS (Github, Gitlab, Gitea, Forgejo, etc.)
  - Started
- Cloud storage (via librclone, so all/most supported providers like S3-compatible, Azure blob, Mega, Dropbox)
- Google Workspace (Gmail, Drive, Calendar, Contacts, etc.)
- Build a better, responsive UI for the web interface
- Other hypervisors
  - Here I need some community feedback on what would be the most useful. We only use proxmox in-house.

### Better integration with Proxmox Backup Server
Once PBS supports a plugin system, we plan to integrate parts of the backup workflow directly into PBS instead of providing a separate UI.