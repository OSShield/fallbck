# FallBCK

FallBCK backs up your filesystems, databases, Kubernetes clusters, Proxmox VE and Docker hosts, and Microsoft 365 tenants into [Proxmox Backup Server](https://www.proxmox.com/en/products/proxmox-backup-server/overview). You get PBS's dedup, verification and pruning, plus one place to manage all the jobs.

It's two moving parts:

- **`fallbck-server`**: a single binary with Postgres behind it. It runs the Web UI and REST API, and it embeds [Temporal](https://temporal.io) to do the orchestration. You don't need a separate Temporal cluster.
- **Agents**: small daemons on the boxes you back up. Agents only ever talk to the server's public URL. They never see your PBS credentials unless you explicitly allow it.

Snapshots are plain pxar, so restores use PBS's own tools (the GUI or `proxmox-backup-client`). If FallBCK is down, you can still get your data back.

## Where to start

- **Kicking the tires?** [Try it locally](getting-started/quick-start.md) with Docker Compose in about two minutes.
- **Setting it up for real?** Go to [Production install](getting-started/production.md) for TLS, SSO and a proper reverse proxy.
- **Backing something up?** Start with the [Agents](agents/index.md) overview, then the page for what you're protecting.
- **Automating?** See the [CLI](operations/cli.md) and the [REST API](reference/api.md).

## What it can back up

| What | Agent | Page |
|---|---|---|
| Files and directories (Linux, Windows) | `fallbck-agent` | [Agents and file backups](agents/index.md), [Windows](agents/windows.md) |
| PostgreSQL, MySQL/MariaDB, MongoDB | `fallbck-agent` + the vendor client tools | [Databases](agents/databases.md) |
| Microsoft SQL Server | `fallbck-agent` (no extra tools) | [SQL Server](agents/sql-server.md) |
| Kubernetes resources, PVCs, in-cluster databases | `fallbck-k8s-agent` (Helm) | [Kubernetes](agents/kubernetes.md) |
| Proxmox VE node config | `fallbck-agent` on the node | [Proxmox VE hosts](agents/proxmox.md) |
| Docker hosts (containers, volumes, compose) | `fallbck-agent` | [Docker hosts](agents/docker.md) |
| Exchange Online, OneDrive, SharePoint, Teams, Entra ID | `fallbck-agent` (anywhere with outbound HTTPS) | [Microsoft 365](agents/m365.md) |

!!! note "FallBCK never deletes anything on PBS"
    Retention is a PBS datastore prune job, so set one up. FallBCK writes snapshots and that's it. It doesn't prune, forget or delete, and its API token doesn't need the rights to.
