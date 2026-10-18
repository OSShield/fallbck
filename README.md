# fallbck

Backups for filesystems, databases, Kubernetes, Proxmox VE and Docker hosts, and Microsoft 365, straight into Proxmox Backup Server.

FallBCK is one server binary (with [Temporal](https://temporal.io) and its Web UI baked in) plus lightweight agents. Snapshots are plain pxar, so you restore with PBS's own tools.

📖 **Docs: <https://osshield.github.io/fallbck/>**

## Quick start (local, no login)

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

For a real install (TLS, SSO, reverse proxy), see [Production install](https://osshield.github.io/fallbck/getting-started/production/).

## Hacking on it

```bash
go build ./... && go test ./...
```

More in [Development](https://osshield.github.io/fallbck/development/). The docs source is in [`docs/`](docs/).


## Roadmap
### Backup Sources
These are the future backup sources that are currently planned. If you miss any, feel free to open an issue or contribute with a pull request:

- VCS (Github, Gitlab, Gitea, Forgejo, etc.)
- Cloud storage (via RClone, so all/most supported providers)
- Google Workspace (Gmail, Drive, Calendar, Contacts, etc.)
- Other hypervisors
  - Here I need some community feedback on what would be the most useful. We only use proxmox in-house.

### Better integration with Proxmox Backup Server
Once PBS supports a plugin system, we plan to integrate parts of or the entire backup workflow directly into PBS.