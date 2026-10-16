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
