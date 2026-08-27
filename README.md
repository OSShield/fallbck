# fallbck
Backup filesystems, databases, kubernetes and more.

FallBCK is a single-binary backup server (with an embedded [Temporal](https://temporal.io) engine and Web UI) plus lightweight agents. See [STRUCTURE.md](STRUCTURE.md) for the architecture.

## Quick start (local, no login)

```bash
cd deploy
docker compose up -d --build          # postgres + fallbck-server (admin auth disabled, --dev)
open http://localhost:8080            # Web UI; Temporal UI at http://localhost:8080/temporal/
```

Enroll an example agent container:

```bash
TOKEN=$(curl -s -X POST http://localhost:8080/api/v1/tokens -H 'Content-Type: application/json' -d '{"name":"compose-agent"}' | jq -r .raw_token)
FALLBCK_AGENT_ENROLLMENT_KEY=$TOKEN docker compose --profile agent up -d
```

## With single sign-on and TLS (like production)

```bash
cd deploy
docker compose -f docker-compose.yml -f compose.sso.yml up -d --build
open https://fallbck.localhost        # accept Caddy's local CA; sign in as admin@example.com / password
```

Caddy terminates TLS and forwards HTTP + gRPC to the server over h2c; dex is the OIDC provider. In production point `public_url` at your reverse proxy and configure `auth.oidc.*` for your identity provider (`deploy/server.yaml.example`, `deploy/caddy/Caddyfile.production.example`, `deploy/nginx.conf.example`).

## Agents

```bash
fallbck-agent enroll --server https://backup.example.com --token <enrollment token>
fallbck-agent run
```

The agent needs exactly one endpoint: the server's public URL. It receives a bearer token at enrollment, polls its own Temporal task queue through the server's gateway, and streams backups into PBS through a session the server opens on its behalf (the agent never holds PBS credentials). A job can instead be set to **direct PBS access** (server-side job option `direct_pbs`): the agent then fetches the target's connection details and API token for that run and talks to PBS itself — useful when the agent has a better path to PBS than the server does.

## CLI

Create an API key in the Web UI (API Keys), then:

```bash
export FALLBCK_SERVER_URL=https://backup.example.com FALLBCK_API_KEY=fbk_...
fallbck-ctl token create --name web-01
fallbck-ctl agents list
```

## Troubleshooting

Set `DEBUG=true` (or `FALLBCK_LOG_LEVEL=debug`) on the server or agent for verbose logs. On the server this shows every PBS session handshake — the upgrade request (datastore, snapshot, token id without the secret) and PBS's answer — plus the embedded Temporal's info logs. On the agent it shows tunnel setup and credential fetches.

PBS API tokens must be entered as `user@realm!tokenid:secret` (the `=` spelling from the PBS token dialog is accepted and normalised); the token needs `Datastore.Backup` on the datastore/namespace. A `401 authentication failed` from PBS means the token or secret is wrong; `403` means missing privileges.

## Linux packages

Releases ship `.deb`, `.rpm` and `.apk` packages for `fallbck-server` and `fallbck-agent` (built by [GoReleaser](.goreleaser.yml) from the `Release` GitHub Action on `v*` tags; every push to `main` and every PR produces a snapshot build as a workflow artifact).

| Package | Service | Config |
|---|---|---|
| `fallbck-server` | systemd `fallbck-server` (deb/rpm) / OpenRC `fallbck-server` (apk), runs as user `fallbck` | `/etc/fallbck/server.yaml`, secrets in `/etc/fallbck/server.env` |
| `fallbck-agent` | systemd `fallbck-agent` / OpenRC `fallbck-agent`, runs as root | `/etc/fallbck/agent.env` (optional self-enrollment), state in `/var/lib/fallbck/agent` |

```bash
# server
apt install ./fallbck_server_Linux_amd64.deb      # or rpm -i / apk add --allow-untrusted
$EDITOR /etc/fallbck/server.yaml /etc/fallbck/server.env
systemctl enable --now fallbck-server              # OpenRC: rc-update add fallbck-server default && rc-service fallbck-server start

# agent
apt install ./fallbck_agent_Linux_amd64.deb
fallbck-agent enroll --server https://backup.example.com --token <enrollment token>
systemctl enable --now fallbck-agent
```

Publishing to the package repositories needs the `PKG_UPLOAD_PASSWORD` repository secret (the `linux_push` user of `*.pkg.lv`).

## Development

```bash
go build ./... && go test ./...
go test -tags sqlite ./pkg/temporal/embedded/ ./pkg/integration/   # boots the real Temporal server in-process
```

`go.mod` currently `replace`s `github.com/osshield/gopbs` with a sibling checkout (`../gopbs-fallbck`, branch `fallbck-session-dialer`) that adds `pbs.Config.DialSession`; until that change is merged and tagged, Docker and CI builds need the replace pointed at a published version.

Requires Go 1.26+. The server binary is large (~175 MB) because it embeds the Temporal server and Web UI; the Dockerfiles use BuildKit cache mounts to keep rebuilds fast.
