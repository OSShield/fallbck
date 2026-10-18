# Docker hosts

Backs up a Docker host's containers, networks, volumes and compose projects, so you can stand it back up on a fresh box.

## Setup

Run `fallbck-agent` **as root** on the Docker host, one of two ways:

- the OS package, or
- the `cr.osshield.eu/fallbck/agent` image with the Docker socket mounted.

Onboarding (*Docker host*) prints both. Once the agent's heartbeat says it can reach the daemon, create a **Docker host** job.

## What's in the snapshot

Each run writes one `docker.pxar` into `host/<hostname>-docker`, with:

- **`collect/`**:
    - `docker inspect` for every container, network and volume
    - the compose files named in the `com.docker.compose.*` labels, plus `.env`
    - `/etc/docker/daemon.json`
    - image refs with digests (and, if the job asks, `docker save` tarballs of locally built or all images)
    - the `fallbck-docker.json` manifest and a generated restore runbook
- **`vol-<name>`**: one per named volume, archived file by file
- **`host-<path>`**: one per *additional host path* on the job, e.g. compose project dirs or bind-mounted data (`/srv/app` → `host-srv-app`)

Bind mounts are listed in the manifest but only archived if you add them as host paths. Out of scope: Swarm services, remote daemons, and DB dumps from inside containers. For those, point a [database job](databases.md) at the published port.

## Live copy vs. pause

Volumes are copied live by default. For anything that hates being copied hot:

- label a container `fallbck.io/pause=true` (or list it in the job) and it gets `docker pause`d while its volumes are copied;
- label a container or volume `fallbck.io/skip=true` to leave it out.

## How volumes get read

| `docker_backup.volume_access` | What happens |
|---|---|
| `auto` (default) | `direct` if `/var/lib/docker/volumes` is visible, otherwise `helper` |
| `direct` | reads `/var/lib/docker/volumes` straight off disk |
| `helper` | streams each volume through a throwaway container (`docker_backup.helper_image`, default `alpine:3.24`) |

Paused and helper-read volumes get staged in the spool first, so size the spool for your biggest one. The daemon is reached through `DOCKER_HOST` (unix sockets only) or `/var/run/docker.sock`. Override with `docker_backup.socket`.

## Restore

You need a host with Docker and the compose plugin:

```bash
eval "$(fallbck-ctl targets credentials <target>)"
proxmox-backup-client restore host/dock01-docker/2026-09-17T02:00:00Z docker.pxar /var/tmp/fallbck-docker-restore
bash /var/tmp/fallbck-docker-restore/collect/fallbck-docker-restore.sh --dry-run
bash /var/tmp/fallbck-docker-restore/collect/fallbck-docker-restore.sh --yes   # --containers also recreates standalone ones
```

The runbook restores `daemon.json`, recreates networks and volumes, copies each `vol-<name>` back in through a helper container, loads saved images and pulls the rest by digest, puts the compose files back and runs `docker compose up -d` per project. For containers that aren't part of a compose project it prints a best-effort `docker run`, and only runs it with `--containers`.
