# Production install

A production FallBCK is boring on purpose: `fallbck-server`, a Postgres database, and a reverse proxy that terminates TLS. Temporal runs inside the server, so that's the whole stack.

## What you need

- **Postgres** (any supported version). FallBCK uses one database for itself and, by default, creates `temporal` and `temporal_visibility` next to it for the embedded Temporal.
- **A reverse proxy with TLS**: Caddy, nginx or Traefik. The server only speaks plaintext h2c on one port and expects to sit behind the proxy.
- **An OIDC provider** for admin logins: Keycloak, Entra ID, Authentik, dex, whatever you already run.
- **A Proxmox Backup Server** and an API token with `Datastore.Backup` on the datastore (or namespace) you'll write to. See below.

### The PBS token

Give FallBCK its own user and token, with the `DatastoreBackup` role on the datastore and nothing else:

```bash
proxmox-backup-manager user create fallbck@pbs
proxmox-backup-manager user generate-token fallbck@pbs backup
proxmox-backup-manager acl update /datastore/store1 DatastoreBackup --auth-id 'fallbck@pbs'
proxmox-backup-manager acl update /datastore/store1 DatastoreBackup --auth-id 'fallbck@pbs!backup'
```

PBS gives a token the overlap of its own ACL entries and its user's, so both lines are needed. Scope it to a namespace (`/datastore/store1/hosts`) if you like.

That's all FallBCK ever uses: it only speaks the backup protocol, and retention is a PBS prune job. The server checks this. Every six hours, and whenever you save a target, it asks PBS what the token may do (a token can always ask about itself). A token that holds more than `Datastore.Backup` within its datastore gets a *too broad* warning on the target and the dashboard, listing each extra privilege and how to remove it. A token missing `Datastore.Backup` gets a red one, since backups would fail. The warnings stay until a check comes back clean, and every change of verdict lands in the audit log. *Check now* on the target form re-runs it.
## Install the server

Pick your poison:

=== "Linux package"

    ```bash
    apt install ./fallbck_server_Linux_amd64.deb      # or rpm -i / apk add --allow-untrusted
    $EDITOR /etc/fallbck/server.yaml /etc/fallbck/server.env
    systemctl enable --now fallbck-server
    ```

    See [Linux packages](packages.md) for paths and the OpenRC variant.

=== "Container"

    ```bash
    docker run -d --name fallbck-server \
      -p 8080:8080 \
      -v /srv/fallbck:/var/lib/fallbck/server \
      -v /srv/fallbck/server.yaml:/etc/fallbck/server.yaml:ro \
      -e TZ=Europe/Stockholm \
      cr.osshield.eu/fallbck/server:latest --config /etc/fallbck/server.yaml
    ```

    Or skip the file and set everything through `FALLBCK_*` env vars, the way `deploy/docker-compose.yml` does.

## Configure it

Start from [`deploy/server.yaml.example`](https://github.com/osshield/fallbck/blob/main/deploy/server.yaml.example). The bits you have to touch:

```yaml
public_url: "https://backup.example.com"   # what users and agents type in
# jwt_secret is generated into data_dir on first start; set it only to manage it yourself
database:
  url: "postgres://fallbck:...@db:5432/fallbck"
auth:
  oidc:
    issuer: "https://idp.example.com/realms/infra"
    client_id: "fallbck"
    client_secret: "..."
    allowed_groups: ["backup-admins"]
```

Register `https://backup.example.com/auth/callback` (your `public_url` plus the callback path) as the redirect URI in your IdP. The first person to sign in becomes the admin, so make that you, then hand out roles under *Access* ([Access control](../operations/access.md)). Every key has a `FALLBCK_*` environment variable too, which is handy for secrets. The full list is in [Server config](../reference/server-config.md).

!!! danger "Back up the master key"
    On first start the server generates `master.key` in its data dir. It seals your PBS API tokens and every target's encryption key. Lose it along with your exported key files and your encrypted backups are gone for good unless you manually back up the encryption keys. Back it up with the database, and keep it somewhere that isn't the backup server.

## Put a reverse proxy in front

Whatever proxy you use, it has to:

- forward **both** HTTP and gRPC to the backend over **h2c** on the same port (agents speak gRPC, browsers speak HTTP);
- keep read/idle timeouts **above 90 seconds**, because agents hold 70-second long polls open;
- not buffer request bodies (PBS chunk uploads go through here);
- pass `/temporal/` through as-is.

=== "Caddy"

    ```caddy
    backup.example.com {
        encode gzip
        reverse_proxy fallbck-server:8080 {
            transport http {
                versions h2c 2
                read_timeout 0
            }
            flush_interval -1
        }
    }
    ```

=== "nginx"

    nginx needs a separate `grpc_pass`, chosen by Content-Type:

    ```nginx
    map $http_content_type $fallbck_is_grpc {
        default 0;
        "~^application/grpc" 1;
    }

    upstream fallbck { server fallbck-server:8080; }

    server {
        listen 443 ssl;
        http2 on;
        server_name backup.example.com;
        ssl_certificate     /etc/ssl/certs/backup.example.com.crt;
        ssl_certificate_key /etc/ssl/private/backup.example.com.key;
        client_max_body_size 0;

        location / {
            if ($fallbck_is_grpc) {
                grpc_pass grpc://fallbck;
            }
            proxy_pass http://fallbck;
            proxy_http_version 1.1;
            proxy_set_header Host $host;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto https;
            proxy_read_timeout 120s;
            proxy_send_timeout 120s;
            proxy_request_buffering off;
        }

        grpc_read_timeout 120s;
        grpc_send_timeout 120s;
    }
    ```

=== "Traefik"

    Traefik v3 has a 60-second read timeout on entrypoints by default, which is too short for the long polls. Turn it off or raise it in the static config:

    ```yaml
    # traefik.yml (static)
    entryPoints:
      websecure:
        address: ":443"
        transport:
          respondingTimeouts:
            readTimeout: 0
    providers:
      file:
        filename: /etc/traefik/fallbck.yml
    ```

    Then route to the server over h2c in the dynamic config:

    ```yaml
    # fallbck.yml (dynamic)
    http:
      routers:
        fallbck:
          rule: Host(`backup.example.com`)
          entryPoints: [websecure]
          service: fallbck
          tls: {}
      services:
        fallbck:
          loadBalancer:
            servers:
              - url: h2c://fallbck-server:8080
            responseForwarding:
              flushInterval: -1
    ```

=== "HAProxy"

    Enable HTTP/2 to the backend with `proto h2`, this enables both HTTP and gRPC:

    ```haproxy
    defaults
        mode http
        timeout connect 5s
        timeout client  120s
        timeout server  120s

    frontend fallbck_in
        bind :443 ssl crt /etc/haproxy/certs/backup.example.com.pem alpn h2,http/1.1
        option forwardfor
        http-request set-header X-Forwarded-Proto https
        default_backend fallbck

    backend fallbck
        server fallbck fallbck-server:8080 proto h2
    ```

By default only a proxy on the same host may set `X-Forwarded-For`. If yours runs in a container or on another box, add its address or network to `trusted_proxies` (for Docker, its compose network, e.g. `172.16.0.0/12`). Otherwise the audit log shows the proxy's address for everyone, and the per-address enrollment limit treats all agents as one client. Don't trust a whole private range when other hosts in it can reach the server directly: they could then fake their address.

### Behind Cloudflare

Cloudflare's proxy works for the Web UI and API. If you want to proxy agent traffic:

- **Turn on gRPC** under *Network* in the Cloudflare dashboard. Agents speak gRPC on the same hostname, and without it they can't connect at all.
- **Keep your own proxy in front of the server.** Cloudflare only proxies gRPC to an origin that speaks HTTP/2 over TLS on 443, and `fallbck-server` only does plaintext h2c. Put Caddy or nginx (as above) in between with a real cert or a Cloudflare Origin CA cert, and set SSL mode to *Full (strict)*.
- **Trust Cloudflare's ranges.** Add your local proxy plus the ranges from <https://www.cloudflare.com/ips/> to `trusted_proxies`. Then firewall the origin so only Cloudflare can reach it, or anyone who skips Cloudflare can fake their address.
- **Keep the WAF and bot checks off agent traffic.** Agents aren't browsers and can't solve a challenge. Bot Fight Mode can't be skipped per path, so switch it off, or use Super Bot Fight Mode with a skip rule for `/api/v1/agents/*` and gRPC requests.

!!! warning "Backups through the tunnel"
    Cloudflare cuts a request after about 100 seconds without a response from the origin (only Enterprise can raise that), and Free and Pro plans cap request bodies at 100 MB. A backup through the server's PBS tunnel is one long gRPC stream, so a large or slow run may get cut off. Test a big backup and a long incremental before you rely on it.

    The safe setup is a second hostname for agents with the proxy off (grey cloud), pointed at the same reverse proxy, and set as the agents' `server_url`. Or turn on [direct PBS](../agents/index.md) for jobs whose agents can reach PBS themselves, so the backup data never goes through Cloudflare.

## Next up

Sign in, open **Onboarding**, and enroll your first agent. [Agents and file backups](../agents/index.md) explains what happens along the way.

## Release signatures

Every release's checksums file is signed keyless with cosign from the GitHub release workflow, and the container images are signed the same way. To check a download by hand:

```bash
cosign verify-blob --bundle fallbck_<version>_checksums.txt.sigstore.json \
  --certificate-identity-regexp '^https://github.com/osshield/fallbck/.github/workflows/release.yml@refs/tags/v' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  fallbck_<version>_checksums.txt
sha256sum -c --ignore-missing fallbck_<version>_checksums.txt
```

The server does the same check before it mirrors an agent release, and agents do it again before they replace their own binary. An agent older than 0.15 can't verify, so update those once by package or installer. A server older than 0.15 offers no signature, so a 0.15+ agent refuses to self-update from it.
