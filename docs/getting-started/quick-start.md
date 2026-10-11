# Try it locally

The fastest way to see FallBCK run is the Compose stack in `deploy/`. It brings up Postgres and the server in dev mode with login switched off, so don't put this on the internet.

```bash
git clone https://github.com/osshield/fallbck.git
cd fallbck/deploy
docker compose up -d --build
```

Open <http://localhost:8080> for the Web UI. The embedded Temporal UI is at <http://localhost:8080/temporal/> if you want to watch workflows go by.

## Enroll an agent

Grab an enrollment token from the API, then start the example agent container with it:

```bash
TOKEN=$(curl -s -X POST http://localhost:8080/api/v1/tokens \
  -H 'Content-Type: application/json' -d '{"name":"compose-agent"}' | jq -r .raw_token)
FALLBCK_AGENT_ENROLLMENT_KEY=$TOKEN docker compose --profile agent up -d
```

The agent turns up on the **Agents** page within a few seconds. From there, **Onboarding** walks you through adding a PBS target and your first backup job.

!!! tip "No PBS lying around?"
    You'll need one to actually store backups. A throwaway PBS VM is fine for testing. Give the API token `Datastore.Backup` on a datastore and you're set.

## With SSO and TLS

Want something closer to production? Use the SSO overlay. Caddy terminates TLS and [dex](https://dexidp.io) plays the OIDC provider:

```bash
cd deploy
docker compose -f docker-compose.yml -f compose.sso.yml up -d --build
```

Browse to <https://fallbck.localhost>, accept Caddy's local CA, and sign in as `admin@example.com` / `password`.

When you're ready for the real thing, head to [Production install](production.md).
