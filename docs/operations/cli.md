# CLI

`fallbck-ctl` is a thin client over the [REST API](../reference/api.md). Create an API key in the Web UI (**API Keys**), then:

```bash
export FALLBCK_SERVER_URL=https://backup.example.com
export FALLBCK_API_KEY=fbk_...
```

## Commands

```bash
# enrollment tokens
fallbck-ctl token create --name web-01 [--max-uses 1] [--days 1]   # prints the enroll command
fallbck-ctl token list

# agents
fallbck-ctl agents list
fallbck-ctl agents merge <agent> --into <agent>   # id, id prefix or hostname

# PBS targets
fallbck-ctl targets list
fallbck-ctl targets credentials <target>          # prints PBS_REPOSITORY / PBS_PASSWORD / PBS_FINGERPRINT exports

# jobs and runs
fallbck-ctl jobs list
fallbck-ctl jobs run <job-id>
fallbck-ctl runs list

fallbck-ctl version
```

`--max-uses 0` makes a token unlimited. That's handy for automated rollouts. Just give it a short `--days`.

`targets credentials` is made for restores, used like this:

```bash
eval "$(fallbck-ctl targets credentials pbs-main)"
proxmox-backup-client snapshot list
```

It hands out the PBS API token, so every call gets logged on the server.

`agents merge` moves one agent's jobs and run history onto another and deletes the first. It's mostly for [retiring the old DB agent](../agents/databases.md#coming-from-fallbck-db-agent).

Jobs get created in the Web UI's onboarding flow, or through the [API](../reference/api.md#jobs) if you're scripting it.
