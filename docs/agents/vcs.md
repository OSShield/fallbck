# Git repositories

Backs up git repositories over HTTPS: every branch, tag and merge request head, plus Git LFS objects. Any `fallbck-agent` can run these jobs once it has git 2.31 or newer, and git-lfs for repositories that use LFS.

This is a beta. For now you create jobs through the [API](../reference/api.md#vcs-connections) with a list of repository URLs. Listing VCS projects/repos/groups, and the web UI, come in a later version.

**It currently backs up code, not projects**: issues, merge request discussions, CI/CD settings and releases are not included.

## 1. Prepare the agent

Install git and git-lfs on the agent host. The agent reports what it found with its next heartbeat, and the agent's status page tells you when a job can't run because git is missing or too old.

!!! info "The agent keeps a mirror of every repository"
    Each repository is kept as a bare mirror in the agent's VCS state directory, `<data_dir>/vcs-state` by default. The first run clones everything; later runs only fetch what changed. Plan for as much space as the repositories and their LFS objects take.

    To put the mirrors on a bigger disk, set `vcs_state_dir` in `agent.yaml` or `FALLBCK_AGENT_VCS_STATE_DIR`. When a job is deleted or moved to another agent, its mirrors are deleted 7 days later.

    We are planning to do on-host backups for servers like Gitlab so that we don't have to duplicate the data, but this was the best way to achieve source-agnostic incremental runs for now without re-fetching everything each time.

## 2. Create a connection

A connection is the git host and, optionally, the token to read it with. Every repository of a job must be below the connection's URL: the token is only ever sent there.

```bash
curl -X POST https://fallbck.example.com/api/v1/vcs/connections \
  -H "Authorization: Bearer $FBK_KEY" -H "Content-Type: application/json" \
  -d '{"name": "git-internal", "provider": "git", "base_url": "https://git.example.com", "token": "..."}'
```

The token is sealed on the server and handed to the agent per run. It is sent as HTTP basic auth with the user name `oauth2`, which GitLab accepts. For hosts that want a specific user name, keep the token on the agent instead (next step). Add `ca_pem` for a host with a private CA. Leave out `token` for public repositories.

## 3. Keep the token on the agent (optional)

If the server shouldn't hold the token, create the connection without one and store the token in the agent's encrypted credential store:

```bash
fallbck-agent vcs profile create --name git-internal --url https://git.example.com --ask-token
fallbck-agent vcs profile list
fallbck-agent vcs profile test --name git-internal   # GitLab: checks the token and records its expiry
```

The job then names the profile (`"profile": "git-internal"`). The agent only uses a profile for the URL it was created for, so the profile's `--url` must equal the connection's `base_url`. Use `--token-file` instead of `--ask-token` when a secret manager keeps the token in a file. `--username` sets the basic auth user name.

## 4. Create a job

```json
{
  "name": "git repositories",
  "agent_id": "<uuid>",
  "target_id": "<uuid>",
  "job_type": "vcs",
  "schedule_cron": "0 3 * * *",
  "vcs_config": {
    "connection_id": "<uuid>",
    "repositories": [
      "https://git.example.com/team/app.git",
      "https://git.example.com/team/infra.git"
    ],
    "workloads": {"lfs": true},
    "concurrency": 4
  }
}
```

`POST` it to `/api/v1/jobs`. Add `"profile"` to use an agent credential profile, and `"backup_id"` to choose the PBS group.

## What lands on PBS

Each run writes **one snapshot** in the group `host/vcs-<connection name>`:

| Path | Contents |
|---|---|
| `vcs.pxar` → `<host>/<path>/repository.git/` | Bare mirror: branches, tags, `refs/merge-requests/*/head`, LFS objects in `lfs/objects/` |
| `vcs.pxar` → `RESTORE.md`, `restore.sh` | How to restore, and a script that does it |
| `fallbck-vcs.json.blob` | The run manifest: every repository and how its fetch went |

Use a pxar v2 target: files of a mirror that did not change since the last run are referenced from the previous snapshot instead of being read again. An encrypted target is a good idea too, since source code has a tendency to contain some (semi-)secrets.

## When something fails

- A repository that hasn't changed costs one `git ls-remote` and nothing else.
- If a fetch fails and the agent has an earlier mirror, that mirror goes into the snapshot marked `stale`, and the run ends **partial**.
- A repository that fails on its first run is left out, and the run ends partial.
- The run fails only when no repository could be backed up.

## Restore

Restore the archive, then push a repository into an empty one on the git host:

```bash
proxmox-backup-client restore host/vcs-git-internal/<time> vcs.pxar ./restore
sh ./restore/restore.sh git.example.com/team/app https://git.example.com/team/app-restored.git
```

This pushes all branches, tags and LFS objects. Merge request refs stay in the backup: GitLab doesn't accept pushes to them. To look at the code without a server, `git clone ./restore/git.example.com/team/app/repository.git`.
