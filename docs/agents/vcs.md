# Git repositories

Backs up git repositories over HTTPS: every branch, tag and merge or pull request head, plus Git LFS objects and wikis. Any `fallbck-agent` can run these jobs once it has git 2.31 or newer, and git-lfs for repositories that use LFS.

There are two kinds of connection:

- **GitLab** (`gitlab`): the agent lists the projects of the groups you name through the GitLab API, so new projects are picked up automatically. Works with gitlab.com and self-managed GitLab.
- **GitHub** (`github`): the agent lists the repositories of the owners (organizations or users) you name, the token user's starred repositories and gists through the GitHub API. Works with github.com and GitHub Enterprise Server.
- **Plain git** (`git`): any HTTPS git host; the job lists the repository URLs.

This is a beta. Set it up in the web UI (**Git Connections**, then **Onboarding → Git repositories**) or through the [API](../reference/api.md#vcs-connections); both are shown below.

**It backs up code, not projects**: issues, merge request discussions, CI/CD settings and releases are not included. The exception is GitHub's opt-in `metadata` workload, which stores issues, pull requests, comments and releases as JSON next to the mirror.

## 1. Prepare the agent

Install git and git-lfs on the agent host. The agent reports what it found with its next heartbeat, and the agent's status page tells you when a job can't run because git is missing or too old. GitLab jobs also need an agent version that supports GitLab: the server refuses a GitLab job for an older agent and asks you to update it.

!!! info "The agent keeps a mirror of every repository"
    Each repository is kept as a bare mirror in the agent's VCS state directory, `<data_dir>/vcs-state` by default. The first run clones everything; later runs only fetch what changed. Plan for as much space as the repositories and their LFS objects take.

    To put the mirrors on a bigger disk, set `vcs_state_dir` in `agent.yaml` or `FALLBCK_AGENT_VCS_STATE_DIR`. When a job is deleted or moved to another agent, its mirrors are deleted 7 days later.

    We are planning to do on-host backups for servers like Gitlab so that we don't have to duplicate the data, but this was the best way to achieve source-agnostic incremental runs for now without re-fetching everything each time.

## 2. Create a connection

A connection is the git host and, optionally, the token to read it with. Every repository of a job must be below the connection's URL: the token is only ever sent there.

In the web UI: **Git Connections → Add Connection**. For GitLab and GitHub, press **Test** on the list afterwards: it checks the token's scopes and records when it expires. Or through the API:

```bash
curl -X POST https://fallbck.example.com/api/v1/vcs/connections \
  -H "Authorization: Bearer $FBK_KEY" -H "Content-Type: application/json" \
  -d '{"name": "gitlab", "provider": "gitlab", "base_url": "https://gitlab.example.com", "token": "glpat-..."}'
```

For GitHub, use `"provider": "github"` and `"base_url": "https://github.com"` (or your GitHub Enterprise Server URL). For a plain git host, use `"provider": "git"` and the URL every repository is below (`https://git.example.com/team`).

### GitLab tokens

Use a personal, group or project access token with the **`read_api`** and **`read_repository`** scopes. `api` and `write_repository` work too, but give the backup more than it needs. Check the token with `POST /api/v1/vcs/connections/{id}/test`: it reports the GitLab version, the token's user, its scopes and when it expires, and the health page warns 30 days before that.

Which projects a job sees depends on the token:

- With **groups** in the job, the projects of those groups the token can read. A group access token is the natural fit.
- Without groups, **every project** on the instance when the token's user is an administrator. Otherwise only the projects the user is a member of, and each run's manifest says so. gitlab.com can't be backed up as a whole: name the groups.

The token is sealed on the server and handed to the agent per run. It is sent as HTTP basic auth with the user name `oauth2`, which GitLab accepts. For hosts that want a specific user name, keep the token on the agent instead (next step). Add `ca_pem` for a host with a private CA. Leave out `token` for public repositories.

### GitHub tokens

A classic personal access token needs `repo` (private repositories), `read:org` (organization repositories) and `gist` (secret gists). A fine-grained token needs read access to *Contents*, *Metadata*, *Issues* and *Pull requests* on the repositories it should see. **Test** reads `/user` and reports the token's user, scopes and expiry. Starred repositories and "own gists" are those of the token's user.

On github.com, gists live on `gist.github.com`, so the token is sent there as well, and only when the job backs up gists. GitHub Enterprise serves both below the connection URL.

### GitHub App

Github app auth offers some improvements vs. Github tokens, mainly that it doesn't rely on a single user/account and has its own API rate limit (which grows with org size).

1. Create a GitHub App (organization settings, **Developer settings → GitHub Apps**). It needs no webhook. Give it read access to **Contents** and **Metadata**, plus **Issues** and **Pull requests** if jobs should have the `metadata` workload enabled.
2. Install it on the organization and pick the repositories it may read. The installation id is the number at the end of the installations settings URL.
3. Generate a private key and create the connection with it:

```bash
curl -X POST https://fallbck.example.com/api/v1/vcs/connections \
  -H "Authorization: Bearer $FBK_KEY" -H "Content-Type: application/json" \
  -d "$(jq -n --rawfile key app.private-key.pem '{name: "github", provider: "github", base_url: "https://github.com",
        auth_type: "github_app", app_id: 123456, installation_id: 7890123, app_key: $key}')"
```

The key is sealed like a token and never returned. For each run the server creates an installation token, limited to the read permissions the job needs, and hands it to the agent, which asks for a new one before it expires. That means the **server** needs outbound HTTPS to the GitHub API, not just the agent (unless you're using agent-side profiles, in that case the agent itself handles the process and the server is not involved). **Test** checks the key, the installation, and how many repositories it can read.

An installation token belongs to no user, so a job on an App connection can't back up starred repositories or gists: name owners or repositories. An App installed on a personal account only sees that account's public repositories through the owner listing; list its private ones as repositories.

## 3. Keep the token on the agent (optional)

If the server shouldn't hold the token, create the connection without one and store the token in the agent's encrypted credential store:

```bash
fallbck-agent vcs profile create --name git-internal --url https://git.example.com --ask-token
fallbck-agent vcs profile list
fallbck-agent vcs profile test --name git-internal   # GitLab or GitHub: checks the token and records its expiry
```

The job then names the profile (`"profile": "git-internal"`). The agent only uses a profile for the URL it was created for, so the profile's `--url` must equal the connection's `base_url`. Use `--token-file` instead of `--ask-token` when a secret manager keeps the token in a file. `--username` sets the basic auth user name. `profile test` assumes GitHub for github.com and GitLab for everything else; add `--provider github` for GitHub Enterprise Server.

A profile can hold a [GitHub App](#github-app) too. The agent then mints the installation tokens itself and the key never leaves the host:

```bash
fallbck-agent vcs profile create --name gh-app --url https://github.com --auth github_app \
  --app-id 123456 --installation-id 7890123 --app-key-file /etc/fallbck/github-app.pem
fallbck-agent vcs profile test --name gh-app
```

The key file is read at every run, so you can rotate it in place. Add `--store-app-key` to copy it into the encrypted store instead. The agent signs the App's requests with its own clock, and GitHub refuses them when it's more than a minute or so off: keep NTP running. An App key reads every repository of the installation, so think twice before putting the same one on many agents; a separate App per agent or team keeps the blast radius small.

## 4. Create a job

In the web UI, open **Onboarding**, pick an existing agent and choose **Git repositories**. The form shows the GitLab fields or the repository list depending on the connection, and only offers agents that can run it. Edit the job later from **Backup Jobs**. Each run's page lists every repository with its status, size and any errors.

Through the API, a GitLab job selects projects by group:

```json
{
  "name": "gitlab",
  "agent_id": "<uuid>",
  "target_id": "<uuid>",
  "job_type": "vcs",
  "schedule_cron": "0 3 * * *",
  "vcs_config": {
    "connection_id": "<uuid>",
    "groups": ["platform", "data/pipelines"],
    "include_subgroups": true,
    "exclude": ["platform/sandbox", "*/playground-*"],
    "archived": true,
    "forks": false,
    "workloads": {"lfs": true, "wiki": true},
    "max_repo_size": 10737418240
  }
}
```

| Field | Default | |
|---|---|---|
| `groups` | all projects (see [tokens](#gitlab-tokens)) | Group full paths. A group that doesn't exist is a warning in the manifest; the run fails only when none of them exist. |
| `include_subgroups` | `true` | Also back up the projects of subgroups. |
| `exclude` | none | Globs on project paths. A match on a group path leaves out everything below it. |
| `archived`, `forks` | `true` | Include archived projects and forks. A fork is only recognised as one when the token can see the project it was forked from. |
| `workloads.lfs`, `workloads.wiki` | `true` | Fetch LFS objects; mirror project wikis. An enabled wiki without pages is skipped quietly. |
| `max_repo_size` | no limit | Skip repositories larger than this many bytes (LFS objects not counted). GitLab only reports sizes to tokens with at least the Reporter role. |
| `concurrency` | 4 | Repositories fetched at once. |

A GitHub job names owners, explicit repositories, starred repositories and gists in any mix:

```json
{
  "name": "github",
  "agent_id": "<uuid>",
  "target_id": "<uuid>",
  "job_type": "vcs",
  "schedule_cron": "0 3 * * *",
  "vcs_config": {
    "connection_id": "<uuid>",
    "groups": ["acme", "octocat"],
    "repositories": ["https://github.com/torvalds/linux"],
    "starred": true,
    "gists": {"own": true, "starred": true, "users": ["octocat"], "ids": ["https://gist.github.com/octocat/6cad326836d38bd3a7ae"]},
    "exclude": ["acme/scratch-*"],
    "forks": false,
    "workloads": {"lfs": true, "wiki": true, "metadata": true}
  }
}
```

| Field | Default | |
|---|---|---|
| `groups` | none | Organization or user logins. For an organization, every repository the token can see; for the token's own login, its repositories including private ones; for another user, their public repositories. |
| `repositories` | none | `https://github.com/<owner>/<name>` URLs. Always backed up: the filters don't apply. |
| `starred` | `false` | Every repository the token's user has starred. |
| `gists` | none | `own` (the token user's gists, secret ones included), `starred`, `users` (their public gists) and `ids` (ids or URLs). Gists are not filtered. |
| `exclude`, `archived`, `forks`, `max_repo_size` | as for GitLab | Globs on `owner/name`; apply to listed repositories, not to explicit ones. |
| `workloads.metadata` | `false` | Issues (with pull requests), issue comments, pull requests, review comments, releases, labels and milestones as JSON in `_metadata/`; for gists, the gist object and its comments. A list that fails is a warning and keeps its previous file. After the first run, issues, pull requests and comments only fetch what changed since the last run; once a week everything is listed again, which is when items deleted on GitHub drop out. |

Mirrors are kept by GitHub's repository id, so a renamed or transferred repository carries on from its mirror. API rate limits are waited out (up to an hour per request) instead of failing the run.

A plain git job lists its repositories instead:

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

`POST` either to `/api/v1/jobs`. Add `"profile"` to use an agent credential profile, and `"backup_id"` to choose the PBS group.

Mirrors of GitLab projects are kept by project id, so a renamed or moved project carries on from its mirror instead of being cloned again; the snapshot shows it under its new path. A project waiting for GitLab's delayed deletion is still backed up, under the path GitLab gives it meanwhile (`<name>-deletion_scheduled-<id>`), until it is removed for good.

## What lands on PBS

Each run writes **one snapshot** in the group `host/vcs-<connection name>`:

| Path | Contents |
|---|---|
| `vcs.pxar` → `<path>/repository.git/` | Bare mirror: branches, tags, `refs/merge-requests/*/head` (GitLab) or `refs/pull/*/head` (GitHub), LFS objects in `lfs/objects/`. `<path>` is the project's full path for GitLab (`platform/api`), `<owner>/<name>` for GitHub and `<host>/<path>` for plain git. |
| `vcs.pxar` → `<path>/wiki.git/` | The project wiki (GitLab and GitHub, when it has pages) |
| `vcs.pxar` → `<path>/_metadata/` | GitHub issues, pull requests, comments and releases as JSON (`metadata` workload) |
| `vcs.pxar` → `_gists/<owner>/<id>/` | GitHub gists: `repository.git/`, and `_metadata/` with the gist and its comments |
| `vcs.pxar` → `RESTORE.md`, `restore.sh` | How to restore, and a script that does it |
| `fallbck-vcs.json.blob` | The run manifest: every repository and how its fetch went, plus the GitLab version and the token's user |

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

This pushes all branches, tags and LFS objects. Merge and pull request refs stay in the backup: GitLab and GitHub don't accept pushes to them. For a gist, create a new gist and run `git --git-dir=_gists/<owner>/<id>/repository.git push --force <gist URL>.git HEAD:main`. To look at the code without a server, `git clone ./restore/git.example.com/team/app/repository.git`.
