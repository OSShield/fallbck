# GitHub

Mirrors GitHub repositories with their wikis, issues, pull requests and releases. Any `fallbck-agent` can run these jobs as long as it has git 2.31 or newer and outbound HTTPS to `api.github.com` and `github.com` (or your GitHub Enterprise Server). The agent container image ships git.

## 1. Add an account

Under **GitHub Accounts**, add a token. A classic token needs `repo` (private repositories), `read:org` (organization repositories) and `read:user`. A fine-grained token needs read access to *Contents*, *Metadata*, *Issues* and *Pull requests* on the repositories it should see. For GitHub Enterprise Server, set the API URL to `https://<host>/api/v3`.

The token gets sealed on the server and handed to the agent per run with its backup ticket. git receives it as an HTTP header through the environment, scoped to the API's host, so it never shows up on a command line or in the mirror's config. **Test** reads `/user` from the server and shows the token's scopes.

Accounts use the `tenants` permissions, same as Microsoft 365 tenants.

## 2. Create a job

Pick an account and any mix of sources. The job backs up the union:

| Source | What it lists |
|---|---|
| Organizations | `GET /orgs/{org}/repos`, with an optional type (`all`, `public`, `private`, `forks`, `sources`, `member`). Write `acme:sources` in the form. A user entered here falls back to the repositories that user owns. |
| Users | The repositories a user owns. For the token's own login that includes private repositories. |
| Repositories | Explicit `owner/name` entries. These are always backed up, and the filters below don't apply. |
| Starred | Every repository the token's user has starred. |
| Gists | The token user's own gists (secret ones included), starred gists, the public gists of given users, and explicit gist ids or URLs. |

Then narrow repositories down with include/exclude globs on `owner/name`, *skip forks* and *skip archived* (gists aren't filtered). Choose the content: wiki, issues and pull requests (with comments), and releases (metadata only, not assets). Git LFS objects are fetched when you tick LFS and `git-lfs` is installed on the agent.

A typical setup is two jobs: your organizations and own repositories nightly, and starred repositories monthly (they can run to tens of GB) with issues switched off.

## What lands on PBS

Each run writes one snapshot **per repository**, each in its own group. The prefix is the job's group, which defaults to `github-<account name>` (override it with `backup_id`):

| Group | Archive | Contents |
|---|---|---|
| `host/<group>-<owner>-<name>` | `repo.pxar` | `repo.git/` (bare mirror: every branch, tag and pull request ref), `wiki.git/`, `metadata/*.json`, `RESTORE.md`, plus `fallbck-github-repo.json.blob` |
| `host/<group>-gist-<owner>-<id>` | `repo.pxar` | `repo.git/` (the gist's history), `metadata/gist.json`, `metadata/comments.json` |
| `host/<group>` | `index.pxar` | the run manifest listing every repository group, `account.json`, `RESTORE.md`, plus `fallbck-github.json.blob` |

A repository that gets deleted on GitHub keeps its history on PBS. One failing repository fails only itself: the run ends **Partial** and lists the failed repositories.

## Incrementals

The agent keeps the bare mirrors under `<data_dir>/github-state/<job>/`, so later runs only `git fetch` what changed. On pxar v2 targets, unchanged pack files are reused from the previous snapshot. Make room on the agent for every mirror of the job. Untick *keep mirrors* to clone from scratch every run and delete the clone afterwards, trading bandwidth for disk.

API rate limits are waited out (the primary limit up to an hour per call) instead of failing the run.

## Restore

Restore `repo.pxar` with the PBS UI or `proxmox-backup-client restore`, then:

```bash
git clone repo.git ./src                         # a working copy
git -C repo.git push --mirror <new remote URL>   # or everything to a new remote
```

Push `wiki.git` the same way to `<repo URL>.wiki.git` (create the first wiki page in the UI first). GitHub has no bulk import for issues and pull requests, so `metadata/` is for reference or scripted re-creation.

To recreate a gist, create a new one and run `git -C repo.git push --force <gist URL>.git HEAD:main`.

## Not covered

- release assets, Actions artifacts and logs, discussions, projects
- repository settings, webhooks, secrets and branch protection (`metadata/repository.json` has the basics)
