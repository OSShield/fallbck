# Agents and file backups

An agent is a small daemon on the box you're backing up. `fallbck-agent` covers files, databases, Proxmox VE nodes, Docker hosts and Microsoft 365. Kubernetes gets its own agent, [`fallbck-k8s-agent`](kubernetes.md).

## How an agent talks to the world

An agent needs exactly one thing: the server's public URL. That's it, no extra ports. With that URL it:

1. enrolls once with a one-time token and gets a long-lived bearer token back;
2. polls its own Temporal task queue through the server's gateway, so it never touches Temporal directly;
3. streams backups into PBS through a tunnel the server opens for it. The agent never holds the PBS credentials.

Tokens rotate on their own before they expire, so there's nothing to babysit.

## Onboarding

The easy way in is **Onboarding** in the Web UI. You'll also find it as *Add New Agent* on the Agents page and *Set Up Backups* on the Backup Jobs page. It starts with one question:

- **New agent**: pick the type and platform, then run the install and enroll commands it prints. The page waits until that exact agent shows up and reports what it can do.
- **Existing agent**: pick one that's already enrolled.

Either way you land in the job setup: backup type, PBS target (pick one, create one, or clone an existing one into another namespace), what to back up, schedule, review. At the end it creates the job and offers *Run now* so you can watch the first run go. Then it loops back so you can add the next one.

New jobs of every type get created here. The **Backup Jobs** page lists and edits them all, with filters for type, state, last run, agent, target and schedule. The flow keeps its state in the URL, so a reload picks up where you left off.

## Enrolling by hand

```bash
fallbck-agent enroll --server https://backup.example.com --token <enrollment token>
fallbck-agent run
```

Get the token from the Web UI or with `fallbck-ctl token create`. Packaged installs run `fallbck-agent run` as a service, so you just `systemctl enable --now fallbck-agent`.

Instead of running `enroll`, you can set `FALLBCK_AGENT_ENROLLMENT_KEY` (or `enrollment_key` in `agent.yaml`) and the agent enrolls itself on first start. That's the way to go for containers.

### Private CA or self-signed cert?

Pass `--ca-cert <pem bundle>` to `enroll`. For a quick test you can use `--insecure-skip-verify` instead, but don't ship that. Either setting is used for the enroll call and saved in `agent.yaml` (`server_ca_cert_path` / `insecure_skip_verify`). The Kubernetes agent takes the same thing as Helm values `server.caCert` / `server.insecureSkipVerify`.

## File backups

A file job takes one or more paths plus optional excludes.

**Archive layout.** Each job writes one `root.pxar`:

- one path: that directory gets archived directly;
- several paths: each one sits at the top level under its basename (`/etc` → `etc`). If two share a basename they get named after the full path instead (`/etc/mydir` → `etc-mydir`, `/var/lib/mydir` → `var-lib-mydir`).

**Excludes** use the same syntax as `proxmox-backup-client --exclude`: `*.tmp`, `/var/cache` (anchored to the backup path), `**/node_modules`. They're recorded in the archive just like the official client does it, and `.pxarexclude` files in the tree are honored too. With several paths, patterns match against the archive-relative path, so a root stored as `etc-mydir` gets matched as `/etc-mydir/...`.

### Incremental runs on pxar v2

On a **pxar v2** target the agent does metadata change detection, the same thing as `proxmox-backup-client --change-detection-mode metadata`:

- It keeps a copy of each upload's metadata stream under `<data_dir>/pxar-cache/`.
- Next run, it checks that copy against the previous snapshot's index on PBS.
- Files whose size, mode, owner, mtime, xattrs and ACLs haven't changed don't get read again. Their chunks are reused.

Runs of unchanged files get re-read only if the boundary chunks would drag in more than 10% unrelated bytes. The run page shows how many files were reused. No cache (first run, pruned snapshot, different agent)? You get a full read, no harm done.

## Direct PBS access

By default everything goes through the server. If an agent has a better path to PBS than the server does (same rack, same LAN), flip on **direct PBS** for that job (`direct_pbs` in the API). For each run, the agent then fetches the target's endpoint, fingerprint and API token, and talks to PBS itself. It only works on jobs that have the flag set, so you can't turn it on from the agent side.
