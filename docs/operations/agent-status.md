# Agent status and updates

Click any hostname on the Agents page to get to **/agents/&lt;id&gt;**, which has everything about that agent on one page.

## What's on the page

- **Status**: an agent whose last heartbeat is older than 90 seconds shows as offline, whatever it last claimed.
- Last heartbeat, version compared with the server's, platform, task queue.
- **Alerts**, raised for:
    - the agent being offline or never seen
    - an agent version behind the server's
    - spool space below `min_free_bytes`
    - jobs this agent can't run: DB tools missing, not a PVE/Docker host, a credential profile it doesn't have or that's for another engine
    - jobs whose last run failed, or was **partial** (some units, volumes or users failed while the rest reached PBS)
- The credential profiles and client tools it reported.
- Its jobs with their last run, and its recent runs.

Agents send a compact summary with a heartbeat every five minutes: profiles, tools and versions, free space on spool and data dir, resource counts.

## Asking the agent directly

These two run as a Temporal activity on the agent's own queue, so the agent has to be online. The page tells you if it isn't.

- **Refresh inventory** pulls the full picture: settings, containers and volumes on a Docker host, namespaces and PVC counts on a cluster agent, the PVE node.
- **View logs** fetches the agent's buffered log lines.

The **Debug** toggle is here too. See [Troubleshooting](troubleshooting.md).

## Agent updates

When an agent falls behind the server's version, the Agents page and the status page show *v&lt;version&gt; available*. Linux agents can update themselves. There are two ways to set that off:

- **Auto-update: on**: a per-agent opt-in. The agent updates itself whenever it's behind.
- **Update now**: a one-off kick. It's picked up on the next heartbeat.

What happens under the hood:

1. The server downloads its **own** release's agent archive from GitHub (once per OS/arch), checks the checksum, and caches the binary in `<data_dir>/agent-releases/<version>/`. If GitHub is unreachable, the Agents page shows a banner and the server retries every 10 minutes.
2. The heartbeat answer tells the agent to update. If a backup is running, the agent waits until it's done. It never kills a run to update.
3. The agent downloads the binary from the server, checks the SHA-256, runs `<new> version` as a smoke test, swaps it in (the old one stays as `fallbck-agent.old`) and restarts itself.
4. If any of that fails, the error shows on the agent and it tries again an hour later.

!!! note "Who can't self-update"
    Containers, the Kubernetes agent and Windows agents. Their image or package owns the binary. They show *Cannot update itself* when they're behind. Upgrade the image, Helm release or MSI instead. Same goes for an agent whose binary directory isn't writable.

So your agents need to reach the server, and the server needs to reach `github.com`. That's all it takes.
