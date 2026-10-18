# Troubleshooting

## Turn up the logs

- **Server or agent:** `DEBUG=true` or `FALLBCK_LOG_LEVEL=debug`. Agents also take `log_level: debug` in `agent.yaml`.
- **A running agent, no restart:** hit **Debug** on the agent's status page. It goes out with the next heartbeat (about 30s) and applies live.

With debug on, the server logs every PBS session handshake (the upgrade request with datastore, snapshot and token id, never the secret, plus PBS's answer) and the embedded Temporal's info logs. The agent logs tunnel setup and credential fetches.

## Look at the run

Every run has a page at **/runs/&lt;id&gt;**. Get there from **Details** in the history list. While the backup's going it **updates live** (current phase, and for Kubernetes a per-PVC table filling in), then switches to the finished view:

- timing and transfer stats
- the full error
- the agent's log
- a type-specific section: per-archive sizes and chunks for files, per-database WAL/binlog/oplog info for DBs, a per-PVC table plus resource counts and warnings for Kubernetes
- the raw details JSON, for download

Every backup activity heartbeats its current phase every 15 seconds. When a run fails it records the phase it was in plus the agent's recent log lines, at all levels, even with debug off. A *heartbeat timeout* tells you the last phase the agent reached before it went quiet, which usually narrows things down nicely.

## PBS says no

API tokens go in as `user@realm!tokenid:secret`. The `=` form from the PBS token dialog works too and gets normalized.

| PBS says | Means |
|---|---|
| `401 authentication failed` | wrong token id or secret |
| `403` | missing privileges |

The token needs `Datastore.Backup` on the datastore or namespace, **and nothing else**. FallBCK never prunes, forgets or deletes on PBS, so don't hand it `Datastore.Prune` or `Datastore.Modify`. The target form shows what PBS reports for the token, and the dashboard flags tokens that hold more or less than that (see [The PBS token](../getting-started/production.md#the-pbs-token)). A *not checked* badge means the server couldn't ask PBS: hover it for the error, which is usually the same reachability or TLS problem a backup would hit.

## Agent shows offline

- An agent is offline after 90 seconds without a heartbeat. Check the service on the box (`systemctl status fallbck-agent`) and its logs.
- Agents hold 70-second long polls open. If your reverse proxy times out sooner, agents keep dropping. Set read timeouts above 90s (see [Production install](../getting-started/production.md#put-a-reverse-proxy-in-front)).
- Private CA? Make sure the agent trusts it (`server_ca_cert_path`).
