# Security

A backup server is a prime target for attackers. It normally reaches every edge of the environment that you care about, and an attacker who owns it can quietly wipe your backups before they hit production. 

FallBCK is built on the assumption that the server, an agent or an admin account will get popped someday. This page walks through what each piece can and can't do when that happens.

## PBS stays in charge of your backups

- **Backup rights only.** The PBS API token FallBCK uses/needs `DatastoreBackup` and nothing else. That lets it write new snapshots and *read* back the groups it owns. It can't delete, prune or forget snapshots, change ACLs, or touch groups it didn't write.
- **It checks your token.** Each target's token is checked against PBS's own permission answer. Anything beyond `Datastore.Backup` inside the target's datastore shows up as a warning on the target, privilege and path included. If you handed it `Admin` on `/` to get going, you will be warned.
- **FallBCK never deletes anything on PBS.** Retention is handled by PBS prune jobs. A compromised FallBCK server can write junk snapshots, but your existing ones stay put.
- **Plain pxar.** Snapshots are the same format `proxmox-backup-client` writes, so you can restore with PBS's own tools when FallBCK is down or gone (or use our upcoming CLI).

## Agents never hold PBS credentials

By default agents never see a PBS token or a PBS address. They send everything through a tunnel on the server:

- For each run the server creates a **backup ticket**, a short-lived JWT that names the agent, target, datastore, namespace and snapshot. The agent can't pick any of those.
- The server opens the PBS session for exactly that snapshot and just pipes the bytes over to PBS. It doesn't parse the backup protocol, and on an encrypted target the bytes it pipes are ciphertext.
- Jobs that write several snapshots (M365, Kubernetes volumes) mint a sub-ticket for each one. A sub-ticket's group has to extend the job's group, so an agent can't write into another job's snapshots.

The exception is **direct PBS** (`direct_pbs`). It's a per-job switch you flip on the server, and only then does the agent get the target's token for that run. An agent can't turn it on for itself.

## Agents only dial out

- **No inbound ports.** Agents connect to the server's public URL. The server never connects to them, so you don't open anything towards your hosts.
- **Limited Temporal access.** Agents are Temporal workers, but they never reach Temporal directly. The gateway checks the agent's token and only lets through the few calls an activity worker needs. Each agent can only poll its own task queue. Embedded Temporal listens on `127.0.0.1` by default.
- **Enrollment.** A new agent enrolls with an enrollment token that's good for one use and 24 hours unless you say otherwise. Its labels come from that token and later from the server, never from the agent itself, so it lands in the access scope you picked.
- **Agent tokens.** They're bound to the agent's queue and a token version, checked against the database for revocation (30s cache), and rotated by the agent before they expire.
- **Signed updates.** Agent updates come from signed releases. The server checks the Sigstore signature on the release checksums before it mirrors a release, and the agent checks the signature and the binary's checksum again before it swaps itself out.

## Encryption happens on the agent

With [client-side encryption](encryption.md) on a target, chunks and blobs are encrypted on the agent before they leave the host, and the manifest is signed. PBS and the server's tunnel only ever see ciphertext.

- The key is sealed with the server's master key. The agent fetches it with its backup ticket and keeps it in memory for that run only. It never lands in a pod spec, Temporal history or a log. Only its fingerprint does.
- An agent refuses to upload plaintext to an encrypted target.
- Admins only get a key out as a passphrase-protected key file, and exports land in the audit log.
- With an **RSA master key** on the target, FallBCK stores only the public half. Each snapshot carries its key wrapped with it, and the private key that unwraps it never comes near FallBCK.

Let's be straight about the limitation here: the server holds the encryption keys, because it hands them to agents. That keeps PBS, the network between agent and PBS, and anyone with only the datastore from reading your data. It doesn't keep out someone who owns the server *and* its master key. Unfortunately, PBS does not support asymmetric encryption of data (yet).

## Secrets at rest

- **Master key.** PBS tokens, encryption keys, Microsoft 365 client secrets and certificate private keys, and VCS tokens and GitHub App keys are all sealed with the server's master key (AES-256-GCM). The master key lives in a file or an environment variable, not in the database, so a database dump on its own doesn't give them up.
- **Hashed tokens.** API keys and enrollment tokens are stored as hashes. You see the raw value once, when it's created.
- **Redacted job specs.** Database passwords are stripped out of the job spec that goes to the agent. The agent fetches them with its ticket at run time, so they never sit in Temporal history.

## Credentials that never touch the server

Sometimes the server shouldn't know a credential at all. Keep it on the agent:

- **Database credential profiles** ([Databases](../agents/databases.md)) and **VCS credential profiles** ([Git repositories](../agents/vcs.md)), including GitHub App keys, live in the agent's encrypted store. That's AES-256-GCM, with the key in a 0600 file that's also wrapped with DPAPI on Windows. The server only learns the profile names.
- A VCS profile only works for the URL it was made for. So a compromised server can't point a job at its own host and harvest the token.
- Databases can also use passwordless local auth, where there's no secret at all.
- **Kubernetes** jobs read database credentials from Secrets in the cluster. They only read Secrets labelled `fallbck.io/allow-db-credentials: "true"`, and only to reach a Service in the same namespace. Worker pods get short-lived credentials from a per-run Secret and have no Kubernetes API access.
- **Coming soon: Microsoft 365 credential profiles.** Today a tenant's secret or certificate key is sealed on the server and handed to the agent for each run ([Microsoft 365](../agents/m365.md)). Profiles will keep it in the agent's encrypted store instead, like databases and Git.

## Who can do what

- **SSO only.** Admins sign in through OIDC. There are no local passwords to leak, and SSO is always free, never in a paid tier (we don't even have a paid tier, and we never will).
- **No implicit admin.** Access is RBAC with labels: roles, bindings and selectors. Someone your IdP signs in still gets nothing without a binding. Out-of-scope objects are filtered in the SQL query and return 404. Details in [Access control](access.md).
- **Scoped API keys.** An API key has one role and one selector, and can't reach further than the person who made it.
- **Sensitive actions have their own permissions.** Revealing a PBS token and exporting a key each need their own permission. The built-in `operator` role has neither.
- **Revocable sessions.** Sessions live on the server. Revoking one, or signing a user out everywhere, takes effect within 30 seconds.
- **No token swapping.** Session cookies, agent tokens, backup tickets and login state are all JWTs, each with its own audience, so you can't use one as another.
- **CSRF protection.** Cookies are `HttpOnly` and `SameSite=Lax`, and browser requests that change something need an `X-Requested-With` header.

## Audit log

Every change, credential reveal, key export, sign-in and refused sign-in goes into the audit log. A trigger on the table refuses `UPDATE` and `DELETE` for every database role, the server's own included. The one exception is the server's scheduled prune of old entries, which can export them to a file, an HTTP endpoint or syslog first. Nothing is deleted until that export has gone through.

That stops mistakes and casual tampering, not someone who holds the server's database credentials: they can switch the trigger off. If you need a trail an attacker on the server can't touch, ship it somewhere else.

## No phoning home

At runtime the server and agents talk to PBS, your IdP and whatever you back up (Microsoft 365, GitLab, GitHub). On top of that, the server fetches its matching agent release from GitHub so agents can update themselves. There's no telemetry and no license server.

## What you still have to protect

- **The master key and the database together.** With both, someone has every sealed secret. Back the master key up somewhere other than the backup server, and don't store it next to the database dumps.
- **Encryption key files.** Export them and keep them offline, with their passphrases.
- **`rbac:manage`.** Whoever holds it can give themselves anything. Treat it like `admin`.
- **The Temporal UI.** It isn't scoped by labels, which is why `temporal:ui` is global only. Leave it read-only (`temporal.ui.read_only`, the default).
- **Direct PBS.** It trades the tunnel for a token on the agent. Only turn it on for agents you trust with that target.

Found a hole? See [SECURITY.md](https://github.com/osshield/fallbck/blob/main/SECURITY.md) for how to report it.
