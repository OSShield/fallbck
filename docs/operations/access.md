# Access control

Who can do what is decided by **roles**, **bindings** and **labels**. There's no implicit admin: no binding means no access, even for someone your IdP happily signs in.

## The first sign-in

On a fresh server there are no bindings. The first person who signs in with a verified email gets the built-in `admin` role on everything, and the audit log says so (`auth.bootstrap`). Make sure that's you. Do it right after the server comes up, or keep `allowed_groups` / `allowed_emails` set until you have.

"Verified" is your IdP's call. If the ID token says `email_verified: false`, user bindings on that email never match, and that includes the first-sign-in promotion. Keycloak does this for any user whose email was never verified: flip *Email verified* on the user, or bind a group instead. A missing `email_verified` claim counts as verified (Entra ID leaves it out). The login page tells you when this is what's going on.

After that, everyone else needs a binding before they can sign in. Someone without one gets "Your account has no role on this server" and an `auth.denied` line in the audit log, which is handy when they ping you about it.

Upgrading from a version without RBAC? Existing API keys keep working as `admin` on everything. Sessions don't: the first sign-in after the upgrade bootstraps as above, so sign in yourself before anyone else does.

## Roles

A role is a named set of permissions. Three ship with the server and can't be edited:

| Role | What it does |
|---|---|
| `admin` | Everything, including access management and API keys. |
| `operator` | Reads everything. Creates, runs and deletes jobs. Manages agents, enrollment tokens, targets and tenants, but can't delete them, reveal PBS credentials or export keys. |
| `viewer` | Reads everything. |

Need something else? Clone one on the *Access* page and tick the boxes. Permissions are `resource:action`:

| Resource | Actions |
|---|---|
| `agents` | `read`, `write` (debug, updates, logs, inventory, merge, labels), `delete`, `enroll` (enrollment tokens and onboarding) |
| `jobs` | `read` (the job and all its runs), `write`, `run` (run and cancel), `delete` |
| `targets` | `read`, `write`, `delete`, `credentials` (reveal the PBS token) |
| `keyrings` | `read`, `write` (create, rename, master key, rotate, import), `export`, `delete` |
| `tenants` | `read`, `write`, `delete` |
| `apikeys` | `manage` |
| `rbac` | `manage` |
| `audit` | `read` |
| `temporal` | `ui` (the Temporal Web UI; admin only by default, see below) |

Runs don't have permissions of their own. If you can see a job, you can see its runs.

## Labels and bindings

Agents, targets, jobs, M365 tenants, key rings and enrollment tokens carry **labels**: `key=value` pairs, Kubernetes syntax, up to 20 per object. Every form has a labels box, one pair per line.

A **binding** grants a role to a subject on a **selector**. The subject is one of:

- **user**: a verified email,
- **group**: a value of the groups claim (`oidc.groups_claim`, default `groups`),
- **claim**: a value of another ID token claim, written `claim=value`. The server only reads the claims listed in `oidc.binding_claims`, which defaults to `roles`. That's what Entra ID app roles show up as, so `roles=Backup.Admin` works out of the box.

The binding form suggests the emails, groups and claim values earlier sign-ins have shown, refused ones included. So when someone new can't get in, their groups are already in the list.

The bindings list shows when each subject last turned up at a sign-in, and marks it **stale** after 90 days without one. A stale user binding is usually someone who left, so have a look and remove it. A stale group might just be quiet.

### Selectors

A selector is a comma-separated list of clauses, and every clause has to hold:

| Clause | Matches objects that |
|---|---|
| `team=web` | have `team` set to `web` |
| `team!=web` | don't have `team=web`, including objects without a `team` label |
| `env in (prod, stage)` | have `env` set to one of those |
| `env notin (dev, test)` | don't have `env` set to one of those, including objects without `env` |
| `managed` | have a `managed` label, whatever its value |
| `!legacy` | have no `legacy` label |

An empty selector matches everything. It's the same syntax as Kubernetes label selectors. The form shows how the server reads what you type before you save.

!!! warning "`!=` and `notin` match unlabelled objects"
    `team notin (finance)` also covers every object with no `team` label at all. That's how Kubernetes does it, and it's usually not what you want for access. Pair it with `team` (has a team) when it matters: `team, team notin (finance)`.

Old API clients that send a selector as an object (`{"team": "web"}`) still work. It's read as `team=web`.

Bindings add up. Give `team-web` the `operator` role on `team=web` and `viewer` on everything, and they can run their own jobs and look at everyone else's.

Out-of-scope objects simply don't exist for you. Lists leave them out and direct links return 404, the same as a deleted object. The filtering happens in the SQL query, so nothing leaks through a page you happen to have open.

A few rules keep scopes honest:

- **Relabelling needs write on both sides.** You can't move an object out of your scope, or someone else's into it.
- **A job needs its pieces.** Creating or editing one needs `jobs:write` on its labels plus `agents:read` on the agent, `targets:read` on the target and `tenants:read` on the M365 tenant.
- **Key rings are shared.** Attaching a target to a ring needs `keyrings:read` on it. Turning on encryption without picking a ring creates one with the target's labels, which needs `keyrings:write` on those. Rotate and export are ring permissions because they hit every target on the ring.
- **Some permissions are global only.** A role with `rbac:manage`, `apikeys:manage` or `temporal:ui` can only be bound with an empty selector. The first two would let a scoped admin grant themselves more. The Temporal UI shows every workflow regardless of labels. A custom role that still has one of them on a scoped binding from before simply doesn't get that permission.
- **The last global access admin can't be removed.** Add another binding first.

Changes land within 30 seconds. Sessions re-check their bindings on every request through a short cache, so removing someone's binding doesn't wait for their 12-hour session to run out.

!!! note "rbac:manage is the keys to the kingdom"
    Whoever can edit roles and bindings can give themselves anything. Treat it like `admin`.

### Enrollment tokens

Put labels on an enrollment token and every agent enrolled with it gets them. That's how a Helm install or an install-script run lands in the right scope without a second step. The agent can't pick its own labels: they come from the token, full stop.

The onboarding page has a labels box on the install step. It goes on the token, and new targets and jobs in the flow start with the same labels.

Jobs don't inherit an agent's labels on the server. Set them on the job. Onboarding prefills them from the agent so you don't have to think about it.

## API keys

An API key has exactly one role and one selector. You can't mint a key that reaches further than you do: every permission of the role has to be one you already hold on a selector the key's selector narrows. A `viewer` key on `team=web` is fine for a team operator, while an `admin` key on everything isn't.

Only `apikeys:manage` can create keys, so keys can't spawn keys behind your back either.

## Audit log

Every change, credential reveal, key export, sign-in, refused sign-in and access change goes into an append-only table. The *Audit Log* page filters by actor, action, resource and date, and exports CSV.

Each entry keeps the labels the object had at the time. `audit:read` is scoped like everything else, so a team sees its own trail and not the rest.

The table refuses `UPDATE` and plain `DELETE`, including from the server's own database user.

### Retention and export

Once a day the server deletes entries older than `audit.retention` (a year by default, `0` keeps everything). Before deleting, it hands them to `audit.export` if you set one:

```yaml
audit:
  retention: 8760h
  export: /var/log/fallbck/audit.jsonl        # appended, one JSON object per line
  # export: https://logs.example.com/ingest   # POSTed as application/x-ndjson
  # export_headers: {Authorization: "Splunk <token>"}
  # export: udp://syslog.example.com:514      # or tcp://, or syslog: for the local daemon
```

A batch is only deleted once the export took it. If the export fails, nothing is deleted and the server tries again the next day. A batch can occasionally be exported twice, if the server dies right between export and delete, so dedupe on `id` if that matters to you.

Each prune writes its own `audit.prune` entry with the cut-off, the count and where the rows went. A bad `audit.export` stops the server at startup, so you find out straight away rather than a year later.

## Dev mode

With `auth.insecure_disable` (only under `--dev`), every request is the global admin. API keys aren't even looked at.

## Known gaps

- The Temporal UI isn't scoped, which is why `temporal:ui` is global only. It's also read-only by default (`temporal.ui.read_only`). Turn that off and whoever can open it can terminate or cancel any workflow.
- A key ring's list of attached targets shows every target name on the ring, scoped or not.
- Groups and claims come from the sign-in and live in the session. Someone removed from a group at your IdP keeps that group's access until their session ends (12 hours by default). Removing the *binding* takes effect within 30 seconds.
- There's no directory sync (SCIM or Graph). Suggestions only know what sign-ins have shown.
