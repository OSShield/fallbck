# Remote storage

Backs up storage that lives somewhere else: S3 buckets, Azure Blob containers, Azure Files shares, and SFTP, SMB, FTP and WebDAV servers. Any `fallbck-agent` that can reach the storage runs the job. It lists what's there and reads every object into PBS. It never writes, renames or deletes anything on the remote.

| Backend | `backend` | A root is |
|---|---|---|
| S3 (AWS, MinIO, Wasabi, Cloudflare R2, anything S3-compatible) | `s3` | `bucket` or `bucket/prefix` |
| Azure Blob Storage | `azureblob` | `container` or `container/prefix` |
| Azure Files | `azurefiles` | `share` or `share/path` |
| SFTP (also [Hetzner Storage Box](#hetzner-storage-box)) | `sftp` | an absolute path on the server, without the leading `/` |
| SMB / CIFS | `smb` | `share` or `share/path` |
| FTP / FTPS | `ftp` | an absolute path on the server, without the leading `/` |
| WebDAV (Nextcloud, ownCloud, SharePoint, …) | `webdav` | a path below the remote's URL |

This is a beta. Set it up in the web UI (**Remotes**, then **Onboarding → Remote storage**) or through the [API](../reference/api.md#remotes); both are shown below.

## 1. Prepare the agent

Nothing to install: the backends are built into `fallbck-agent` (it uses [rclone](https://rclone.org) under the hood). The agent reports which backends it has with its heartbeat. An agent from before remote jobs reports none, and the server won't give it a remote job until you update it.

The agent needs a network path to the storage. The server doesn't: it never connects to a remote itself.

## 2. Use a read-only credential

The agent only lists and reads, so give it a credential that can't do anything else. If the server or the agent is ever compromised, a read-only key can't wipe your buckets.

**S3.** An IAM policy that lists and reads the buckets the job backs up:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": ["s3:ListBucket", "s3:GetBucketLocation"],
      "Resource": ["arn:aws:s3:::photos", "arn:aws:s3:::archive"]
    },
    {
      "Effect": "Allow",
      "Action": ["s3:GetObject"],
      "Resource": ["arn:aws:s3:::photos/*", "arn:aws:s3:::archive/*"]
    }
  ]
}
```

A job that backs up every bucket (no `roots`) also needs `s3:ListAllMyBuckets` on `"Resource": "*"`, and the second statement's resources become `arn:aws:s3:::*/*`.

MinIO takes the same policy (`mc admin policy create`). Wasabi and R2 have their own read-only key options; use those.

**Azure Blob.** Either the account key, which can do everything (but generally don't do that, use a read-only key), or a SAS URL, which can be limited:

- **Allowed services:** Blob
- **Allowed resource types:** Container and Object, plus Service if a job backs up every container
- **Allowed permissions:** Read and List, nothing else
- An expiry date you'll remember to renew. The agent can't warn you about it.

The SAS has to be for the remote's own storage account.

**Azure Files.** The same as Blob, with **File** as the allowed service and Container and Object as the resource types. A SAS made for Blob doesn't work on Files.

**SFTP, SMB, FTP and WebDAV.** A user with read access to the paths. On SFTP, that's a password or an unencrypted private key.

## 3. Create a remote

A remote is the storage endpoint and, optionally, the credential to read it with. The credential is only ever sent to that endpoint.

In the web UI: **Remotes → Add Remote**. Or through the API:

```bash
curl -X POST https://fallbck.example.com/api/v1/remotes \
  -H "Authorization: Bearer $FBK_KEY" -H "Content-Type: application/json" \
  -d '{"name": "minio", "backend": "s3", "endpoint": "https://minio.example.com:9000", "path_style": true,
       "secrets": {"access_key_id": "AKIA...", "secret_access_key": "..."}}'
```

| Backend | Fields |
|---|---|
| `s3` | `provider` (`AWS`, `Minio`, `Wasabi`, `Cloudflare`, `Other`; left empty it's AWS without an endpoint and Other with one), `region`, `endpoint` (empty for AWS), `path_style` (MinIO and most self-hosted S3 want it). Secrets: `access_key_id`, `secret_access_key`. |
| `azureblob`, `azurefiles` | `account`, `endpoint` (empty for Azure itself). Secrets: `account_key` or `sas_url`. |
| `sftp` | `host`, `port` (default 22), `user`, `known_hosts` (required). Secrets: `password` or `key_pem`. |
| `smb` | `host`, `port` (default 445), `user`, `domain`. Secrets: `password`. |
| `ftp` | `host`, `port` (default 21, or 990 with implicit TLS), `user`, `tls` (`explicit`, the default, `implicit` or `none`). Secrets: `password`. |
| `webdav` | `url`, `vendor` (`nextcloud`, `owncloud`, `infinitescale`, `sharepoint`, `sharepoint-ntlm`, `fastmail`, `rclone`, `other`), `user`. Secrets: `password` or `bearer_token`, or none. |

The credential is sealed on the server and handed to the agent per run with its backup ticket. The API never returns it.

!!! warning "SFTP needs the server's host keys"
    The agent won't talk to an SFTP server it can't verify. Put the server's keys in `known_hosts`, one `<type> <base64>` per entry. Get them with `ssh-keyscan -p 22 sftp.example.com`, or let `fallbck-agent remote profile test` fetch and print them (step 4). Compare the fingerprint with the server's before you trust it.

!!! warning "FTP sends the password in clear text unless you use TLS"
    Keep `tls` on `explicit` (or `implicit`, if that's all the server does). The certificate has to be valid for the host and trusted by the agent's system. There's no option to skip that check, so a server with a self-signed certificate is refused. Put its CA in the agent's system trust store, or give the server a real certificate. Use `none` only on a network you trust with the password.

### Hetzner Storage Box

A Storage Box is SFTP on port 23, so it's an `sftp` remote. In the web UI, enter the user (`u123456`, or a sub-account like `u123456-sub1`) and click **Hetzner Storage Box**, which fills in the host and port. Through the API:

```json
{"name": "storagebox", "backend": "sftp", "host": "u123456.your-storagebox.de", "port": 23,
 "user": "u123456-sub1", "known_hosts": ["ssh-ed25519 AAAA..."]}
```

- A sub-account logs in on its main account's host and sees only its own directory. Give the job a sub-account with read-only access, not the main account.
- Get the host keys with `ssh-keyscan -p 23 u123456.your-storagebox.de`, and check them against the fingerprints Hetzner publishes.

The **Test** button on the Remotes page doesn't connect to anything, because the server has no route to your storage and shouldn't need one. It shows the agent commands that test the remote from where the job will run.

## 4. Keep the credential on the agent (optional)

If the server shouldn't hold the credential, create the remote with `"auth_method": "agent"` and no secrets. Then store the credential in the agent's encrypted store:

```bash
fallbck-agent remote profile create --name minio --backend s3 \
  --endpoint https://minio.example.com:9000 --access-key-id AKIA... --ask-secret
fallbck-agent remote profile list
fallbck-agent remote profile test --name minio --root photos
```

Every job on that remote then names the profile (`"profile": "minio"`). Any other job can name one too, and the server then never hands that job the remote's credential.

The agent only uses a profile for the endpoint it was created for. If someone changes the remote to point somewhere else, the agent refuses to send the credential there, and the run fails before it reads anything. What `--endpoint` takes:

| Backend | `--endpoint` |
|---|---|
| `s3` | the endpoint URL, or `aws` for AWS (any region) |
| `azureblob`, `azurefiles` | the storage account name, or the blob or file service URL |
| `sftp`, `smb`, `ftp` | `host` or `host:port`. For FTP with implicit TLS, `host:990`. |
| `webdav` | the server URL (only scheme, host and port count) |

Where the credential comes from:

- `--ask-secret` prompts for the backend's usual secret: the S3 secret access key, the Azure account key, or the password. It reads one line from standard input when piped.
- `--ask-sas-url` (Azure Blob and Files) and `--ask-token` (WebDAV) prompt for the alternatives.
- `--secret-file` reads that secret from a file at every run, so a secret manager can rotate it in place.
- `--key-file` (SFTP) reads a private key at every run. Add `--store-key` to copy it into the store instead.
- `--env-auth` (S3) stores nothing and uses the agent's environment or instance role: `AWS_ACCESS_KEY_ID` and friends, an EC2 instance profile, or IRSA.

### Import from rclone.conf

Already using rclone on that machine? Import a remote from its config instead of typing it in again:

```bash
fallbck-agent remote profile create --name minio --from-rclone-conf ~/.config/rclone/rclone.conf
```

The section defaults to `--name`; pick another with `--section`. The import takes the backend, the endpoint and the credential, and reveals rclone's obscured passwords. An encrypted config opens with `RCLONE_CONFIG_PASS`, or the agent asks for the password. Flags you add win over the section, so `--secret-file` or `--env-auth` replace its secret. The credential is copied into the store, so later changes to rclone.conf don't reach the profile. An SFTP `key_file` is still read at every run, unless you add `--store-key`. If the section has both a key and a password, the profile keeps the key.

It then prints the matching remote as JSON for `POST /api/v1/remotes`, with `auth_method` set to `agent`. Its endpoint is the one the profile is bound to. For SFTP, you still need to fill in `known_hosts`.

It only imports sections of type `s3`, `azureblob`, `azurefiles`, `sftp`, `smb`, `ftp` and `webdav`, and refuses anything it can't do the same way. That covers wrapper remotes such as `crypt` and `alias` (import the section they point to), S3 profiles and session tokens, Azure managed identities and service principals, SFTP through an `ssh` command, an agent or an encrypted key, Kerberos on SMB, and FTP with `no_check_certificate`. S3 providers other than AWS need `endpoint` written out, because rclone fills it in itself. Azure endpoints in the emulator form (`<url>/<account>`) aren't accepted, the same as for remotes.

`profile test` opens the root the way a run would and lists the first ten entries. Give it what the remote has that the profile doesn't: `--root`, plus `--user`, `--region`, `--domain` or `--tls` (FTP) where they apply. For an Azure endpoint URL, `--user` is the account name. For SFTP, pass the server's key with `--host-key`. Without it, the agent fetches the key, prints its fingerprint and trusts it for that one test.

The agent's status page warns when a job names a profile the agent doesn't have, a profile made for another endpoint, or a backend the agent can't read.

## 5. Create a job

In the web UI, open **Onboarding**, pick an existing agent and choose **Remote storage**. The form only offers agents that can read the remote's backend. Edit the job later from **Backup Jobs**.

Through the API:

```json
{
  "name": "photos",
  "agent_id": "<uuid>",
  "target_id": "<uuid>",
  "job_type": "remote",
  "schedule_cron": "0 2 * * *",
  "remote_config": {
    "remote_id": "<uuid>",
    "roots": ["photos", "archive/2026"],
    "exclude": ["tmp", "*.part"],
    "split": "single"
  }
}
```

| Field | Default | |
|---|---|---|
| `roots` | every bucket, container or share; the whole remote on SFTP, FTP and WebDAV; required on Azure Files | What to back up (see the table at the top). Roots can't overlap. |
| `include` | everything | Globs on paths below a root. `*` doesn't cross `/`. A pattern that matches a directory takes everything below it. |
| `exclude` | nothing | Same syntax. Excludes win over includes. |
| `split` | `single` | `single`: one snapshot per run, each root a directory in it. `per_root`: one snapshot group per root. |
| `backup_id` | `remote-<remote name>` | The job's PBS group. |
| `profile` | none | An agent credential profile (step 4). Required when the remote keeps its credential on the agents. |

`POST` it to `/api/v1/jobs`.

Leave `roots` out on S3, Azure or SMB and the job backs up every bucket, container or share the credential can see. The agent lists them again at the start of every run, so a new bucket is in the next backup without touching the job, and a deleted one just drops out. SMB shares ending in `$` (`IPC$`, `C$`) are skipped. The credential needs the right to list them; see step 2. Azure Files can't do this yet: name the shares. There's no way to exclude a bucket yet, so give the job a credential that only sees what you want backed up, or list the roots.

## What lands on PBS

With `split: single`, each run writes **one snapshot** in `host/remote-<remote name>`:

| Path | Contents |
|---|---|
| `remote.pxar` → `<root>/…` | The objects of each root, under the root's path (`photos/…`, `archive/2026/…`). A whole-remote root sits at the top. |
| `fallbck-remote.json.blob` | The run manifest: the remote (never its credential), each root's object and byte counts, warnings |

With `split: per_root`, each root gets its own group, `<job group>-<root>`, with `/` turned into `-`: `remote-minio-photos`, `remote-minio-archive-2026`. Each of those snapshots has the root's objects at the top of `remote.pxar`, plus a manifest for that root. The job's own group gets a small snapshot with an empty archive and the run manifest, which lists every root's snapshot. Use this when roots are big and you want to prune or restore them separately.

Objects keep their size and modification time. On S3 that's the listing's `LastModified`, so the agent doesn't have to ask about every object separately. Directories all get the same fixed time, since object stores don't have real ones. Use a **pxar v2 target**: objects that didn't change since the last run are referenced from the previous snapshot instead of being read again. Without v2, every run downloads everything.

## When something fails

- An object whose key can't be a path (`a//b`, `a/./b`) is skipped with a warning.
- An object that changes size between listing and reading is cut or padded with zeros to the listed size, with a warning. The next run picks up the new version.
- A root that can't be opened or listed fails on its own, and the rest carry on.
- In a job without roots, a failed bucket listing fails the run (it's retried like any other failure), and finding no buckets at all makes it partial.
- Any warning or failed root makes the run **partial**. The run fails only when no root could be backed up.
- With `per_root`, two discovered names that make the same group (SMB shares `Data` and `data`) can't share it: the second one fails, and the run is partial.
- With `per_root`, a retry of the same run skips the roots that already finished, so a timeout on root nine doesn't redo roots one to eight. Progress is kept in `<data_dir>/remote-state/<job id>/run.json`. The next scheduled run starts from scratch.

Roots run one after another. Each run's page lists every root with its status, size, snapshot and any error.

## Restore

There's no restore tool yet: restore the archive, then copy it back with whatever you like.

```bash
proxmox-backup-client restore host/remote-minio/<time> remote.pxar ./restore
rclone copy ./restore/photos minio:photos-restored
```

`aws s3 sync`, `azcopy`, `smbclient` or plain `scp` work just as well. For a `per_root` job, restore from the root's own group (`host/remote-minio-photos/<time>`), where the objects sit at the top of the archive.
