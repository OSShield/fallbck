# Encryption

Turn on **Client-side encryption** on a PBS target (or `encryption_mode: encrypt` in the API) and every snapshot written there is encrypted on the agent before it leaves the host. It's the same thing `proxmox-backup-client --keyfile` does:

- chunks and manifest blobs are AES-256-GCM,
- the manifest is signed,
- PBS only ever sees ciphertext. You'll get the lock icon on the snapshot.

Keys live on **key rings**. A target is attached to one ring and encrypts with the ring's active key, so every job and host writing to that target deduplicates against each other. Several targets can share a ring, and should when they're namespaces of the same datastore: PBS dedups per datastore, and an encrypted chunk's digest depends on the key, so two namespaces with different keys store the same file twice. Targets on different PBS servers or datastores never share chunks anyway, so give those their own rings.

When you enable encryption on a target without picking a ring, you get a new ring named after the target. Pick an existing ring instead to share its key. Cloning a target keeps its ring.

## Where the key lives

The server generates the key when you enable encryption and stores it sealed with the **server master key** (`security.master_key_file`, default `<data_dir>/master.key`, or `FALLBCK_MASTER_KEY` in containers). That same master key also seals the targets' PBS API tokens.

Agents fetch the key per run with their backup ticket and keep it in memory for that run only. An agent refuses to upload plaintext to an encrypted target. Kubernetes worker pods fetch it the same way. The key never shows up in a pod spec, in Temporal history or in logs. Only its fingerprint does.

## Export the key file. Now.

!!! danger "Seriously, do this first"
    Without the key file, or the server database **plus** its master key, nothing on that target can be restored. Not by you, not by anyone.

Hit *Export key file* on the target form. You get a passphrase-protected (scrypt) key file in `proxmox-backup-client` format (the passphrase needs 12 characters or more), named after the target and key fingerprint. Keep it, and its passphrase, somewhere that isn't the backup server. Onboarding won't let you past a freshly encrypted target until you've downloaded it.

Restore with:

```bash
proxmox-backup-client restore --keyfile <file> ...
```

The restore commands in the run manifests assume you've got the key file at hand.

### Belt and braces: RSA master key

Optionally paste an **RSA master public key** (2048 bits or more) on the target. Every snapshot then also carries the encryption key wrapped with it, so if the key file goes missing, the private key can still get the data back (`proxmox-backup-client key import-with-master-key`).

## Rotation, import, disabling

All of these act on the ring, so they apply to every target attached to it.

- **Rotate key** makes a new key. The old one is retired, not deleted, because the snapshots written with it still need it. It stays exportable by fingerprint. New snapshots won't dedup against old ones.
- **Import key file** adopts a key from `proxmox-backup-client` or another ring. To make two existing targets share a key, attach one to the other's ring instead; it's the same thing without the file.
- **Disabling** encryption on a target keeps it attached to its ring, for the same reason. Re-enabling picks up where it left off.
- **Deleting a ring** only works once no target uses it. It takes the ring's keys with it, so export first.

The *Key rings* table on the Targets page lists every ring with its fingerprint and targets.

You can turn encryption on for a target that already holds plaintext snapshots. Each host just starts a new chunk history. Every run records which key fingerprint it used (`key_fingerprint`, shown on the run page).

The retired standalone DB agent can't encrypt. The server won't prepare a run for it on an encrypted target.
