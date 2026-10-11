# Encryption

Turn on **Client-side encryption** on a PBS target (or `encryption_mode: encrypt` in the API) and every snapshot written there is encrypted on the agent before it leaves the host. It's the same thing `proxmox-backup-client --keyfile` does:

- chunks and manifest blobs are AES-256-GCM,
- the manifest is signed,
- PBS only ever sees ciphertext. You'll get the lock icon on the snapshot.

There's one key per target, shared by every job and host writing to it, so dedup keeps working across them. Different targets never share chunks anyway, so a key per target doesn't cost you anything.

## Where the key lives

The server generates the key when you enable encryption and stores it sealed with the **server master key** (`security.master_key_file`, default `<data_dir>/master.key`, or `FALLBCK_MASTER_KEY` in containers). That same master key also seals the targets' PBS API tokens.

Agents fetch the key per run with their backup ticket and keep it in memory for that run only. An agent refuses to upload plaintext to an encrypted target. Kubernetes worker pods fetch it the same way. The key never shows up in a pod spec, in Temporal history or in logs. Only its fingerprint does.

## Export the key file. Now.

!!! danger "Seriously, do this first"
    Without the key file, or the server database **plus** its master key, nothing on that target can be restored. Not by you, not by anyone.

Hit *Export key file* on the target form. You get a passphrase-protected (scrypt) key file in `proxmox-backup-client` format, named after the target and key fingerprint. Keep it, and its passphrase, somewhere that isn't the backup server. Onboarding won't let you past a freshly encrypted target until you've downloaded it.

Restore with:

```bash
proxmox-backup-client restore --keyfile <file> ...
```

The restore commands in the run manifests assume you've got the key file at hand.

### Belt and braces: RSA master key

Optionally paste an **RSA master public key** (2048 bits or more) on the target. Every snapshot then also carries the encryption key wrapped with it, so if the key file goes missing, the private key can still get the data back (`proxmox-backup-client key import-with-master-key`).

## Rotation, import, disabling

- **Rotate key** makes a new key. The old one is retired, not deleted, because the snapshots written with it still need it. It stays exportable by fingerprint. New snapshots won't dedup against old ones.
- **Import key file** adopts a key from `proxmox-backup-client` or another FallBCK target. That's how a cloned target shares its source's key. A clone copies the master public key but starts out unencrypted.
- **Disabling** encryption keeps the keys around, for the same reason.

You can turn encryption on for a target that already holds plaintext snapshots. Each host just starts a new chunk history. Every run records which key fingerprint it used (`key_fingerprint`, shown on the run page).

The retired standalone DB agent can't encrypt. The server won't prepare a run for it on an encrypted target.
