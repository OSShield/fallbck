# Demo Environment
This is a preconfigured demo environment for testing and development. It includes a demo proxmox backup server instance with **unsafe defaults**, so don't use this one near production. Don't expose it to the internet. Don't water it, don't feed it after midnight.

- The demo starts FallBCK without any authentication
- The PBS instance is ephemeral and does not persist data between restarts
- The PBS instance has unsafe defaults and overridden token secrets designed to be easy to remember and test, not to be secure

## Default Credentials

FallBCK has no credentials. PBS uses the root password set in the compose file, default `demo`.
All other users use a random password printed at startup
All API keys have been set to `12345678-1234-1234-1234-1234567890ab`

| Service | Username | Password |
|---------|----------|----------|
| FallBCK | No auth     | No auth     |
| PBS     | root (PAM)    | demo    |
| 