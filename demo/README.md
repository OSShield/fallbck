# Demo Environment
This is a preconfigured demo environment for testing and development. It includes a demo proxmox backup server instance with **unsafe defaults**, so don't use this one near production. Don't expose it to the internet. Don't water it, don't feed it after midnight.

- The demo starts FallBCK without any authentication
- The PBS instance is ephemeral and does not persist data between restarts
- The PBS instance has unsafe defaults and overridden token secrets designed to be easy to remember, not secure