# Linux packages

Every release ships `.deb`, `.rpm` and `.apk` packages for `fallbck-server` and `fallbck-agent`. You can grab them from the [releases page](https://github.com/OSShield/fallbck/releases), or you can use our package repository (see config below).

| Package | Service | Config |
|---|---|---|
| `fallbck-server` | systemd (deb/rpm) or OpenRC (apk) unit `fallbck-server`, runs as user `fallbck` | `/etc/fallbck/server.yaml`, secrets in `/etc/fallbck/server.env` |
| `fallbck-agent` | systemd / OpenRC unit `fallbck-agent`, runs as root | `/etc/fallbck/agent.env` (optional self-enrollment, DB profiles). State, spool and `agent.yaml` live in `/var/lib/fallbck/agent`, and there's an example config in `/usr/share/doc/fallbck-agent/` |

## Server

```bash
apt install ./fallbck_server_Linux_amd64.deb      # or rpm -i / apk add --allow-untrusted
$EDITOR /etc/fallbck/server.yaml /etc/fallbck/server.env
systemctl enable --now fallbck-server
```

On Alpine: `rc-update add fallbck-server default && rc-service fallbck-server start`.

## Agent

```bash
apt install ./fallbck_agent_Linux_amd64.deb
fallbck-agent enroll --server https://backup.example.com --token <enrollment token>
systemctl enable --now fallbck-agent
```

Want the same box to do database dumps? Install the client tools next to it. No second agent needed:

```bash
apt install postgresql-client mariadb-client      # whichever engines you back up
fallbck-agent tools                               # shows what it found
```


## Package Repositories
### Debian/Ubuntu
```bash
# Fetch the GPG key for the repository
curl -fsSL https://deb.osshield.eu/key | \
  sudo gpg --dearmor -o /etc/apt/keyrings/osshield-debian.gpg

# Add the APT source (old format)
echo "deb [signed-by=/etc/apt/keyrings/osshield-debian.gpg] https://deb.osshield.eu all main" | \
  sudo tee /etc/apt/sources.list.d/osshield-debian.list

# Update the sources and install the server or agent
sudo apt-get update

# sudo apt-get install fallbck-server
# sudo apt-get install fallbck-agent
```

### RPM-based repositories (YUM/DNF)
```bash
# Create the configuration file
echo <<EOT > /etc/yum.repos.d/osshield-rpm.repo
[osshield-rpm]
name=osshield-rpm
baseurl=https://rpm.osshield.eu
enabled=1
gpgcheck=1
gpgkey=https://rpm.osshield.eu/key
EOT

# Import the GPG key used to sign packages
sudo rpm --import https://rpm.osshield.eu/key

# Install server or agent
# yum install fallbck-server
# yum install fallbck-agent
```

### Alpine
```bash
# Fetch the signing key
cd /etc/apk/keys && curl -JO https://alpine.osshield.eu/key

# Add the repository URL
echo "https://alpine.osshield.eu/all >> /etc/apk/repositories

# Install the server or agent
# apk add fallbck-server
# apk add fallbck-agent
```

### Winget (agent only)
```powershell
# Add the source
winget source add --name "osshield-win" --arg "https://win.osshield.eu" --type "Microsoft.Rest"

# Install the agent
# winget install --source "osshield-win" OSShield.FallbckAgent
```



## Upgrades

Install the new package over the old one (`apt install ./…deb`, `rpm -U`, `apk add`). If the service is running, it gets restarted so the new binary takes over right away. A stopped or not-yet-enrolled service is left alone and you get the post-install hint instead.

Upgrades never touch your data, enrollment or config files. A backup that's running on that host when the restart happens gets cut off, and the server retries it on the next scheduled run.

Linux agents can also [update themselves](../operations/agent-status.md#agent-updates) from the server, so you don't have to chase every box after a server upgrade.
