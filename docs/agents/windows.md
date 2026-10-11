# Windows

`fallbck-agent` runs on Windows (x64 and arm64) as a regular Windows service.

## Install

Grab the MSI from the [releases page](https://github.com/osshield/fallbck/releases). Double-click it and it asks for the server URL, the enrollment key and, optionally, a CA bundle. It then enrolls and starts the service.

For unattended installs, use the PowerShell one-liner that the onboarding flow prints (*Files* → *Windows*), or pass MSI properties:

```powershell
& ([scriptblock]::Create((iwr -useb https://backup.example.com/install-agent.ps1).Content)) -Token <enrollment token>

# or by hand
msiexec /i fallbck-agent_Windows_x86_64.msi /qn SERVER_URL=https://backup.example.com TOKEN=<token>
```

The service runs as LocalSystem and keeps its state (`agent.yaml`, caches, logs) in `%ProgramData%\fallbck\agent`. If you enrolled by hand, `fallbck-agent.exe service install|uninstall|start|stop|status` manages the service.

## What gets backed up

Paths are Windows paths: `C:\Users`, `D:\data`, or a whole volume like `C:\`. In the archive they show up as `C`, `D-data` and so on.

**Shadow copies.** Each run takes a Volume Shadow Copy of every volume it touches first, so open and locked files come out consistent. Leftover shadow copies get cleaned up the next time the agent starts. To read the live filesystem instead, set `vss: false` in `agent.yaml` or `FALLBCK_AGENT_VSS=false`.

**Metadata.** File types, sizes, mtimes, hardlinks and symlinks/junctions are recorded, with made-up POSIX modes (read-only files become `0444`). NTFS ACLs and alternate data streams **aren't** included yet.

Incremental runs with [metadata change detection](index.md#incremental-runs-on-pxar-v2) work the same as on Linux.

!!! note "No self-update on Windows"
    Windows agents don't [update themselves](../operations/agent-status.md#agent-updates). Roll out the new MSI when you upgrade the server.
