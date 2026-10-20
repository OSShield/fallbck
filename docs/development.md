# Development

You need Go 1.26+.

```bash
go build ./... && go test ./...
go test -tags sqlite ./pkg/temporal/embedded/ ./pkg/integration/   # boots a real Temporal in-process
```

Some things are best tested against a real PBS instance - e.g. whether `proxmox-backup-client` restores what the agent encrypted, whether dedup and incremental reuse hold up. The `pbse2e` tests start a throwaway [ephemeral-pbs](https://github.com/osshield/ephemeral-pbs) container per package (needs Docker) and run the agent activity through the tunnel against it:

```bash
go test -tags pbse2e -count=1 ./pkg/tokencheck/ ./pkg/agent/
```

Set `FALLBCK_E2E_PBS_IMAGE` to try a local build of the image. Users, tokens and namespaces are configured in `pkg/pbse2e/pbs-config.yml`.

The server binary is big (about 175 MB) because the whole Temporal server and Web UI are baked in. The Dockerfiles use BuildKit cache mounts, so rebuilds stay quick.

For a local stack to poke at, see [Try it locally](getting-started/quick-start.md).

## Releases

[GoReleaser](https://github.com/osshield/fallbck/blob/main/.goreleaser.yml) builds everything from the `Release` GitHub Action when a `v*` tag is pushed. Every push to `main` and every PR gets a snapshot build as a workflow artifact, so packaging can't quietly rot.

## Docs

This site is in `docs/` and gets built with [Zensical](https://zensical.org) from `mkdocs.yml`. Preview it locally:

```bash
pip install zensical
zensical serve
```

Pushes to `main` that touch `docs/` or `mkdocs.yml` deploy to GitHub Pages automatically.
