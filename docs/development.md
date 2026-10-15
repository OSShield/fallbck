# Development

You need Go 1.26+.

```bash
go build ./... && go test ./...
go test -tags sqlite ./pkg/temporal/embedded/ ./pkg/integration/   # boots a real Temporal in-process
```

The server binary is big (about 175 MB) because the whole Temporal server and Web UI are baked in. The Dockerfiles use BuildKit cache mounts, so rebuilds stay quick.

!!! warning "gopbs replace"
    `go.mod` currently `replace`s `github.com/osshield/gopbs` with a sibling checkout (`../gopbs-fallbck`, branch `fallbck-session-dialer`) that adds `pbs.Config.DialSession`. Until that's merged and tagged, Docker and CI builds need the replace pointed at a published version.

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
