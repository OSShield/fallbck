# Frontend development

The FallBCK UI uses Go HTML templates and locally vendored HTMX 4.0.0. There is
no frontend build step. Run the Docker overlay described in the README and edit
`web/`; refresh the browser to see template, stylesheet and script changes.
Rebuild the server for Go changes. Production builds embed the same assets;
`--web-dir` is accepted only together with `--dev`.

## Structure

- `web/server.go` renders full documents or HTMX page fragments.
- `web/forms.go` adapts HTML forms to the existing API handlers, preserving their
  authorization, validation, credential handling and scheduling behavior.
- `web/run_detail.go` prepares typed filesystem, database and Kubernetes records.
- `web/templates/components.html` contains shared table and status components.
- `web/static/css/app.css` defines light/dark tokens, layout and responsive rules.
- `web/static/js/app.js` handles local dialog, focus, field visibility, clipboard
  and navigation behavior. HTMX owns requests, page swaps and live polling.

HTMX inheritance is explicit using `:inherited`. Navigation replaces `#app`;
dialogs request their own fragments. Validation errors replace the form's error
region while preserving input. Successful saves refresh the server-rendered
listing. Active run details poll every three seconds and stop when finished.
HTML responses are private and uncached, including one-time enrollment tokens
and API keys. Mutating routes retain the existing session and CSRF checks.

## Visual identity

Graphite and mineral surfaces, amber navigation accents, an archive-inspired
mark, flat rules and tabular metadata give FallBCK its own operational identity.
Menu icons accompany readable labels. Status always includes text. Dense tables
become labeled records when their panel becomes narrow; forms retain visible
actions while their content scrolls. Both themes include visible keyboard focus
and reduced-motion support.

## Verification

Run `go test ./...` with the Go version specified by `go.mod`. Frontend tests
cover full pages and HTMX fragments, all backup form types, validation and
escaping, advanced setting preservation, credential handling, authentication,
CSRF and typed run details.

The integration script uses a disposable PostgreSQL database and synthetic
records. The test server and database have no external network access. First
build the development image, then run:

```sh
docker compose -f deploy/docker-compose.yml -f deploy/compose.frontend.yml build server
docker compose -f deploy/compose.ui-test.yml up -d --wait
python3 scripts/verify-frontend.py
```

Inspect populated pages at `http://localhost:18081`. The script checks create,
edit, validation, secret redaction, deletion, revocation, agent debug controls,
job triggering/cancellation and run details. It verifies the Docker project,
database and network before making any changes. It cannot target the regular
development instance. It does not execute real backups or contact a PBS server.

After browser inspection, remove only the disposable stack:

```sh
docker compose -f deploy/compose.ui-test.yml down -v
```

Browser checks should include phone, tablet and desktop layouts, both themes,
navigation and browser history, keyboard dialog dismissal, validation focus,
conditional fields, save-and-refresh behavior and live run updates. Real agent
backup execution and external OIDC provider integration require their respective
environments and are outside this UI verification fixture.
