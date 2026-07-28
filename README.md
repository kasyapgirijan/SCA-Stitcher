# SCA Stitcher

Consolidates Checkmarx SCA scan reports into developer-friendly Excel, CSV, and HTML output — stitching every vulnerable transitive package back to the primary library a developer should actually upgrade.

Runs as a command-line tool or as an authenticated web application. It reads a local
`SCA_ScanReport.json` (or a ZIP containing it), so it needs **no Checkmarx API key**
and never calls back to Checkmarx.

## Why this exists

Checkmarx SCA reports list direct and transitive dependency findings, but the standard
exports are not shaped for the people who fix them. A developer handed a raw export
sees a vulnerable transitive package and no obvious answer to the only question that
matters: *which dependency do I actually bump?*

SCA Stitcher answers that. It resolves each vulnerable transitive package to the
primary library that pulls it in, groups findings by that library, and keeps the
supporting evidence — dependency path, file location, CVE/Cx ID, and CVSS score —
attached to every row. The result is ready to hand to an application team or to raise
work from in Jira.

It consolidates and maps findings. It does not create Jira tickets.

## Quick start

CSV and HTML output need only the Python standard library. Excel output needs
XlsxWriter:

```powershell
python -m pip install XlsxWriter
```

Run against an exported report:

```powershell
python .\checkmarx_sca_consolidator_v2.py `
  --input .\SCA_ScanReport.json `
  --out .\sca_consolidated
```

With custom grouping rules:

```powershell
python .\checkmarx_sca_consolidator_v2.py `
  --input .\SCA_ScanReport.json `
  --out .\sca_consolidated `
  --group-config .\checkmarx_group_config.example.json
```

## Outputs

```text
sca_consolidated\sca_stitcher_consolidated.xlsx
sca_consolidated\sca_stitcher_consolidated.csv
sca_consolidated\library_group_summary.csv
sca_consolidated\unmapped_libraries.csv
sca_consolidated\consolidated_preview.html
sca_consolidated\schema_diagnostics.json
```

The Excel workbook carries the consolidated rows, a per-group summary, the unmapped
findings, and the run diagnostics as separate sheets.

## How the mapping works

To resolve a vulnerable package to its primary library, SCA Stitcher tries, in order:

1. The package's own `PackagePaths` dependency chain, preferring a direct dependency.
2. Exact package ID.
3. Package name and version.
4. A unique package name.
5. The manifest location. A direct package covers its own location and, when that
   location is a file, the directory containing it — so `services/api/pom.xml` covers
   `services/api`. The most specific covering location wins, and it must have exactly
   one direct package claiming it.

Step 5 deliberately does not walk further up the tree. Matching on a shared repository
root would let a transitive package under `services/worker` be attributed to an
unrelated direct package under `services/api`, which points a developer at the wrong
upgrade. For the same reason, when several direct packages share one manifest the
result is recorded as ambiguous rather than resolved to an arbitrary one of them.

Anything still unresolved is written to `unmapped_libraries.csv` and the Excel
`Unmapped` sheet rather than being silently dropped or guessed at. The `Mapping Source`
column records which step produced each row, including `ambiguous location scope`.

Grouping rolls up related findings so a team sees one item instead of twenty: the same
primary library at different versions collapses into one `Library Group`, and built-in
rules group ecosystem clusters such as `eslint`, `eslint-plugin-react-hooks`, and
`eslint-plugin-react-refresh` under `ESLint`, and BIRT-related findings under `BIRT`.
Add your own with `--group-config`.

Each row's vulnerability column holds only `CVE/Cx ID | CVSS score`, plus current
version, latest version, and an `Is Latest?` flag for both the primary and the
vulnerable library.

## Web application

An authenticated Docker web app for private, ephemeral report processing. Uploads,
previews, exports, and report metadata are never persisted.

Copy the environment template and set a strong secret:

```powershell
Copy-Item .env.example .env
python -c "import secrets; print(secrets.token_hex(32))"
```

Paste the generated value after `SECRET_KEY=` in `.env`. Keep `.env` local; it is
ignored by Git. Then build, provision an administrator, and start:

```powershell
docker compose build
docker compose run --rm web flask --app web_app create-admin
docker compose up
```

Open <http://localhost:8080> and upload a `.json` or `.zip` report. Preview the
consolidated findings in the browser, print or save the preview as PDF, or download
Excel, CSV, or standalone HTML. The named Docker volume holds only the
local-development `users.db`; reports are processed in temporary storage and deleted
when the request finishes.

### Account management

Local administrators manage accounts at `/admin`. Accounts created or reset there must
replace their temporary password at the next sign-in.

Reset a forgotten password from the server console:

```powershell
flask --app web_app reset-password
```

A plain reset deliberately does not change roles. If every administrator has lost the
admin role, restore it on an existing account with `--grant-admin`:

```powershell
flask --app web_app list-admins
flask --app web_app reset-password --grant-admin
```

## Security and deployment

There is no HTTP first-account setup route: local accounts can only be provisioned
from the CLI. Production refuses to start with local password authentication and
requires verified AWS ALB OIDC/Cognito identity, secure cookies, a strong secret, and
trusted hosts.

- [Production security assessment](docs/security-assessment.md)
- [AWS production guide](docs/aws-production.md)
- [ECS task-definition example](aws/ecs-task-definition.example.json)

Uploads default to a 25 MiB limit (`MAX_UPLOAD_BYTES`); JSON members extracted from ZIP
uploads are capped to the same limit. Nesting depth, node count, package count, row
count, request rate, and generated-output size are all bounded and configurable — see
`.env.example`; `MAX_JSON_NODES` counts every JSON value, scalars included, and
`MAX_REPORT_CONTENT_CHARS` bounds total generated cell content while rows are built so
no export format can be materialized beyond it. CLI report parsing defaults to a 100 MiB JSON cap
(`MAX_REPORT_BYTES`); that variable applies to the CLI only, not to the web service.

The in-browser preview renders at most `MAX_PREVIEW_ROWS` rows (default 2000) and says
so when it truncates; downloads are never truncated. `TRUST_PROXY_HOPS` defaults to 0,
which ignores `X-Forwarded-*` entirely — set it to the number of proxies in front of
the app so audit events and the per-IP login limiter see the real client address.

Production dependencies are exact and hash-locked in `requirements.txt`; regenerate the
lock from `requirements.in`. Development and audit tooling is isolated in
`requirements-dev.txt`.

## Development

```powershell
python -m pip install -r requirements-dev.txt
python -m pytest
```

The suite covers authentication and role enforcement, CSRF rejection on every
state-changing route, rate limiting, spreadsheet formula-injection neutralization,
export sandboxing, report size and structure limits, preview row bounds, audit-record
attribution and log-injection resistance, forwarded-header trust, ALB assertion
verification and signing-key cache behavior, concurrency guards on administrator
role changes, and dependency-location mapping including ambiguous and unrelated paths.

## Notes

Do not commit scan reports, generated workbooks, or ZIP exports. `.gitignore` already
excludes the common local report and output paths.

If `schema_diagnostics.json` reports `packages_using_count_fallback`, the source export
did not itemize CVE/CVSS data for those packages. They are still included, but the
vulnerability column will say the details were not itemized in the source.
