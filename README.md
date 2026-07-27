# Checkmarx SCA JSON consolidator

Python utilities for consolidating native Checkmarx SCA JSON reports into developer-friendly Excel/CSV/HTML output.

The repository also includes an authenticated Docker web application for private, ephemeral report processing. Only usernames and password hashes are stored; uploads, previews, exports, and report metadata are not persisted.

## Docker web application

Copy the environment template and replace `SECRET_KEY` with a long random value:

```powershell
Copy-Item .env.example .env
python -c "import secrets; print(secrets.token_hex(32))"
docker compose up --build
```

Paste the generated value after `SECRET_KEY=` in `.env`. The template also documents the secure-cookie setting and report size limits. Keep `.env` local; it is ignored by Git.

Open <http://localhost:8080>, create the first account, and upload a `.json` or `.zip` report. You can preview the consolidated findings, print/save the preview as PDF for sharing, or download CSV, Excel, or standalone HTML directly. The named Docker volume contains only `users.db`; report files are processed in temporary storage and deleted at the end of each request.

For HTTPS deployments, place the app behind a TLS reverse proxy and set `COOKIE_SECURE=true`. Uploads default to a 25 MiB limit, configurable with `MAX_UPLOAD_BYTES`; extracted JSON members inside ZIP uploads are capped to the same limit. CLI report parsing defaults to a 100 MiB JSON cap, configurable with `MAX_REPORT_BYTES`. Back up the `user-data` volume if accounts need to survive host replacement.

The web app now refuses to start without `SECRET_KEY` unless it is running under test configuration. This avoids accidentally creating restart-sensitive random session secrets in production.

The main version is:

```text
checkmarx_sca_consolidator_v2.py
```

It reads the local exported `SCA_ScanReport.json` or a ZIP containing the JSON. It does **not** need a Checkmarx API key, and it does **not** create Jira tickets.

## Why this exists

Checkmarx SCA reports may show direct and transitive dependency information, but the standard exports are not always ready for Jira or EPD teams. This script consolidates findings so the team can work from the primary/direct library while still seeing the vulnerable transitive package path, file location, CVE/Cx ID, and CVSS score.

## Install

CSV and HTML output work with Python standard library only.

For Excel output:

```powershell
python -m pip install XlsxWriter
```

## Run

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

The script generates:

```text
sca_consolidated\checkmarx_sca_consolidated.xlsx
sca_consolidated\checkmarx_sca_consolidated.csv
sca_consolidated\library_group_summary.csv
sca_consolidated\unmapped_libraries.csv
sca_consolidated\consolidated_preview.html
sca_consolidated\schema_diagnostics.json
```

## Implemented requirements

- Vulnerability column contains only `CVE/Cx ID | CVSS score`; severity is not appended there.
- Adds current version, latest version, and `Is Latest?` for both primary and vulnerable libraries.
- Groups same primary library with different versions under one `Library Group`.
- Groups ESLint-related packages such as `eslint`, `eslint-plugin-react-hooks`, and `eslint-plugin-react-refresh` under `ESLint`.
- Groups BIRT-related findings under `BIRT`.
- Uses `PackagePaths`, exact package ID, package name/version, unique package name, and location matching to reduce unmapped primary libraries.
- Writes unresolved/ambiguous mappings to `unmapped_libraries.csv` and the Excel `Unmapped` sheet.

## Important notes

Do not commit company scan reports, generated Excel files, or ZIP exports. `.gitignore` is configured to keep common local reports and generated output folders out of the repo.

If `schema_diagnostics.json` shows `packages_using_count_fallback`, the source report did not expose itemized CVE/CVSS data for those packages. The package is still retained, but the vulnerability column will say that details were not itemized in the source.
