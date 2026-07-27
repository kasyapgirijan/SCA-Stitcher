# Checkmarx SCA JSON consolidator

Python utilities for consolidating native Checkmarx SCA JSON reports into developer-friendly Excel/CSV/HTML output.

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
