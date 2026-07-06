# Checkmarx native SCA JSON consolidator

This version reads a local Checkmarx native JSON report beginning with `RiskReportSummary` and `Packages`. It does **not** call the Checkmarx API and does **not** create Jira issues.

## Run

```powershell
python .\checkmarx_sca_native_consolidator.py `
  --input .\SCA_ScanReport.json `
  --out .\jira_ready
```

Open `jira_ready\consolidated_preview.html` after the script completes.

## Outputs

- `consolidated_preview.html` — human-readable Jira ticket preview.
- `tickets\*.md` — one Markdown ticket body for every primary/direct dependency.
- `tickets\*.json` — structured payload for future Jira API integration.
- `schema_diagnostics.json` — confirms whether CVE/CVSS detail was available in the supplied report.

## Important result to verify

Check `schema_diagnostics.json`:

- `detailed_vulnerabilities_found > 0`: CVE/Cx ID and CVSS fields were found and included.
- `detailed_vulnerabilities_found = 0`: the export has only per-package severity counts. The path grouping is still generated, but CVE/CVSS will explicitly be marked “not itemized in source.” It is not a parsing failure.

## Input supported

- `.json` native SCA report
- `.zip` containing a JSON report

No third-party Python packages are required.
