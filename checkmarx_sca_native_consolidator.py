#!/usr/bin/env python3
r"""
Checkmarx SCA native JSON -> Jira-ready consolidated ticket previews.

Supports the native Checkmarx report shape visible in SCA_ScanReport.json:
  {
    "RiskReportSummary": {...},
    "Packages": [
      {
        "Id": "Maven-...",
        "Name": "group:artifact",
        "Version": "x.y.z",
        "IsDirectDependency": true|false,
        "DependencyType": "Direct"|"Transitive",
        "Locations": [...],
        "PackagePaths": [...],
        "VulnerabilityCount": 0,
        "CriticalVulnerabilityCount": 0,
        ...
      }
    ]
  }

No Checkmarx API key or Jira credentials are required. The script only reads a
local JSON/ZIP export and writes Markdown, HTML and JSON ticket previews.

Usage (Windows PowerShell):
  python .\\checkmarx_sca_native_consolidator.py `
    --input .\SCA_ScanReport.json `
    --out .\jira_ready

The source report must contain per-vulnerability detail somewhere in the JSON
(e.g. CVE/Cx ID and CVSS). If the export only carries package-level counts,
the script still creates the right primary-library / dependency-path grouping,
but labels the CVE/CVSS cell as "not itemized in source" instead of inventing
values. See schema_diagnostics.json in the output folder.
"""

from __future__ import annotations

import argparse
import hashlib
import html
import json
import os
import re
import sys
import zipfile
from collections import defaultdict
from dataclasses import asdict, dataclass
from io import BytesIO
from pathlib import Path
from typing import Any, Iterable, Optional


SEVERITY_ORDER = {
    "critical": 5,
    "high": 4,
    "medium": 3,
    "moderate": 3,
    "low": 2,
    "info": 1,
    "informational": 1,
    "none": 0,
    "unknown": 0,
    "unspecified": 0,
    "": 0,
}

DETAIL_KEYS = (
    "Vulnerabilities",
    "VulnerabilityDetails",
    "VulnerabilityDetailsList",
    "VulnerabilityList",
    "Issues",
    "Findings",
    "CVEs",
    "Cves",
    "CveList",
)

PATH_KEYS = (
    "PackagePath",
    "PackagePaths",
    "Path",
    "Paths",
    "DependencyPath",
    "DependencyPaths",
    "Packages",
    "Nodes",
    "Chain",
)

DEFAULT_MAX_REPORT_BYTES = int(os.environ.get("MAX_REPORT_BYTES", str(100 * 1024 * 1024)))


class ConsolidationError(RuntimeError):
    pass


@dataclass(frozen=True)
class Vulnerability:
    vuln_id: str
    cvss: Optional[float]
    severity: str
    note: str = ""

    def display(self) -> str:
        chunks = [self.vuln_id]
        if self.cvss is not None:
            chunks.append(f"CVSS {self.cvss:g}")
        if self.severity and self.severity.lower() not in {"unspecified", "unknown"}:
            chunks.append(self.severity.title())
        if self.note:
            chunks.append(self.note)
        return " | ".join(chunks)


@dataclass(frozen=True)
class FindingRow:
    primary: str
    package_path: tuple[str, ...]
    location: str
    vulnerabilities: tuple[Vulnerability, ...]

    @property
    def is_direct(self) -> bool:
        return len(self.package_path) == 1


@dataclass
class Ticket:
    project: str
    primary: str
    rows: list[FindingRow]

    @property
    def label(self) -> str:
        digest = hashlib.sha256(f"{self.project}|{self.primary}".encode("utf-8")).hexdigest()[:12]
        return f"cxsca-{digest}"

    @property
    def summary(self) -> str:
        return f"[SCA] {self.primary} — vulnerable dependency chain(s)"

    @property
    def unique_vulnerabilities(self) -> list[Vulnerability]:
        found: dict[tuple[str, Optional[float], str, str], Vulnerability] = {}
        for row in self.rows:
            for vuln in row.vulnerabilities:
                found[(vuln.vuln_id, vuln.cvss, vuln.severity, vuln.note)] = vuln
        return sorted(found.values(), key=vulnerability_sort_key)


def ci_get(mapping: Any, *keys: str, default: Any = None) -> Any:
    """Get a dictionary value with case-insensitive key matching."""
    if not isinstance(mapping, dict):
        return default
    for key in keys:
        if key in mapping:
            return mapping[key]
    lower = {str(key).lower(): value for key, value in mapping.items()}
    for key in keys:
        value = lower.get(key.lower())
        if value is not None:
            return value
    return default


def text(value: Any, default: str = "") -> str:
    if value is None:
        return default
    result = str(value).strip()
    return result or default


def as_float(value: Any) -> Optional[float]:
    if value in (None, "", "N/A", "n/a"):
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def as_int(value: Any) -> int:
    try:
        return int(float(value or 0))
    except (TypeError, ValueError):
        return 0


def stable_unique(values: Iterable[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for value in values:
        value = text(value)
        if value and value not in seen:
            seen.add(value)
            result.append(value)
    return result


def package_display(pkg: Any) -> str:
    if isinstance(pkg, str):
        return text(pkg, "Unknown package")
    if not isinstance(pkg, dict):
        return "Unknown package"
    name = text(ci_get(pkg, "Name", "PackageName", "ArtifactName", "Id"), "Unknown package")
    version = text(ci_get(pkg, "Version", "PackageVersion"))
    return f"{name} @ {version}" if version else name


def package_ref(pkg: Any) -> str:
    if isinstance(pkg, str):
        return text(pkg)
    if not isinstance(pkg, dict):
        return ""
    return text(ci_get(pkg, "Id", "PackageId", "BomRef", "Purl")) or package_display(pkg)


def package_locations(pkg: dict[str, Any]) -> str:
    raw = ci_get(pkg, "Locations", "Location", "FilePaths", "Files", default=[])
    if isinstance(raw, str):
        return raw.strip() or "Not supplied by source"
    if isinstance(raw, dict):
        raw = [raw]
    if not isinstance(raw, list):
        return "Not supplied by source"

    values: list[str] = []
    for item in raw:
        if isinstance(item, str):
            values.append(item)
        elif isinstance(item, dict):
            values.append(text(ci_get(item, "Path", "Location", "FilePath", "Name")))
    result = "; ".join(stable_unique(values))
    return result or "Not supplied by source"


def is_direct(pkg: dict[str, Any]) -> bool:
    direct_value = ci_get(pkg, "IsDirectDependency", "DirectDependency")
    if isinstance(direct_value, bool):
        return direct_value
    if text(direct_value).lower() in {"true", "yes", "1"}:
        return True
    return text(ci_get(pkg, "DependencyType", "Type")).lower() == "direct"


def count_summary(pkg: dict[str, Any]) -> dict[str, int]:
    return {
        "critical": as_int(ci_get(pkg, "CriticalVulnerabilityCount", "CriticalCount")),
        "high": as_int(ci_get(pkg, "HighVulnerabilityCount", "HighCount")),
        "medium": as_int(ci_get(pkg, "MediumVulnerabilityCount", "MediumCount")),
        "low": as_int(ci_get(pkg, "LowVulnerabilityCount", "LowCount")),
        "none": as_int(ci_get(pkg, "NoneVulnerabilityCount", "NoneCount")),
        "total": as_int(ci_get(pkg, "VulnerabilityCount", "TotalVulnerabilityCount")),
    }


def count_note(counts: dict[str, int]) -> str:
    return ", ".join(
        f"{label.title()}={counts[label]}"
        for label in ("critical", "high", "medium", "low", "none")
        if counts[label]
    ) or f"Total={counts['total']}"


def package_is_reportable(pkg: dict[str, Any], include_none: bool, detailed_vulns: list[Vulnerability]) -> bool:
    usable_details = [item for item in detailed_vulns if include_none or item.severity.lower() != "none"]
    if usable_details:
        return True
    counts = count_summary(pkg)
    if include_none:
        return counts["total"] > 0 or sum(counts.values()) > 0
    return any(counts[level] > 0 for level in ("critical", "high", "medium", "low"))


def looks_like_vulnerability(mapping: dict[str, Any]) -> bool:
    """Avoid treating a package record itself as a vulnerability detail."""
    candidate = " ".join(
        text(ci_get(mapping, key))
        for key in ("Cve", "CVE", "CveId", "CVEId", "VulnerabilityId", "IssueId", "Id", "Name")
    )
    has_vuln_id = bool(re.search(r"(?:CVE-\d{4}-\d+|Cxa[:\-][A-Za-z0-9._-]+)", candidate, re.I))
    has_vuln_fields = any(
        ci_get(mapping, key) is not None
        for key in ("Cvss", "CVSS", "CvssScore", "CVSSScore", "BaseScore", "Vector", "Severity")
    )
    return has_vuln_id or (has_vuln_fields and not ci_get(mapping, "IsDirectDependency", "DependencyType"))


def detail_to_vulnerability(detail: dict[str, Any]) -> Optional[Vulnerability]:
    all_text = " ".join(str(value) for value in detail.values() if isinstance(value, (str, int, float)))
    cve_match = re.search(r"CVE-\d{4}-\d+", all_text, re.I)
    cxa_match = re.search(r"Cxa[:\-][A-Za-z0-9._-]+", all_text, re.I)
    vuln_id = text(
        ci_get(detail, "Cve", "CVE", "CveId", "CVEId", "VulnerabilityId", "IssueId", "CxaId", "Id", "Name")
    )
    if cve_match:
        vuln_id = cve_match.group(0).upper()
    elif cxa_match:
        vuln_id = cxa_match.group(0)
    if not vuln_id:
        return None

    score = as_float(ci_get(detail, "CvssScore", "CVSSScore", "Cvss", "CVSS", "BaseScore", "Score"))
    severity = text(ci_get(detail, "Severity", "SeverityName", "RiskSeverity", "Level"), "Unspecified").lower()
    return Vulnerability(vuln_id=vuln_id, cvss=score, severity=severity)


def walk_for_vulnerability_dicts(value: Any, depth: int = 0, max_depth: int = 7) -> list[dict[str, Any]]:
    """Extract likely vulnerability objects from explicitly named detail fields."""
    if depth > max_depth:
        return []
    result: list[dict[str, Any]] = []
    if isinstance(value, dict):
        if looks_like_vulnerability(value):
            result.append(value)
        for child in value.values():
            result.extend(walk_for_vulnerability_dicts(child, depth + 1, max_depth))
    elif isinstance(value, list):
        for child in value:
            result.extend(walk_for_vulnerability_dicts(child, depth + 1, max_depth))
    return result


def package_vulnerability_details(pkg: dict[str, Any]) -> list[Vulnerability]:
    raw_fields: list[Any] = []
    for key in DETAIL_KEYS:
        value = ci_get(pkg, key)
        if value is not None:
            raw_fields.append(value)

    found: dict[tuple[str, Optional[float], str], Vulnerability] = {}
    for raw in raw_fields:
        for detail in walk_for_vulnerability_dicts(raw):
            vulnerability = detail_to_vulnerability(detail)
            if vulnerability:
                found[(vulnerability.vuln_id, vulnerability.cvss, vulnerability.severity)] = vulnerability
    return sorted(found.values(), key=vulnerability_sort_key)


def package_refs_from_global_detail(detail: dict[str, Any]) -> list[str]:
    refs: list[str] = []
    for key in (
        "PackageId", "AffectedPackageId", "ComponentId", "DependencyId", "PackageRef", "AffectedRef",
        "PackageIds", "AffectedPackageIds", "ComponentIds", "Dependencies",
    ):
        value = ci_get(detail, key)
        if isinstance(value, str):
            refs.append(value)
        elif isinstance(value, list):
            for item in value:
                if isinstance(item, str):
                    refs.append(item)
                elif isinstance(item, dict):
                    refs.append(package_ref(item))
        elif isinstance(value, dict):
            refs.append(package_ref(value))

    for key in ("Package", "AffectedPackage", "Component", "Dependency"):
        value = ci_get(detail, key)
        if isinstance(value, dict):
            refs.append(package_ref(value))
    return stable_unique(refs)


def global_vulnerability_map(source: dict[str, Any]) -> dict[str, list[Vulnerability]]:
    """Map top-level detailed vulnerability records to Package Ids when supplied."""
    result: dict[str, dict[tuple[str, Optional[float], str], Vulnerability]] = defaultdict(dict)
    for key in DETAIL_KEYS:
        raw = ci_get(source, key)
        if raw is None:
            continue
        candidates = walk_for_vulnerability_dicts(raw)
        for detail in candidates:
            vuln = detail_to_vulnerability(detail)
            if not vuln:
                continue
            for ref in package_refs_from_global_detail(detail):
                result[ref][(vuln.vuln_id, vuln.cvss, vuln.severity)] = vuln
    return {key: sorted(value.values(), key=vulnerability_sort_key) for key, value in result.items()}


def is_component_like(value: Any) -> bool:
    return isinstance(value, dict) and bool(ci_get(value, "Id", "Name", "PackageName", "Version"))


def normalise_package_paths(raw: Any) -> list[list[dict[str, Any]]]:
    """Tolerate the several PackagePaths shapes emitted by Checkmarx exports."""
    if raw in (None, "", []):
        return []
    if isinstance(raw, dict):
        for key in PATH_KEYS:
            nested = ci_get(raw, key)
            if isinstance(nested, list):
                return normalise_package_paths(nested)
        return [[raw]] if is_component_like(raw) else []
    if not isinstance(raw, list):
        return []

    # Screenshot-compatible shape: PackagePaths is a flat list of component objects.
    if raw and all(is_component_like(item) for item in raw):
        return [[item for item in raw if isinstance(item, dict)]]

    paths: list[list[dict[str, Any]]] = []
    for item in raw:
        if isinstance(item, list):
            chain = [part for part in item if isinstance(part, dict) and is_component_like(part)]
            if chain:
                paths.append(chain)
            continue
        if isinstance(item, dict):
            nested_chain: list[dict[str, Any]] = []
            for key in PATH_KEYS:
                nested = ci_get(item, key)
                if isinstance(nested, list):
                    nested_chain = [part for part in nested if isinstance(part, dict) and is_component_like(part)]
                    break
            if nested_chain:
                paths.append(nested_chain)
            elif is_component_like(item):
                paths.append([item])
    return paths


def vulnerability_sort_key(vuln: Vulnerability) -> tuple[int, float, str]:
    return (
        -SEVERITY_ORDER.get(vuln.severity.lower(), 0),
        -(vuln.cvss if vuln.cvss is not None else -1),
        vuln.vuln_id.lower(),
    )


def sort_rows(rows: Iterable[FindingRow]) -> list[FindingRow]:
    return sorted(
        rows,
        key=lambda row: (
            row.primary.lower(),
            not row.is_direct,
            len(row.package_path),
            " > ".join(row.package_path).lower(),
            row.location.lower(),
        ),
    )


def parse_native(source: dict[str, Any], project: str, include_none: bool) -> tuple[list[FindingRow], dict[str, Any]]:
    packages = ci_get(source, "Packages", default=[])
    if not isinstance(packages, list):
        raise ConsolidationError("Native Checkmarx JSON must contain a top-level 'Packages' array.")

    native_packages = [item for item in packages if isinstance(item, dict)]
    if not native_packages:
        raise ConsolidationError("The report contains no usable package objects.")

    global_details = global_vulnerability_map(source)
    direct_packages = [item for item in native_packages if is_direct(item)]
    if not direct_packages:
        raise ConsolidationError(
            "No direct dependencies were found. Expected IsDirectDependency=true or DependencyType='Direct'."
        )

    direct_by_ref = {package_ref(item): package_display(item) for item in direct_packages if package_ref(item)}
    direct_by_display = {package_display(item): package_display(item) for item in direct_packages}

    rows_by_key: dict[tuple[str, tuple[str, ...], str], dict[tuple[str, Optional[float], str, str], Vulnerability]] = defaultdict(dict)
    detailed_vulnerability_records = 0
    fallback_count_rows = 0
    unmapped_transitive_rows = 0

    def usable_vulns(pkg: dict[str, Any]) -> list[Vulnerability]:
        local = package_vulnerability_details(pkg)
        ref = package_ref(pkg)
        combined = {(item.vuln_id, item.cvss, item.severity): item for item in local}
        for item in global_details.get(ref, []):
            combined[(item.vuln_id, item.cvss, item.severity)] = item
        values = sorted(combined.values(), key=vulnerability_sort_key)
        return [item for item in values if include_none or item.severity.lower() != "none"]

    def fallback_vulnerability(pkg: dict[str, Any]) -> list[Vulnerability]:
        counts = count_summary(pkg)
        if not package_is_reportable(pkg, include_none, []):
            return []
        note = f"CVE/CVSS details not itemized in source ({count_note(counts)})"
        severity = text(ci_get(pkg, "Severity", "RiskSeverity"), "Unspecified").lower()
        return [Vulnerability("Vulnerability details require a detailed Checkmarx export", None, severity, note)]

    def add_row(primary: str, path: list[str], location: str, vulnerabilities: list[Vulnerability]) -> None:
        if not vulnerabilities:
            return
        key = (primary, tuple(path), location)
        for vuln in vulnerabilities:
            rows_by_key[key][(vuln.vuln_id, vuln.cvss, vuln.severity, vuln.note)] = vuln

    for pkg in native_packages:
        details = usable_vulns(pkg)
        if not package_is_reportable(pkg, include_none, details):
            continue
        if details:
            detailed_vulnerability_records += len(details)
        else:
            details = fallback_vulnerability(pkg)
            fallback_count_rows += 1

        display = package_display(pkg)
        location = package_locations(pkg)
        if is_direct(pkg):
            add_row(display, [display], location, details)
            continue

        raw_paths = ci_get(pkg, "PackagePaths", "PackagePath", default=[])
        chains = normalise_package_paths(raw_paths)
        if not chains:
            # Keep it visible rather than silently dropping it. The diagnostic marks this ticket.
            primary = f"Unmapped primary dependency — {display}"
            add_row(primary, [display], location, details)
            unmapped_transitive_rows += 1
            continue

        for chain in chains:
            chain_displays = [package_display(part) for part in chain]
            chain_refs = [package_ref(part) for part in chain]
            if not chain_displays:
                chain_displays = [display]
                chain_refs = [package_ref(pkg)]
            if chain_refs[-1] != package_ref(pkg) and chain_displays[-1] != display:
                chain_refs.append(package_ref(pkg))
                chain_displays.append(display)

            root_ref = chain_refs[0]
            root_display = chain_displays[0]
            primary = direct_by_ref.get(root_ref) or direct_by_display.get(root_display)
            if not primary:
                # Some reports omit the direct root from PackagePaths. Do not hide those findings.
                primary = f"Unmapped primary dependency — {root_display}"
                unmapped_transitive_rows += 1
            elif chain_displays[0] != primary:
                chain_displays.insert(0, primary)
            add_row(primary, chain_displays, location, details)

    rows: list[FindingRow] = []
    for (primary, path, location), vulns in rows_by_key.items():
        rows.append(
            FindingRow(
                primary=primary,
                package_path=path,
                location=location,
                vulnerabilities=tuple(sorted(vulns.values(), key=vulnerability_sort_key)),
            )
        )

    diagnostics = {
        "schema": "Checkmarx SCA native report",
        "top_level_keys": list(source.keys()),
        "project": project,
        "packages_total": len(native_packages),
        "direct_packages_total": len(direct_packages),
        "reportable_rows": len(rows),
        "detailed_vulnerabilities_found": detailed_vulnerability_records,
        "rows_using_count_fallback": fallback_count_rows,
        "unmapped_transitive_rows": unmapped_transitive_rows,
        "global_detail_mappings_found": sum(len(items) for items in global_details.values()),
        "warning": (
            "No per-vulnerability CVE/CVSS detail was found in the supplied report. "
            "The grouping is valid, but request/export the detailed vulnerability data "
            "before using this output for Jira remediation tickets."
            if detailed_vulnerability_records == 0
            else ""
        ),
    }
    return sort_rows(rows), diagnostics


def tickets_from_rows(project: str, rows: list[FindingRow]) -> list[Ticket]:
    grouped: dict[str, list[FindingRow]] = defaultdict(list)
    for row in rows:
        grouped[row.primary].append(row)
    return [Ticket(project=project, primary=key, rows=sort_rows(value)) for key, value in sorted(grouped.items())]


def path_text(path: tuple[str, ...]) -> str:
    return "Direct dependency" if len(path) == 1 else " > ".join(path)


def ticket_description(ticket: Ticket) -> str:
    lines = [
        f"Primary library: {ticket.primary}",
        "",
        "This ticket consolidates vulnerabilities in this direct dependency and its transitive dependency paths.",
        f"Deduplication label: {ticket.label}",
        "",
        "Affected dependency paths:",
    ]
    for index, row in enumerate(ticket.rows, start=1):
        lines.extend([f"{index}. Package path: {path_text(row.package_path)}", f"   Location: {row.location}"])
        lines.extend(f"   - {vulnerability.display()}" for vulnerability in row.vulnerabilities)
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def ticket_markdown(ticket: Ticket) -> str:
    lines = [
        f"# {ticket.summary}",
        "",
        f"**Project:** {ticket.project}  ",
        f"**Primary library:** `{ticket.primary}`  ",
        f"**Idempotency label:** `{ticket.label}`",
        "",
        "| Primary Library | Transitive Library (Package Path) | Location (File Path) | Vulnerability / CVSS Score |",
        "|---|---|---|---|",
    ]
    for index, row in enumerate(ticket.rows):
        primary = f"`{row.primary}`" if index == 0 else ""
        path = path_text(row.package_path).replace("|", r"\|")
        location = row.location.replace("|", r"\|")
        vulnerabilities = "<br>".join(item.display().replace("|", r"\|") for item in row.vulnerabilities)
        lines.append(f"| {primary} | {path} | `{location}` | {vulnerabilities} |")
    lines.extend(["", "## Jira description", "", "```text", ticket_description(ticket).rstrip(), "```", ""])
    return "\n".join(lines)


def ticket_html(ticket: Ticket) -> str:
    body_rows: list[str] = []
    for index, row in enumerate(ticket.rows):
        primary = f"<code>{html.escape(row.primary)}</code>" if index == 0 else ""
        body_rows.append(
            "<tr>"
            f"<td>{primary}</td>"
            f"<td>{html.escape(path_text(row.package_path))}</td>"
            f"<td><code>{html.escape(row.location)}</code></td>"
            f"<td>{'<br>'.join(html.escape(item.display()) for item in row.vulnerabilities)}</td>"
            "</tr>"
        )
    return (
        f"<section><h2>{html.escape(ticket.summary)}</h2>"
        f"<p><strong>Project:</strong> {html.escape(ticket.project)}<br>"
        f"<strong>Idempotency label:</strong> <code>{html.escape(ticket.label)}</code></p>"
        "<table><thead><tr><th>Primary Library</th><th>Transitive Library (Package Path)</th>"
        "<th>Location (File Path)</th><th>Vulnerability / CVSS Score</th>"
        "</tr></thead><tbody>"
        + "".join(body_rows)
        + "</tbody></table></section>"
    )


def safe_filename(value: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9._-]+", "_", value).strip("_")
    return cleaned[:110] or "ticket"


def write_outputs(out_dir: Path, tickets: list[Ticket], diagnostics: dict[str, Any]) -> None:
    ticket_dir = out_dir / "tickets"
    ticket_dir.mkdir(parents=True, exist_ok=True)
    overview = [
        "# Checkmarx SCA consolidated Jira ticket preview",
        "",
        f"Tickets generated: **{len(tickets)}**",
        "",
        "| Primary library | Unique vulnerability entries | Preview |",
        "|---|---:|---|",
    ]
    sections: list[str] = []

    for ticket in tickets:
        filename = safe_filename(ticket.primary)
        markdown_name = f"{filename}.md"
        (ticket_dir / markdown_name).write_text(ticket_markdown(ticket), encoding="utf-8")
        payload = {
            "summary": ticket.summary,
            "description": ticket_description(ticket),
            "labels": [ticket.label, "sca"],
            "project": ticket.project,
            "primary_library": ticket.primary,
            "rows": [
                {
                    "primary": row.primary,
                    "package_path": list(row.package_path),
                    "location": row.location,
                    "vulnerabilities": [asdict(vulnerability) for vulnerability in row.vulnerabilities],
                }
                for row in ticket.rows
            ],
        }
        (ticket_dir / f"{filename}.json").write_text(json.dumps(payload, indent=2), encoding="utf-8")
        overview.append(
            f"| `{ticket.primary}` | {len(ticket.unique_vulnerabilities)} | [Open preview](tickets/{markdown_name}) |"
        )
        sections.append(ticket_html(ticket))

    (out_dir / "README.md").write_text("\n".join(overview) + "\n", encoding="utf-8")
    (out_dir / "schema_diagnostics.json").write_text(json.dumps(diagnostics, indent=2), encoding="utf-8")
    page = """<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>Checkmarx SCA Jira Preview</title>
<style>
body { font-family: Arial, sans-serif; margin: 32px; color: #1f2937; }
section { margin-bottom: 36px; page-break-inside: avoid; }
table { border-collapse: collapse; width: 100%; font-size: 13px; }
th { background: #173f5f; color: #fff; text-align: left; }
th, td { border: 1px solid #bcc6d0; padding: 10px; vertical-align: top; }
td:first-child { width: 17%; font-weight: 600; }
td:nth-child(2) { width: 37%; }
td:nth-child(3) { width: 27%; }
td:nth-child(4) { width: 19%; }
code { font-family: Consolas, monospace; font-size: 12px; }
</style></head><body>
<h1>Checkmarx SCA consolidated Jira ticket preview</h1>
<p>One section equals one Jira ticket for one primary/direct dependency.</p>
""" + "\n".join(sections) + "\n</body></html>\n"
    (out_dir / "consolidated_preview.html").write_text(page, encoding="utf-8")


def load_json(path: Path, max_json_bytes: int | None = DEFAULT_MAX_REPORT_BYTES) -> dict[str, Any]:
    if not path.exists():
        raise ConsolidationError(f"Input file does not exist: {path}")
    if max_json_bytes is not None and path.stat().st_size > max_json_bytes:
        raise ConsolidationError(
            f"Input file is too large ({path.stat().st_size} bytes; limit {max_json_bytes} bytes)."
        )
    raw = path.read_bytes()
    if raw[:4] == b"PK\x03\x04":
        with zipfile.ZipFile(BytesIO(raw)) as archive:
            json_files = [name for name in archive.namelist() if name.lower().endswith(".json")]
            if not json_files:
                raise ConsolidationError("The ZIP does not contain a JSON report.")
            preferred = next((name for name in json_files if "scanreport" in name.lower()), json_files[0])
            info = archive.getinfo(preferred)
            if max_json_bytes is not None and info.file_size > max_json_bytes:
                raise ConsolidationError(
                    f"JSON report inside ZIP is too large ({info.file_size} bytes; limit {max_json_bytes} bytes)."
                )
            raw = archive.read(preferred)
    try:
        data = json.loads(raw.decode("utf-8-sig"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ConsolidationError(f"Input is not valid JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise ConsolidationError("Top-level JSON must be an object.")
    return data


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Create Jira-ready ticket previews from native Checkmarx SCA JSON.")
    parser.add_argument("--input", type=Path, required=True, help="Local SCA_ScanReport.json or a ZIP containing it.")
    parser.add_argument("--out", type=Path, default=Path("./jira_ready_output"), help="Output directory.")
    parser.add_argument("--project", help="Override project name. Defaults to RiskReportSummary.ProjectName.")
    parser.add_argument("--include-none-severity", action="store_true", help="Include packages with only None severity findings.")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    source = load_json(args.input)
    summary = ci_get(source, "RiskReportSummary", default={})
    project = args.project or text(ci_get(summary, "ProjectName"), "Unknown project")
    rows, diagnostics = parse_native(source, project, args.include_none_severity)
    if not rows:
        raise ConsolidationError(
            "No reportable packages remain after filtering. The report contains Packages but has no Critical/High/Medium/Low findings."
        )
    tickets = tickets_from_rows(project, rows)
    args.out.mkdir(parents=True, exist_ok=True)
    write_outputs(args.out, tickets, diagnostics)
    print(f"Generated {len(tickets)} Jira-ready ticket preview(s): {args.out.resolve()}")
    print(f"Open: {args.out.resolve() / 'consolidated_preview.html'}")
    print(f"Diagnostics: {args.out.resolve() / 'schema_diagnostics.json'}")
    if diagnostics["warning"]:
        print(f"WARNING: {diagnostics['warning']}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except ConsolidationError as error:
        print(f"ERROR: {error}", file=sys.stderr)
        raise SystemExit(2)
