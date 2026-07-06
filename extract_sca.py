#!/usr/bin/env python3
"""
Checkmarx SCA -> Jira-ready dependency consolidation.

Purpose
-------
Creates one Jira-ready ticket body per direct/primary dependency and lists:
  * direct vulnerabilities
  * every vulnerable transitive dependency path
  * manifest/file location when it exists in the SBOM
  * CVE/Cx ID, CVSS score, and severity

Input modes
-----------
1) A local CycloneDX JSON SBOM:
   python3 checkmarx_sca_consolidator.py --input bom.json --project agTracker --out ./out

2) A Checkmarx SCA Export Service download:
   export CX_SCA_TOKEN='<access token>'
   python3 checkmarx_sca_consolidator.py --fetch-from-checkmarx \
       --scan-id '<scan uuid>' --project agTracker --out ./out

3) A normalized JSON file (see --write-sample for the supported shape).

The script deliberately defaults to output-only. Jira publication only happens when
--publish-jira is specified.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import html
import json
import os
import re
import sys
import time
import zipfile
from collections import defaultdict
from dataclasses import asdict, dataclass
from io import BytesIO
from pathlib import Path
from typing import Any, Iterable, Optional

try:
    import requests
except ImportError as exc:
    raise SystemExit(
        "Missing dependency 'requests'. Install it with: python3 -m pip install requests"
    ) from exc


DEFAULT_SCA_BASE_URL = "https://api-sca.checkmarx.net"
SEVERITY_ORDER = {
    "critical": 5,
    "high": 4,
    "medium": 3,
    "moderate": 3,
    "low": 2,
    "info": 1,
    "informational": 1,
    "unknown": 0,
    "unspecified": 0,
    "": 0,
}


class ConsolidationError(RuntimeError):
    """Raised when the source does not contain enough data to build a report."""


@dataclass(frozen=True)
class Vulnerability:
    vuln_id: str
    cvss: Optional[float]
    severity: str

    def display(self) -> str:
        cvss = f" | CVSS {self.cvss:g}" if self.cvss is not None else ""
        severity = f" | {self.severity.title()}" if self.severity else ""
        return f"{self.vuln_id}{cvss}{severity}"


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
        digest = hashlib.sha256(
            f"{self.project}|{self.primary}".encode("utf-8")
        ).hexdigest()[:12]
        return f"cxsca-{digest}"

    @property
    def summary(self) -> str:
        return f"[SCA] {self.primary} — vulnerable dependency chain(s)"

    @property
    def unique_vulnerabilities(self) -> list[Vulnerability]:
        found: dict[tuple[str, Optional[float], str], Vulnerability] = {}
        for row in self.rows:
            for vuln in row.vulnerabilities:
                found[(vuln.vuln_id, vuln.cvss, vuln.severity)] = vuln
        return sorted(
            found.values(),
            key=lambda item: (
                -SEVERITY_ORDER.get(item.severity.lower(), 0),
                -(item.cvss if item.cvss is not None else -1),
                item.vuln_id,
            ),
        )


def _as_float(value: Any) -> Optional[float]:
    if value in (None, "", "N/A", "n/a"):
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _norm_text(value: Any, default: str = "") -> str:
    if value is None:
        return default
    text = str(value).strip()
    return text if text else default


def component_display(component: Any) -> str:
    """Return a stable, readable component name from CycloneDX or normalized input."""
    if isinstance(component, str):
        return component.strip()

    if not isinstance(component, dict):
        return _norm_text(component, "Unknown package")

    group = _norm_text(component.get("group"))
    name = _norm_text(
        component.get("name")
        or component.get("packageName")
        or component.get("package")
        or component.get("artifactId")
        or component.get("id")
    )
    version = _norm_text(component.get("version") or component.get("packageVersion"))

    if not name:
        purl = _norm_text(component.get("purl") or component.get("bom-ref"))
        if purl:
            return purl
        return "Unknown package"

    base = f"{group}:{name}" if group else name
    return f"{base} @ {version}" if version else base


def component_ref(component: dict[str, Any]) -> str:
    ref = _norm_text(
        component.get("bom-ref")
        or component.get("ref")
        or component.get("purl")
        or component.get("id")
    )
    return ref or component_display(component)


def component_location(component: dict[str, Any]) -> str:
    """Extract a location from standard CycloneDX evidence or Checkmarx-style properties."""
    evidence = component.get("evidence")
    if isinstance(evidence, dict):
        occurrences = evidence.get("occurrences", [])
        if isinstance(occurrences, list):
            locations = [
                _norm_text(item.get("location"))
                for item in occurrences
                if isinstance(item, dict) and _norm_text(item.get("location"))
            ]
            if locations:
                return "; ".join(dict.fromkeys(locations))

    # Checkmarx exports can place supplemental data in CycloneDX properties.
    properties = component.get("properties", [])
    if isinstance(properties, list):
        candidates: list[str] = []
        for item in properties:
            if not isinstance(item, dict):
                continue
            key = _norm_text(item.get("name")).lower()
            value = _norm_text(item.get("value"))
            if value and any(token in key for token in ("path", "location", "manifest", "file")):
                candidates.append(value)
        if candidates:
            return "; ".join(dict.fromkeys(candidates))

    for key in ("location", "filePath", "file_path", "manifestPath", "manifest_path"):
        value = _norm_text(component.get(key))
        if value:
            return value

    return "Not supplied by source"


def flatten_components(components: Any) -> list[dict[str, Any]]:
    """CycloneDX normally uses a flat components array, but tolerate nested components."""
    flattened: list[dict[str, Any]] = []

    def visit(items: Any) -> None:
        if not isinstance(items, list):
            return
        for item in items:
            if not isinstance(item, dict):
                continue
            flattened.append(item)
            visit(item.get("components"))

    visit(components)
    return flattened


def choose_rating(vulnerability: dict[str, Any]) -> tuple[Optional[float], str]:
    """Choose the strongest available score from a CycloneDX vulnerability."""
    ratings = vulnerability.get("ratings", [])
    candidates: list[tuple[Optional[float], str]] = []

    if isinstance(ratings, list):
        for rating in ratings:
            if not isinstance(rating, dict):
                continue
            score = _as_float(
                rating.get("score")
                or rating.get("baseScore")
                or rating.get("cvssScore")
            )
            severity = _norm_text(
                rating.get("severity") or rating.get("baseSeverity") or "Unspecified"
            ).lower()
            candidates.append((score, severity))

    if not candidates:
        score = _as_float(
            vulnerability.get("score")
            or vulnerability.get("cvss")
            or vulnerability.get("cvssScore")
        )
        severity = _norm_text(vulnerability.get("severity") or "Unspecified").lower()
        return score, severity

    candidates.sort(
        key=lambda item: (
            item[0] is not None,
            item[0] if item[0] is not None else -1,
            SEVERITY_ORDER.get(item[1], 0),
        ),
        reverse=True,
    )
    return candidates[0]


def extract_vulnerabilities_from_cdx(
    bom: dict[str, Any], include_none_severity: bool
) -> dict[str, tuple[Vulnerability, ...]]:
    """
    Build: affected component ref -> vulnerabilities.

    CycloneDX uses:
        vulnerabilities[].affects[].ref
    """
    affected: dict[str, dict[tuple[str, Optional[float], str], Vulnerability]] = defaultdict(dict)

    raw_vulnerabilities = bom.get("vulnerabilities", [])
    if not isinstance(raw_vulnerabilities, list):
        return {}

    for item in raw_vulnerabilities:
        if not isinstance(item, dict):
            continue

        source = item.get("source")
        source_name = source.get("name") if isinstance(source, dict) else ""
        vuln_id = _norm_text(item.get("id") or source_name or item.get("bom-ref") or item.get("name"))
        if not vuln_id:
            continue

        score, severity = choose_rating(item)
        if not include_none_severity and severity.lower() == "none":
            continue

        vulnerability = Vulnerability(vuln_id=vuln_id, cvss=score, severity=severity)
        affects = item.get("affects", [])

        # Some SBOM producers use analysis.component / affects as a single object.
        if isinstance(affects, dict):
            affects = [affects]
        if not isinstance(affects, list):
            affects = []

        for affected_item in affects:
            if isinstance(affected_item, str):
                ref = affected_item
            elif isinstance(affected_item, dict):
                ref = _norm_text(affected_item.get("ref") or affected_item.get("bom-ref"))
            else:
                ref = ""
            if ref:
                affected[ref][(vulnerability.vuln_id, vulnerability.cvss, vulnerability.severity)] = vulnerability

    return {
        ref: tuple(
            sorted(
                vuln_map.values(),
                key=lambda item: (
                    -SEVERITY_ORDER.get(item.severity.lower(), 0),
                    -(item.cvss if item.cvss is not None else -1),
                    item.vuln_id,
                ),
            )
        )
        for ref, vuln_map in affected.items()
    }


def all_paths(
    graph: dict[str, list[str]],
    start: str,
    target: str,
    max_paths: int,
) -> list[list[str]]:
    """Find all simple dependency paths from one direct component to a target."""
    paths: list[list[str]] = []

    def visit(node: str, path: list[str], seen: set[str]) -> None:
        if len(paths) >= max_paths:
            return
        if node == target:
            paths.append(path.copy())
            return
        for child in graph.get(node, []):
            if child in seen:
                continue
            visit(child, path + [child], seen | {child})

    visit(start, [start], {start})
    return paths


def parse_cyclonedx(
    bom: dict[str, Any],
    project: str,
    include_none_severity: bool,
    max_paths_per_vulnerable_component: int,
) -> list[FindingRow]:
    components = flatten_components(bom.get("components", []))
    component_map: dict[str, dict[str, Any]] = {
        component_ref(component): component for component in components
    }

    metadata_component = bom.get("metadata", {}).get("component")
    if isinstance(metadata_component, dict):
        component_map.setdefault(component_ref(metadata_component), metadata_component)

    graph: dict[str, list[str]] = {}
    for dependency in bom.get("dependencies", []):
        if not isinstance(dependency, dict):
            continue
        parent = _norm_text(dependency.get("ref"))
        children = dependency.get("dependsOn", [])
        if parent and isinstance(children, list):
            graph[parent] = [_norm_text(child) for child in children if _norm_text(child)]

    vulnerability_map = extract_vulnerabilities_from_cdx(bom, include_none_severity)
    if not vulnerability_map:
        raise ConsolidationError(
            "No component-linked vulnerabilities were found in the CycloneDX SBOM. "
            "Check that the Checkmarx export contains a top-level 'vulnerabilities' "
            "array with 'affects[].ref' mappings. Save the raw export and we can "
            "add a tenant-specific adapter if its schema differs."
        )

    root_ref = ""
    if isinstance(metadata_component, dict):
        root_ref = component_ref(metadata_component)

    direct_refs = graph.get(root_ref, []) if root_ref else []
    if not direct_refs:
        # Fall back to components not listed as children in the graph.
        child_refs = {child for children in graph.values() for child in children}
        candidates = [ref for ref in graph if ref not in child_refs and ref != root_ref]
        direct_refs = candidates or list(vulnerability_map.keys())

    rows_by_key: dict[tuple[str, tuple[str, ...], str], dict[tuple[str, Optional[float], str], Vulnerability]] = defaultdict(dict)

    for affected_ref, vulnerabilities in vulnerability_map.items():
        if affected_ref not in component_map:
            # SBOMs sometimes refer to an omitted package by purl; show it rather than discard it.
            component_map[affected_ref] = {"bom-ref": affected_ref, "name": affected_ref}

        target_location = component_location(component_map[affected_ref])
        found_path = False

        for direct_ref in direct_refs:
            for path_refs in all_paths(
                graph,
                direct_ref,
                affected_ref,
                max_paths=max_paths_per_vulnerable_component,
            ):
                found_path = True
                path_display = tuple(
                    component_display(component_map.get(ref, {"bom-ref": ref, "name": ref}))
                    for ref in path_refs
                )
                primary = path_display[0]
                key = (primary, path_display, target_location)
                for vulnerability in vulnerabilities:
                    rows_by_key[key][
                        (vulnerability.vuln_id, vulnerability.cvss, vulnerability.severity)
                    ] = vulnerability

        if not found_path:
            # Keep the finding visible even when the SBOM did not include dependency edges.
            target_display = component_display(component_map[affected_ref])
            key = (target_display, (target_display,), target_location)
            for vulnerability in vulnerabilities:
                rows_by_key[key][
                    (vulnerability.vuln_id, vulnerability.cvss, vulnerability.severity)
                ] = vulnerability

    rows: list[FindingRow] = []
    for (primary, path, location), vuln_map in rows_by_key.items():
        vulnerabilities = tuple(
            sorted(
                vuln_map.values(),
                key=lambda item: (
                    -SEVERITY_ORDER.get(item.severity.lower(), 0),
                    -(item.cvss if item.cvss is not None else -1),
                    item.vuln_id,
                ),
            )
        )
        rows.append(
            FindingRow(
                primary=primary,
                package_path=path,
                location=location,
                vulnerabilities=vulnerabilities,
            )
        )

    return sort_rows(rows)


def parse_normalized(
    source: dict[str, Any],
    project: str,
    include_none_severity: bool,
) -> list[FindingRow]:
    """
    Parse a simple normalized source for testing or for a tenant-specific adapter.

    Example finding:
    {
      "primary": {"group": "com.itextpdf", "name": "forms", "version": "7.1.19"},
      "package_path": [
        {"group": "com.itextpdf", "name": "forms", "version": "7.1.19"},
        {"group": "com.itextpdf", "name": "kernel", "version": "7.1.19"}
      ],
      "location": "lib/itext/forms-7.1.19/META-INF/maven/.../pom.xml",
      "vulnerabilities": [{"id": "CVE-2022-34169", "cvss": 7.5, "severity": "High"}]
    }
    """
    findings = source.get("findings", source.get("records", []))
    if not isinstance(findings, list):
        raise ConsolidationError(
            "Normalized input needs a top-level 'findings' or 'records' array."
        )

    rows_by_key: dict[tuple[str, tuple[str, ...], str], dict[tuple[str, Optional[float], str], Vulnerability]] = defaultdict(dict)

    for finding in findings:
        if not isinstance(finding, dict):
            continue

        primary = component_display(finding.get("primary") or finding.get("direct") or "Unknown package")
        raw_path = finding.get("package_path") or finding.get("path") or [finding.get("primary")]
        if not isinstance(raw_path, list):
            raw_path = [raw_path]

        path = tuple(component_display(item) for item in raw_path if item)
        if not path:
            path = (primary,)
        if path[0] == "Unknown package":
            path = (primary,) + path[1:]

        location = _norm_text(
            finding.get("location")
            or finding.get("file_path")
            or finding.get("filePath")
            or "Not supplied by source"
        )

        raw_vulnerabilities = finding.get("vulnerabilities", [])
        if isinstance(raw_vulnerabilities, dict):
            raw_vulnerabilities = [raw_vulnerabilities]

        for raw_vuln in raw_vulnerabilities:
            if not isinstance(raw_vuln, dict):
                continue
            vuln_id = _norm_text(raw_vuln.get("id") or raw_vuln.get("cve") or raw_vuln.get("name"))
            if not vuln_id:
                continue
            severity = _norm_text(raw_vuln.get("severity") or "Unspecified").lower()
            if not include_none_severity and severity == "none":
                continue

            vulnerability = Vulnerability(
                vuln_id=vuln_id,
                cvss=_as_float(raw_vuln.get("cvss") or raw_vuln.get("score")),
                severity=severity,
            )
            key = (primary, path, location)
            rows_by_key[key][
                (vulnerability.vuln_id, vulnerability.cvss, vulnerability.severity)
            ] = vulnerability

    rows: list[FindingRow] = []
    for (primary, path, location), vulnerabilities in rows_by_key.items():
        if vulnerabilities:
            rows.append(
                FindingRow(
                    primary=primary,
                    package_path=path,
                    location=location,
                    vulnerabilities=tuple(vulnerabilities.values()),
                )
            )
    return sort_rows(rows)


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


def tickets_from_rows(project: str, rows: list[FindingRow]) -> list[Ticket]:
    grouped: dict[str, list[FindingRow]] = defaultdict(list)
    for row in rows:
        grouped[row.primary].append(row)

    tickets = [Ticket(project=project, primary=primary, rows=sort_rows(items)) for primary, items in grouped.items()]
    return sorted(tickets, key=lambda ticket: ticket.primary.lower())


def vuln_cell(vulnerabilities: Iterable[Vulnerability], html_mode: bool = False) -> str:
    separator = "<br>" if html_mode else "<br>"
    return separator.join(html.escape(item.display()) if html_mode else item.display() for item in vulnerabilities)


def path_cell(path: tuple[str, ...], html_mode: bool = False) -> str:
    if len(path) == 1:
        return "Direct dependency"
    separator = " &gt; " if html_mode else " > "
    values = [html.escape(item) if html_mode else item for item in path]
    return separator.join(values)


def ticket_description(ticket: Ticket) -> str:
    direct_vulnerabilities: list[Vulnerability] = []
    for row in ticket.rows:
        if row.is_direct:
            direct_vulnerabilities.extend(row.vulnerabilities)

    direct_by_key = {
        (item.vuln_id, item.cvss, item.severity): item for item in direct_vulnerabilities
    }

    lines = [
        f"Primary library: {ticket.primary}",
        "",
        "This ticket consolidates vulnerabilities in this direct dependency and its "
        "transitive dependency chains. Upgrade or override the primary dependency "
        "where possible; otherwise pin the transitive dependency to a secure version.",
        "",
        f"Deduplication label: {ticket.label}",
        "",
    ]

    if direct_by_key:
        lines.extend(["Direct vulnerability:", *[
            f"- {item.display()}" for item in sorted(
                direct_by_key.values(),
                key=lambda value: (
                    -SEVERITY_ORDER.get(value.severity.lower(), 0),
                    -(value.cvss if value.cvss is not None else -1),
                    value.vuln_id,
                ),
            )
        ], ""])

    lines.append("Affected dependency paths:")
    for index, row in enumerate(ticket.rows, start=1):
        lines.append(f"{index}. Package path: {path_cell(row.package_path)}")
        lines.append(f"   Location: {row.location}")
        for vulnerability in row.vulnerabilities:
            lines.append(f"   - {vulnerability.display()}")
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
        "This ticket consolidates the direct dependency and all vulnerable transitive "
        "dependency chains that originate from it.",
        "",
        "| Primary Library | Transitive Library (Package Path) | Location (File Path) | Vulnerability / CVSS Score |",
        "|---|---|---|---|",
    ]

    for index, row in enumerate(ticket.rows):
        primary = f"`{row.primary}`" if index == 0 else ""
        path = path_cell(row.package_path).replace("|", r"\|")
        location = row.location.replace("|", r"\|")
        vulnerabilities = vuln_cell(row.vulnerabilities).replace("|", r"\|")
        lines.append(f"| {primary} | {path} | `{location}` | {vulnerabilities} |")

    lines.extend(["", "## Jira description", "", "```text", ticket_description(ticket).rstrip(), "```", ""])
    return "\n".join(lines)


def ticket_html(ticket: Ticket) -> str:
    rows_html: list[str] = []
    for index, row in enumerate(ticket.rows):
        primary = f"<code>{html.escape(row.primary)}</code>" if index == 0 else ""
        rows_html.append(
            "<tr>"
            f"<td>{primary}</td>"
            f"<td>{path_cell(row.package_path, html_mode=True)}</td>"
            f"<td><code>{html.escape(row.location)}</code></td>"
            f"<td>{vuln_cell(row.vulnerabilities, html_mode=True)}</td>"
            "</tr>"
        )

    return (
        f"<section><h2>{html.escape(ticket.summary)}</h2>"
        f"<p><strong>Project:</strong> {html.escape(ticket.project)}<br>"
        f"<strong>Idempotency label:</strong> <code>{html.escape(ticket.label)}</code></p>"
        "<table><thead><tr>"
        "<th>Primary Library</th><th>Transitive Library (Package Path)</th>"
        "<th>Location (File Path)</th><th>Vulnerability / CVSS Score</th>"
        "</tr></thead><tbody>"
        + "".join(rows_html)
        + "</tbody></table></section>"
    )


def safe_filename(value: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9._-]+", "_", value).strip("_")
    return cleaned[:110] or "ticket"


def write_outputs(out_dir: Path, tickets: list[Ticket]) -> None:
    tickets_dir = out_dir / "tickets"
    tickets_dir.mkdir(parents=True, exist_ok=True)

    index_lines = [
        "# Checkmarx SCA consolidated Jira ticket preview",
        "",
        f"Tickets generated: **{len(tickets)}**",
        "",
        "| Primary library | Vulnerabilities | Ticket preview |",
        "|---|---:|---|",
    ]
    sections: list[str] = []

    for ticket in tickets:
        filename = safe_filename(ticket.primary)
        markdown_name = f"{filename}.md"
        json_name = f"{filename}.json"

        (tickets_dir / markdown_name).write_text(ticket_markdown(ticket), encoding="utf-8")
        ticket_payload = {
            "summary": ticket.summary,
            "description": ticket_description(ticket),
            "labels": [ticket.label, "sca"],
            "primary_library": ticket.primary,
            "project": ticket.project,
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
        (tickets_dir / json_name).write_text(
            json.dumps(ticket_payload, indent=2), encoding="utf-8"
        )

        index_lines.append(
            f"| `{ticket.primary}` | {len(ticket.unique_vulnerabilities)} | "
            f"[Open ticket preview](tickets/{markdown_name}) |"
        )
        sections.append(ticket_html(ticket))

    (out_dir / "README.md").write_text("\n".join(index_lines) + "\n", encoding="utf-8")

    page = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Checkmarx SCA Jira preview</title>
<style>
body { font-family: Arial, sans-serif; margin: 32px; color: #1f2937; }
section { margin: 0 0 36px; page-break-inside: avoid; }
table { border-collapse: collapse; width: 100%; font-size: 13px; }
th { background: #173f5f; color: #fff; text-align: left; }
th, td { border: 1px solid #bcc6d0; padding: 10px; vertical-align: top; }
td:first-child { width: 17%; font-weight: 600; }
td:nth-child(2) { width: 37%; }
td:nth-child(3) { width: 27%; }
td:nth-child(4) { width: 19%; }
code { font-family: Consolas, monospace; font-size: 12px; }
</style>
</head>
<body>
<h1>Checkmarx SCA consolidated Jira ticket preview</h1>
<p>One section equals one Jira ticket for one primary/direct dependency.</p>
""" + "\n".join(sections) + "\n</body></html>\n"
    (out_dir / "consolidated_preview.html").write_text(page, encoding="utf-8")


class CheckmarxSCAExportClient:
    """Small client for the documented Checkmarx SCA Export Service."""

    def __init__(self, base_url: str, access_token: str, timeout: int = 60) -> None:
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update(
            {
                "Authorization": f"Bearer {access_token}",
                "Content-Type": "application/json",
                "Accept": "application/json",
                # Checkmarx documents this header for service-authenticated export requests.
                "Cx-Authentication-Type": "service",
            }
        )

    @staticmethod
    def _first_value(payload: Any, keys: tuple[str, ...]) -> Optional[Any]:
        if isinstance(payload, dict):
            for key in keys:
                if key in payload and payload[key] not in (None, ""):
                    return payload[key]
            for value in payload.values():
                found = CheckmarxSCAExportClient._first_value(value, keys)
                if found not in (None, ""):
                    return found
        elif isinstance(payload, list):
            for item in payload:
                found = CheckmarxSCAExportClient._first_value(item, keys)
                if found not in (None, ""):
                    return found
        return None

    def download_cyclonedx(
        self,
        scan_id: str,
        destination: Path,
        poll_seconds: int = 3,
        max_wait_seconds: int = 180,
    ) -> Path:
        create_payload = {
            "ScanId": scan_id,
            "FileFormat": "CycloneDxJson",
            "ExportParameters": {
                "hideDevAndTestDependencies": False,
                "showOnlyEffectiveLicenses": False,
            },
        }
        response = self.session.post(
            f"{self.base_url}/export/requests",
            json=create_payload,
            timeout=self.timeout,
        )
        response.raise_for_status()
        export_id = self._first_value(response.json(), ("exportId", "ExportId", "id"))
        if not export_id:
            raise ConsolidationError(
                f"Checkmarx did not return an export ID. Response: {response.text[:500]}"
            )

        deadline = time.time() + max_wait_seconds
        file_url: Optional[str] = None
        last_status = "unknown"

        while time.time() < deadline:
            status_response = self.session.get(
                f"{self.base_url}/export/requests",
                params={"exportId": export_id},
                timeout=self.timeout,
            )
            status_response.raise_for_status()
            payload = status_response.json()
            file_url = self._first_value(payload, ("fileUrl", "fileURL", "downloadUrl", "url"))
            last_status = _norm_text(
                self._first_value(payload, ("status", "Status", "state")),
                "unknown",
            ).lower()

            if file_url:
                break
            if last_status in {"failed", "failure", "error", "cancelled", "canceled"}:
                raise ConsolidationError(
                    f"Checkmarx export {export_id} ended with status '{last_status}': "
                    f"{json.dumps(payload)[:800]}"
                )
            time.sleep(poll_seconds)

        if not file_url:
            raise ConsolidationError(
                f"Timed out waiting for Checkmarx export {export_id}; last status: {last_status}"
            )

        # Checkmarx may return a signed URL or an API URL. Send the auth header either way.
        file_response = self.session.get(file_url, timeout=self.timeout)
        file_response.raise_for_status()

        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(file_response.content)
        return destination


class JiraClient:
    """Minimal Jira REST v2 client with idempotent create-or-update behavior."""

    def __init__(
        self,
        base_url: str,
        auth_mode: str,
        email: Optional[str],
        token: str,
        timeout: int = 60,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({"Accept": "application/json", "Content-Type": "application/json"})

        if auth_mode == "bearer":
            self.session.headers["Authorization"] = f"Bearer {token}"
        elif auth_mode == "basic":
            if not email:
                raise ConsolidationError("Jira basic auth needs --jira-email or JIRA_EMAIL.")
            token_value = base64.b64encode(f"{email}:{token}".encode("utf-8")).decode("ascii")
            self.session.headers["Authorization"] = f"Basic {token_value}"
        else:
            raise ConsolidationError("Jira auth mode must be 'basic' or 'bearer'.")

    def find_issue(self, project_key: str, label: str) -> Optional[str]:
        jql = f'project = "{project_key}" AND labels = "{label}" ORDER BY created DESC'
        response = self.session.get(
            f"{self.base_url}/rest/api/2/search",
            params={"jql": jql, "maxResults": 1, "fields": "key"},
            timeout=self.timeout,
        )
        response.raise_for_status()
        issues = response.json().get("issues", [])
        return issues[0].get("key") if issues else None

    def create_or_update(
        self,
        ticket: Ticket,
        project_key: str,
        issue_type: str,
        additional_labels: list[str],
    ) -> str:
        fields = {
            "project": {"key": project_key},
            "summary": ticket.summary,
            # Jira REST v2 accepts a plain-text description on common Server/Data Center
            # deployments. For Jira Cloud rich-text ADF, switch this field to ADF.
            "description": ticket_description(ticket),
            "issuetype": {"name": issue_type},
            "labels": sorted(set([ticket.label, "sca", *additional_labels])),
        }

        existing_key = self.find_issue(project_key, ticket.label)
        if existing_key:
            response = self.session.put(
                f"{self.base_url}/rest/api/2/issue/{existing_key}",
                json={"fields": fields},
                timeout=self.timeout,
            )
            response.raise_for_status()
            return f"updated {existing_key}"

        response = self.session.post(
            f"{self.base_url}/rest/api/2/issue",
            json={"fields": fields},
            timeout=self.timeout,
        )
        response.raise_for_status()
        issue_key = response.json().get("key", "created issue")
        return f"created {issue_key}"


def load_json_from_bytes(raw: bytes) -> dict[str, Any]:
    """Accept a bare JSON export or a zip containing one or more JSON files."""
    if raw[:4] == b"PK\x03\x04":
        with zipfile.ZipFile(BytesIO(raw)) as archive:
            json_members = [name for name in archive.namelist() if name.lower().endswith(".json")]
            if not json_members:
                raise ConsolidationError("The exported ZIP does not contain a JSON file.")
            # Prefer a CycloneDX-like file name when it exists.
            selected = next(
                (name for name in json_members if "cyclone" in name.lower() or "bom" in name.lower()),
                json_members[0],
            )
            raw = archive.read(selected)

    try:
        loaded = json.loads(raw.decode("utf-8-sig"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ConsolidationError(f"Input is not valid JSON: {exc}") from exc

    if not isinstance(loaded, dict):
        raise ConsolidationError("The top-level JSON value must be an object.")
    return loaded


def load_input(path: Path) -> dict[str, Any]:
    if not path.exists():
        raise ConsolidationError(f"Input file does not exist: {path}")
    return load_json_from_bytes(path.read_bytes())


def create_sample(path: Path) -> None:
    """Write a small CycloneDX sample modelled on the itext example in the email."""
    root = "pkg:maven/com.arisglobal/agtracker@1.0.0"
    forms = "pkg:maven/com.itextpdf/forms@7.1.19"
    kernel = "pkg:maven/com.itextpdf/kernel@7.1.19"
    io = "pkg:maven/com.itextpdf/io@7.1.19"
    batik_bridge = "pkg:maven/org.apache.xmlgraphics/batik-bridge@1.14"
    batik_script = "pkg:maven/org.apache.xmlgraphics/batik-script@1.14"
    location = "lib/itext/forms-7.1.19/META-INF/maven/com.itextpdf/forms/pom.xml"

    def component(ref: str, group: str, name: str, version: str, evidence_location: str = "") -> dict[str, Any]:
        value: dict[str, Any] = {
            "type": "library",
            "bom-ref": ref,
            "group": group,
            "name": name,
            "version": version,
            "purl": ref,
        }
        if evidence_location:
            value["evidence"] = {"occurrences": [{"location": evidence_location}]}
        return value

    sample = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": "urn:uuid:demo-cx-sca",
        "metadata": {
            "component": component(root, "com.arisglobal", "agtracker", "1.0.0")
        },
        "components": [
            component(forms, "com.itextpdf", "forms", "7.1.19", location),
            component(kernel, "com.itextpdf", "kernel", "7.1.19", location),
            component(io, "com.itextpdf", "io", "7.1.19", location),
            component(batik_bridge, "org.apache.xmlgraphics", "batik-bridge", "1.14", location),
            component(batik_script, "org.apache.xmlgraphics", "batik-script", "1.14", location),
        ],
        "dependencies": [
            {"ref": root, "dependsOn": [forms]},
            {"ref": forms, "dependsOn": [kernel]},
            {"ref": kernel, "dependsOn": [io, batik_bridge, batik_script]},
            {"ref": io, "dependsOn": []},
            {"ref": batik_bridge, "dependsOn": []},
            {"ref": batik_script, "dependsOn": []},
        ],
        "vulnerabilities": [
            {
                "id": "Cxa:9261daf-3755",
                "ratings": [{"method": "CVSSv3", "score": 9.8, "severity": "critical"}],
                "affects": [{"ref": forms}],
            },
            {
                "id": "CVE-2024-30179",
                "ratings": [{"method": "CVSSv3", "score": 5.9, "severity": "medium"}],
                "affects": [{"ref": forms}],
            },
            {
                "id": "CVE-2022-34169",
                "ratings": [{"method": "CVSSv3", "score": 7.5, "severity": "high"}],
                "affects": [{"ref": io}],
            },
            {
                "id": "CVE-2022-40146",
                "ratings": [{"method": "CVSSv3", "score": 7.5, "severity": "high"}],
                "affects": [{"ref": batik_bridge}, {"ref": batik_script}],
            },
            {
                "id": "CVE-2022-41704",
                "ratings": [{"method": "CVSSv3", "score": 7.5, "severity": "high"}],
                "affects": [{"ref": batik_bridge}, {"ref": batik_script}],
            },
            {
                "id": "CVE-2022-44729",
                "ratings": [{"method": "CVSSv3", "score": 7.1, "severity": "high"}],
                "affects": [{"ref": batik_bridge}, {"ref": batik_script}],
            },
            {
                "id": "CVE-2022-38398",
                "ratings": [{"method": "CVSSv3", "score": 5.3, "severity": "medium"}],
                "affects": [{"ref": batik_bridge}, {"ref": batik_script}],
            },
            {
                "id": "CVE-2022-38648",
                "ratings": [{"method": "CVSSv3", "score": 5.3, "severity": "medium"}],
                "affects": [{"ref": batik_bridge}, {"ref": batik_script}],
            },
            {
                "id": "CVE-DEMO-NONE",
                "ratings": [{"method": "CVSSv3", "score": 0.0, "severity": "none"}],
                "affects": [{"ref": io}],
            },
        ],
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(sample, indent=2), encoding="utf-8")


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Generate one Jira-ready SCA ticket per primary dependency."
    )
    source_group = parser.add_mutually_exclusive_group(required=False)
    source_group.add_argument("--input", type=Path, help="Local CycloneDX or normalized JSON input.")
    source_group.add_argument(
        "--fetch-from-checkmarx",
        action="store_true",
        help="Download a CycloneDX JSON SBOM from Checkmarx SCA Export Service.",
    )
    source_group.add_argument(
        "--write-sample",
        type=Path,
        metavar="PATH",
        help="Write a runnable CycloneDX example JSON file and exit.",
    )

    parser.add_argument("--project", default=os.getenv("CX_PROJECT", "agTracker"))
    parser.add_argument("--out", type=Path, default=Path("./cxsca_jira_output"))
    parser.add_argument("--scan-id", help="Checkmarx SCA scan ID; required with --fetch-from-checkmarx.")
    parser.add_argument(
        "--sca-base-url",
        default=os.getenv("CX_SCA_BASE_URL", DEFAULT_SCA_BASE_URL),
        help=f"Checkmarx SCA base URL (default: {DEFAULT_SCA_BASE_URL}).",
    )
    parser.add_argument(
        "--sca-token",
        default=os.getenv("CX_SCA_TOKEN"),
        help="Checkmarx access token. Defaults to CX_SCA_TOKEN.",
    )
    parser.add_argument(
        "--include-none-severity",
        action="store_true",
        help="Include entries whose severity is exactly 'None'. Default: exclude.",
    )
    parser.add_argument(
        "--max-paths-per-component",
        type=int,
        default=25,
        help="Safety limit for paths to one vulnerable transitive component. Default: 25.",
    )

    jira = parser.add_argument_group("Jira publication (off by default)")
    jira.add_argument(
        "--publish-jira",
        action="store_true",
        help="Create or update Jira issues. Without this flag, only preview files are written.",
    )
    jira.add_argument("--jira-url", default=os.getenv("JIRA_BASE_URL"))
    jira.add_argument(
        "--jira-auth",
        choices=("basic", "bearer"),
        default=os.getenv("JIRA_AUTH_MODE", "basic"),
    )
    jira.add_argument("--jira-email", default=os.getenv("JIRA_EMAIL"))
    jira.add_argument("--jira-token", default=os.getenv("JIRA_API_TOKEN") or os.getenv("JIRA_TOKEN"))
    jira.add_argument("--jira-project-key", default=os.getenv("JIRA_PROJECT_KEY"))
    jira.add_argument("--jira-issue-type", default=os.getenv("JIRA_ISSUE_TYPE", "Task"))
    jira.add_argument(
        "--jira-label",
        action="append",
        default=[],
        help="Additional Jira label; may be supplied multiple times.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_arguments()

    if args.write_sample:
        create_sample(args.write_sample)
        print(f"Sample CycloneDX SBOM written to: {args.write_sample}")
        print(
            "Run: "
            f"python3 {Path(__file__).name} --input {args.write_sample} "
            "--project agTracker --out ./demo_output"
        )
        return 0

    if args.fetch_from_checkmarx:
        if not args.scan_id:
            raise ConsolidationError("--scan-id is required with --fetch-from-checkmarx.")
        if not args.sca_token:
            raise ConsolidationError(
                "Checkmarx token is required. Set CX_SCA_TOKEN or pass --sca-token."
            )
        raw_path = args.out / "raw" / "checkmarx_cyclonedx.json"
        print(f"Requesting CycloneDX SBOM for Checkmarx scan {args.scan_id}...")
        client = CheckmarxSCAExportClient(args.sca_base_url, args.sca_token)
        client.download_cyclonedx(args.scan_id, raw_path)
        print(f"Downloaded Checkmarx export: {raw_path}")
        source = load_input(raw_path)
    elif args.input:
        source = load_input(args.input)
    else:
        raise ConsolidationError(
            "Choose one source: --input, --fetch-from-checkmarx, or --write-sample."
        )

    if source.get("bomFormat") == "CycloneDX" or (
        "components" in source and "dependencies" in source and "vulnerabilities" in source
    ):
        rows = parse_cyclonedx(
            source,
            args.project,
            args.include_none_severity,
            args.max_paths_per_component,
        )
    else:
        rows = parse_normalized(source, args.project, args.include_none_severity)

    if not rows:
        raise ConsolidationError(
            "No reportable findings remain after filtering. Check severity values and source data."
        )

    tickets = tickets_from_rows(args.project, rows)
    args.out.mkdir(parents=True, exist_ok=True)
    write_outputs(args.out, tickets)

    print(f"Generated {len(tickets)} Jira-ready ticket preview(s) in: {args.out.resolve()}")
    print(f"Open: {args.out.resolve() / 'consolidated_preview.html'}")

    if args.publish_jira:
        required = {
            "--jira-url": args.jira_url,
            "--jira-token": args.jira_token,
            "--jira-project-key": args.jira_project_key,
        }
        missing = [flag for flag, value in required.items() if not value]
        if args.jira_auth == "basic" and not args.jira_email:
            missing.append("--jira-email")
        if missing:
            raise ConsolidationError(
                "Jira publication requested but required settings are missing: "
                + ", ".join(missing)
            )

        jira = JiraClient(
            base_url=args.jira_url,
            auth_mode=args.jira_auth,
            email=args.jira_email,
            token=args.jira_token,
        )
        for ticket in tickets:
            result = jira.create_or_update(
                ticket=ticket,
                project_key=args.jira_project_key,
                issue_type=args.jira_issue_type,
                additional_labels=args.jira_label,
            )
            print(f"{ticket.primary}: {result}")

    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ConsolidationError, requests.RequestException) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        raise SystemExit(2)
