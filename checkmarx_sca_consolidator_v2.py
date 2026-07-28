#!/usr/bin/env python3
"""
Checkmarx SCA native JSON consolidator v2.

Reads a local Checkmarx SCA JSON/ZIP export and creates Excel/CSV outputs that
map vulnerable transitive packages back to the primary library developers should
upgrade. It does not require a Checkmarx API key and it does not create Jira
issues.
"""

from __future__ import annotations

import argparse
import csv
import io
import json
import math
import os
import re
import sys
import zipfile
from collections import defaultdict
from dataclasses import dataclass
from html import escape
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

SEVERITY_FIELDS = [
    "CriticalVulnerabilityCount",
    "HighVulnerabilityCount",
    "MediumVulnerabilityCount",
    "LowVulnerabilityCount",
]

SKIP_SEVERITIES = {"NONE", "INFO", "INFORMATIONAL"}

ID_KEYS = (
    "CVE",
    "Cve",
    "CveId",
    "CVEId",
    "CveName",
    "cveName",
    "VulnerabilityId",
    "VulnerabilityID",
    "VulnerabilityName",
    "Vulnerability",
    "Id",
    "ID",
    "Name",
)

CVSS_KEYS = (
    "CVSS",
    "Cvss",
    "CvssScore",
    "CVSSScore",
    "cvssScore",
    "Score",
    "RiskScore",
    "riskScore",
)

BUILTIN_GROUP_RULES = [
    {
        "name": "ESLint",
        "framework": "ESLint",
        "patterns": [r"(?:^|[^a-z0-9])eslint(?:$|[^a-z0-9])", r"(?:^|[^a-z0-9])eslint-", r"(?:^|[^a-z0-9])eslint/"],
    },
    {"name": "BIRT", "framework": "BIRT", "patterns": [r"birt"]},
]


def env_int(
    name: str,
    default: int,
    minimum: int | None = None,
    maximum: int | None = None,
    overrides: dict[str, Any] | None = None,
) -> int:
    """Read an integer setting, naming the offending variable when it is malformed.

    Shared by the CLI and the web app so a given variable behaves identically in
    both. A missing or blank value falls back to ``default``; anything else must
    parse as an integer inside the optional inclusive range.
    """
    raw = (overrides or {}).get(name, os.environ.get(name))
    if raw is None or (isinstance(raw, str) and not raw.strip()):
        return default
    try:
        value = int(raw)
    except (TypeError, ValueError) as exc:
        raise RuntimeError(f"{name} must be an integer (got {raw!r}).") from exc
    if (minimum is not None and value < minimum) or (maximum is not None and value > maximum):
        raise RuntimeError(f"{name} must be between {minimum} and {maximum}.")
    return value


DEFAULT_MAX_REPORT_BYTES = env_int("MAX_REPORT_BYTES", 100 * 1024 * 1024)
DEFAULT_MAX_JSON_DEPTH = env_int("MAX_JSON_DEPTH", 64)
# Counts every JSON value, scalars included. It previously counted only
# containers, so a list of a million numbers passed a limit of two. The default
# is correspondingly higher than the old container-only figure.
DEFAULT_MAX_JSON_NODES = env_int("MAX_JSON_NODES", 2_000_000)
DEFAULT_MAX_PACKAGES = env_int("MAX_REPORT_PACKAGES", 100_000)
DEFAULT_MAX_ROWS = env_int("MAX_REPORT_ROWS", 50_000)
DEFAULT_MAX_ZIP_MEMBERS = env_int("MAX_ZIP_MEMBERS", 10_000)
# Bounds generated content while rows are built, before any format is
# serialized. Row count alone does not bound output: a report with wide cells
# amplifies a few kilobytes of input into megabytes of CSV. The default sits
# well above a full MAX_REPORT_ROWS report of ordinary width (measured at
# roughly 350 characters per row, so ~18M for 50,000 rows) so that the two
# limits do not contradict each other; its job is to bound the pathological
# case, not to be tight.
DEFAULT_MAX_CONTENT_CHARS = env_int("MAX_REPORT_CONTENT_CHARS", 64_000_000)
# Leading whitespace is stripped before the prefix test, so only the characters
# a spreadsheet treats as the start of a formula belong here. The full-width
# variants are included because Excel normalizes them.
FORMULA_PREFIXES = frozenset("=+-@＝＋－＠")

OUTPUT_COLUMNS = [
    "Project", "Library Group", "Framework", "Primary Library", "Primary Current Version",
    "Primary Latest Version", "Primary Is Latest?", "Vulnerable Library", "Vulnerable Current Version",
    "Vulnerable Latest Version", "Vulnerable Is Latest?", "Dependency Type", "Package Path",
    "Location / File Path", "Vulnerability / CVSS Score", "Mapping Source", "Group Reason",
    "Critical Count", "High Count", "Medium Count", "Low Count",
]

SUMMARY_COLUMNS = ["Library Group", "Framework", "Primary Versions", "Vulnerable Library Count", "Location Count", "Rows"]

# Shared by the CLI and the web exports so both produce identically named files.
EXPORT_BASENAME = "sca_stitcher_consolidated"


class ReportError(ValueError):
    """Raised when a report cannot be read or exceeds a configured safety limit.

    Deriving from ValueError keeps this catchable by ordinary ``except Exception``
    handlers; long-running callers such as the web app must never see SystemExit
    for what is really input validation.
    """


@dataclass
class PackageRef:
    package_id: str
    name: str
    version: str

    @classmethod
    def from_obj(cls, obj: Dict[str, Any]) -> "PackageRef":
        return cls(
            package_id=str(obj.get("Id") or obj.get("id") or "").strip(),
            name=str(obj.get("Name") or obj.get("name") or "").strip(),
            version=str(obj.get("Version") or obj.get("version") or "").strip(),
        )

    @property
    def display(self) -> str:
        if self.name and self.version:
            return f"{self.name} @ {self.version}"
        return self.name or self.package_id or "Unknown package"


def spreadsheet_safe(value: Any) -> str:
    """Return a string that spreadsheet programs will not evaluate as a formula."""
    rendered = "" if value is None else str(value)
    candidate = rendered.lstrip(" \t\r\n")
    if candidate and candidate[0] in FORMULA_PREFIXES:
        return "'" + rendered
    return rendered


def validate_json_structure(
    value: Any,
    max_depth: int = DEFAULT_MAX_JSON_DEPTH,
    max_nodes: int = DEFAULT_MAX_JSON_NODES,
) -> Dict[str, Any]:
    if not isinstance(value, dict):
        raise ReportError("Report root must be a JSON object.")
    nodes = 0
    stack: list[tuple[Any, int]] = [(value, 0)]
    while stack:
        current, depth = stack.pop()
        nodes += 1
        if nodes > max_nodes:
            raise ReportError(f"Report exceeds the structural limit of {max_nodes} JSON nodes.")
        if depth > max_depth:
            raise ReportError(f"Report exceeds the maximum nesting depth of {max_depth}.")
        if isinstance(current, dict):
            children: Iterable[Any] = current.values()
        elif isinstance(current, list):
            children = current
        else:
            continue
        # Scalars are counted but never pushed: they contribute to the budget
        # without letting a wide array grow the traversal stack. The check has
        # to happen here, not only when popping, or a trailing run of scalars
        # empties the stack and exits the loop unchecked.
        for item in children:
            if isinstance(item, (dict, list)):
                stack.append((item, depth + 1))
            else:
                nodes += 1
        if nodes > max_nodes:
            raise ReportError(f"Report exceeds the structural limit of {max_nodes} JSON nodes.")
    return value


def reject_json_constant(name: str) -> Any:
    """Refuse Infinity/-Infinity/NaN, which int() cannot convert."""
    raise ReportError(f"Report contains the unsupported JSON constant {name}.")


def decode_report(
    raw: bytes,
    max_depth: int = DEFAULT_MAX_JSON_DEPTH,
    max_nodes: int = DEFAULT_MAX_JSON_NODES,
) -> Dict[str, Any]:
    try:
        parsed = json.loads(raw.decode("utf-8-sig"), parse_constant=reject_json_constant)
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
        raise ReportError("Report is not valid UTF-8 JSON within the supported nesting limit.") from exc
    return validate_json_structure(parsed, max_depth=max_depth, max_nodes=max_nodes)


def load_report(
    path: Path,
    max_json_bytes: int | None = DEFAULT_MAX_REPORT_BYTES,
    max_depth: int = DEFAULT_MAX_JSON_DEPTH,
    max_nodes: int = DEFAULT_MAX_JSON_NODES,
    max_zip_members: int = DEFAULT_MAX_ZIP_MEMBERS,
) -> Dict[str, Any]:
    if not path.exists():
        raise ReportError(f"Input file not found: {path}")

    if path.suffix.lower() == ".zip":
        try:
            archive = zipfile.ZipFile(path)
        except zipfile.BadZipFile as exc:
            raise ReportError("Upload is not a readable ZIP archive.") from exc
        with archive as zf:
            members = zf.infolist()
            # A small archive can declare a very large number of members, so cap
            # the count before doing any per-member work.
            if len(members) > max_zip_members:
                raise ReportError(
                    f"ZIP contains more than the allowed {max_zip_members} members."
                )
            # A single linear pass, rather than sorting every member name.
            preferred_info = min(
                (info for info in members if info.filename.lower().endswith(".json")),
                key=lambda info: ("sca" not in info.filename.lower(), len(info.filename), info.filename),
                default=None,
            )
            if preferred_info is None:
                raise ReportError("ZIP does not contain a JSON report.")
            preferred = preferred_info.filename
            info = preferred_info
            if max_json_bytes is not None and info.file_size > max_json_bytes:
                raise ReportError(
                    f"JSON report inside ZIP is too large ({info.file_size} bytes; limit {max_json_bytes} bytes)."
                )
            with zf.open(preferred) as fh:
                raw = fh.read(-1 if max_json_bytes is None else max_json_bytes + 1)
                if max_json_bytes is not None and len(raw) > max_json_bytes:
                    raise ReportError(f"JSON report inside ZIP exceeds the {max_json_bytes}-byte limit.")
                return decode_report(raw, max_depth=max_depth, max_nodes=max_nodes)

    if max_json_bytes is not None and path.stat().st_size > max_json_bytes:
        raise ReportError(f"JSON report is too large ({path.stat().st_size} bytes; limit {max_json_bytes} bytes).")
    with path.open("rb") as fh:
        raw = fh.read(-1 if max_json_bytes is None else max_json_bytes + 1)
    if max_json_bytes is not None and len(raw) > max_json_bytes:
        raise ReportError(f"JSON report exceeds the {max_json_bytes}-byte limit.")
    return decode_report(raw, max_depth=max_depth, max_nodes=max_nodes)


def as_list(value: Any) -> List[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def text_or_blank(value: Any) -> str:
    if value is None:
        return ""
    return str(value).strip()


def as_int(value: Any) -> int:
    try:
        number = float(value or 0)
    except (TypeError, ValueError):
        return 0
    # A literal such as 1e400 parses as a float infinity without going through
    # parse_constant, and int() raises OverflowError on it.
    if not math.isfinite(number):
        return 0
    try:
        return int(number)
    except (TypeError, ValueError, OverflowError):
        return 0


def name_version_key(name: str, version: str) -> str:
    return f"{name.strip().lower()}@{version.strip().lower()}"


def vuln_count(pkg: Dict[str, Any]) -> int:
    explicit = pkg.get("VulnerabilityCount")
    if explicit not in (None, ""):
        return as_int(explicit)
    return sum(as_int(pkg.get(k)) for k in SEVERITY_FIELDS)


def is_reportable(pkg: Dict[str, Any], detailed: Sequence[Tuple[str, str]]) -> bool:
    """Decide whether a package produces rows.

    ``detailed`` is the already-extracted vulnerability list. It is passed in
    rather than recomputed because walking the package graph is the single most
    expensive operation in report generation.
    """
    severity = text_or_blank(pkg.get("Severity")).upper()
    if severity in SKIP_SEVERITIES:
        return False
    return vuln_count(pkg) > 0 or bool(detailed)


def is_direct(pkg: Dict[str, Any]) -> bool:
    if bool(pkg.get("IsDirectDependency")):
        return True
    return text_or_blank(pkg.get("DependencyType")).lower() == "direct"


def latest_version(pkg: Dict[str, Any]) -> str:
    for key in (
        "NewestVersion",
        "LatestVersion",
        "LatestVersionWithoutVulnerabilities",
        "LatestRecommendedMoreSecureVersion",
        "NextVersionWithoutVulnerabilities",
        "NextRecommendedMoreSecureVersion",
    ):
        value = text_or_blank(pkg.get(key))
        if value:
            return value
    return ""


def normalize_version(v: str) -> str:
    return re.sub(r"[^a-z0-9.\-+_]", "", v.lower())


def is_latest(current: str, latest: str) -> str:
    if not current or not latest:
        return "Unknown"
    return "Yes" if normalize_version(current) == normalize_version(latest) else "No"


def compile_rules(config_path: Optional[Path]) -> List[Dict[str, Any]]:
    rules: List[Dict[str, Any]] = []
    if config_path and config_path.exists():
        with config_path.open("r", encoding="utf-8") as fh:
            data = json.load(fh)
        rules.extend(data.get("groups", []))
    rules.extend(BUILTIN_GROUP_RULES)
    return rules


def apply_group_rules(primary: PackageRef, locations: Sequence[str], rules: Sequence[Dict[str, Any]]) -> Tuple[str, str, str]:
    haystack = " ".join([primary.name, primary.package_id, primary.version, *locations]).lower()
    for rule in rules:
        for pat in rule.get("patterns", []):
            if re.search(pat, haystack, re.I):
                return rule.get("name") or primary.name or "Unknown", rule.get("framework") or "", "custom/built-in rule"
    return primary.name or primary.package_id or "Unknown", "", "primary package name"


def normalize_package_paths(raw: Any) -> List[List[PackageRef]]:
    """Return dependency paths as list of chains.

    Checkmarx exports may encode PackagePaths as:
    - []
    - [{node}, {node}] meaning one chain
    - [[{node}, {node}], [{node}, {node}]] meaning multiple chains
    """
    items = as_list(raw)
    if not items:
        return []
    if all(isinstance(x, dict) for x in items):
        return [[PackageRef.from_obj(x) for x in items]]
    chains: List[List[PackageRef]] = []
    for chain in items:
        if isinstance(chain, list):
            refs = [PackageRef.from_obj(x) for x in chain if isinstance(x, dict)]
            if refs:
                chains.append(refs)
        elif isinstance(chain, dict):
            chains.append([PackageRef.from_obj(chain)])
    return chains


def normalize_location(location: str) -> str:
    return location.replace("\\", "/").strip().strip("/")


def location_ancestors(location: str) -> List[str]:
    """Return a location and each of its ancestor directories, nearest first."""
    normalized = normalize_location(location)
    if not normalized:
        return []
    parts = normalized.split("/")
    return ["/".join(parts[:index]) for index in range(len(parts), 0, -1)]


def location_scopes(location: str) -> List[str]:
    """Return the directory scopes a direct package at ``location`` governs.

    A manifest governs the directory that contains it, so
    ``services/api/pom.xml`` scopes both itself and ``services/api``. A location
    that is already a directory scopes only itself.

    This deliberately stops there. Indexing every ancestor let a shared
    repository root such as ``services`` capture unrelated siblings, so a
    transitive package under ``services/worker`` resolved to whichever direct
    package under ``services`` happened to be indexed first.
    """
    normalized = normalize_location(location)
    if not normalized:
        return []
    scopes = [normalized]
    head, _, tail = normalized.rpartition("/")
    if head and "." in tail:
        scopes.append(head)
    return scopes


def build_indexes(packages: Sequence[Dict[str, Any]]) -> Dict[str, Any]:
    by_id: Dict[str, Dict[str, Any]] = {}
    by_name_version: Dict[str, Dict[str, Any]] = {}
    by_name: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    direct_packages: List[Dict[str, Any]] = []
    # Maps each scope a direct package governs to every direct package claiming
    # it. The value is a list, not a single package: when several direct
    # packages share a scope the mapping is genuinely ambiguous and must not be
    # resolved by insertion order.
    by_direct_location: Dict[str, List[Dict[str, Any]]] = defaultdict(list)

    for pkg in packages:
        ref = PackageRef.from_obj(pkg)
        if ref.package_id:
            by_id[ref.package_id.lower()] = pkg
        if ref.name and ref.version:
            by_name_version[name_version_key(ref.name, ref.version)] = pkg
        if ref.name:
            by_name[ref.name.lower()].append(pkg)
        if is_direct(pkg):
            direct_packages.append(pkg)
            for raw_location in as_list(pkg.get("Locations")):
                for key in location_scopes(text_or_blank(raw_location)):
                    by_direct_location[key].append(pkg)

    return {
        "by_id": by_id,
        "by_name_version": by_name_version,
        "by_name": by_name,
        "direct_packages": direct_packages,
        "by_direct_location": by_direct_location,
    }


def find_pkg_for_ref(ref: PackageRef, indexes: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    if ref.package_id and ref.package_id.lower() in indexes["by_id"]:
        return indexes["by_id"][ref.package_id.lower()]
    if ref.name and ref.version:
        hit = indexes["by_name_version"].get(name_version_key(ref.name, ref.version))
        if hit:
            return hit
    if ref.name:
        hits = indexes["by_name"].get(ref.name.lower(), [])
        if len(hits) == 1:
            return hits[0]
    return None


def infer_primary(pkg: Dict[str, Any], chain: List[PackageRef], indexes: Dict[str, Any]) -> Tuple[PackageRef, str, bool]:
    self_ref = PackageRef.from_obj(pkg)
    if is_direct(pkg):
        return self_ref, "package is direct", False

    for node in chain:
        mapped = find_pkg_for_ref(node, indexes)
        if mapped is not None and is_direct(mapped):
            return PackageRef.from_obj(mapped), "matched direct package in PackagePaths", False

    if chain:
        first = chain[0]
        mapped = find_pkg_for_ref(first, indexes)
        if mapped is not None:
            return PackageRef.from_obj(mapped), "first PackagePaths node resolved", not is_direct(mapped)
        return first, "first PackagePaths node inferred", True

    ambiguous = False
    for raw_location in as_list(pkg.get("Locations")):
        for key in location_ancestors(text_or_blank(raw_location)):
            candidates = indexes["by_direct_location"].get(key)
            if not candidates:
                continue
            unique = {id(candidate): candidate for candidate in candidates}
            if len(unique) == 1:
                mapped = next(iter(unique.values()))
                return PackageRef.from_obj(mapped), "location scope matched direct package", False
            # Several direct packages govern this scope, so which one pulls the
            # transitive package in is unknown. Naming the first would tell a
            # developer to upgrade the wrong library; reporting it as unmapped
            # is the honest answer. Broader ancestors can only be more
            # ambiguous, so stop here.
            ambiguous = True
            break

    if ambiguous:
        return PackageRef("", "Unmapped Primary Library", ""), "ambiguous location scope", True
    return PackageRef("", "Unmapped Primary Library", ""), "unmapped", True


def looks_like_vuln_id(value: str) -> bool:
    value = value.strip()
    return bool(re.search(r"\b(CVE-\d{4}-\d+|CXA?[A-Za-z0-9:_\-]+|GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4})\b", value, re.I))


def recursive_dicts(
    obj: Any,
    max_depth: int = DEFAULT_MAX_JSON_DEPTH,
    max_nodes: int = DEFAULT_MAX_JSON_NODES,
) -> Iterable[Dict[str, Any]]:
    nodes = 0
    stack: list[tuple[Any, int]] = [(obj, 0)]
    while stack:
        current, depth = stack.pop()
        nodes += 1
        if nodes > max_nodes:
            raise ReportError(f"Object exceeds the structural limit of {max_nodes} nodes.")
        if depth > max_depth:
            raise ReportError(f"Object exceeds the maximum nesting depth of {max_depth}.")
        if isinstance(current, dict):
            yield current
            children: Iterable[Any] = current.values()
        elif isinstance(current, list):
            children = current
        else:
            continue
        for item in children:
            if isinstance(item, (dict, list)):
                stack.append((item, depth + 1))
            else:
                nodes += 1
        if nodes > max_nodes:
            raise ReportError(f"Object exceeds the structural limit of {max_nodes} nodes.")


def extract_vulns(
    pkg: Dict[str, Any],
    max_depth: int = DEFAULT_MAX_JSON_DEPTH,
    max_nodes: int = DEFAULT_MAX_JSON_NODES,
) -> List[Tuple[str, str]]:
    vulns: List[Tuple[str, str]] = []
    seen = set()
    for d in recursive_dicts(pkg, max_depth=max_depth, max_nodes=max_nodes):
        vuln_id = ""
        for key in ID_KEYS:
            value = text_or_blank(d.get(key))
            if value and looks_like_vuln_id(value):
                vuln_id = value
                break
        if not vuln_id:
            continue
        cvss = ""
        for key in CVSS_KEYS:
            value = text_or_blank(d.get(key))
            if value and re.search(r"\d", value):
                cvss = value
                break
        item = (vuln_id, cvss)
        if item not in seen:
            seen.add(item)
            vulns.append(item)
    return vulns


def vuln_cell(pkg: Dict[str, Any], detailed: Sequence[Tuple[str, str]]) -> str:
    if detailed:
        return "\n".join(f"{vid} | CVSS {score}" if score else vid for vid, score in detailed)
    counts = {k.replace("VulnerabilityCount", ""): as_int(pkg.get(k)) for k in SEVERITY_FIELDS if as_int(pkg.get(k))}
    if counts:
        return "Vulnerability details not itemized in source; counts: " + ", ".join(f"{k}={v}" for k, v in counts.items())
    return "Vulnerability details not itemized in source"


def make_rows(
    report: Dict[str, Any],
    rules: Sequence[Dict[str, Any]],
    max_packages: int = DEFAULT_MAX_PACKAGES,
    max_rows: int = DEFAULT_MAX_ROWS,
    max_depth: int = DEFAULT_MAX_JSON_DEPTH,
    max_nodes: int = DEFAULT_MAX_JSON_NODES,
    max_content_chars: int = DEFAULT_MAX_CONTENT_CHARS,
) -> Tuple[List[Dict[str, str]], List[Dict[str, str]], Dict[str, Any]]:
    packages = report.get("Packages") or []
    if not isinstance(packages, list):
        raise ReportError("Report does not contain a Packages[] array.")
    if len(packages) > max_packages:
        raise ReportError(f"Report contains more than the allowed {max_packages} packages.")
    # Validated up front so a malformed entry is reported as invalid input with
    # its position, rather than surfacing as an AttributeError from deep inside
    # PackageRef.from_obj() and being logged as an internal fault.
    for index, pkg in enumerate(packages):
        if not isinstance(pkg, dict):
            raise ReportError(f"Packages[{index}] must be a JSON object.")

    raw_summary = report.get("RiskReportSummary")
    if raw_summary is None:
        summary: Dict[str, Any] = {}
    elif isinstance(raw_summary, dict):
        summary = raw_summary
    else:
        # Checked against the raw value rather than after `or {}`, so a falsy
        # non-object such as [] is rejected instead of silently treated as absent.
        raise ReportError("RiskReportSummary must be a JSON object.")
    project = text_or_blank(summary.get("ProjectName")) or text_or_blank(report.get("ProjectName")) or "Unknown Project"
    indexes = build_indexes(packages)

    rows: List[Dict[str, str]] = []
    unmapped: List[Dict[str, str]] = []
    content_chars = 0
    diagnostics = {
        "project": project,
        "packages_total": len(packages),
        "direct_packages": len(indexes["direct_packages"]),
        "reportable_packages": 0,
        "rows_generated": 0,
        "unmapped_rows": 0,
        "packages_using_count_fallback": 0,
        "detailed_vulnerabilities_found": 0,
    }

    for pkg in packages:
        # The single traversal of this package's object graph. is_reportable()
        # and vuln_cell() both need it, and it previously ran two or three times
        # per package, which dominated report generation on large uploads.
        detailed = extract_vulns(pkg, max_depth=max_depth, max_nodes=max_nodes)
        if not is_reportable(pkg, detailed):
            continue
        diagnostics["reportable_packages"] += 1
        if detailed:
            diagnostics["detailed_vulnerabilities_found"] += len(detailed)
        else:
            diagnostics["packages_using_count_fallback"] += 1

        chains = normalize_package_paths(pkg.get("PackagePaths"))
        if not chains:
            chains = [[]]
        locations = [text_or_blank(x) for x in as_list(pkg.get("Locations"))] or [""]
        vuln_ref = PackageRef.from_obj(pkg)

        # These are constant for the package, so resolve them once rather than
        # once per generated row.
        vuln_display = vuln_cell(pkg, detailed)
        pkg_latest = latest_version(pkg)
        pkg_is_latest = is_latest(vuln_ref.version, pkg_latest)
        dependency_type = text_or_blank(pkg.get("DependencyType")) or (
            "Direct" if is_direct(pkg) else "Transitive"
        )
        severity_counts = {
            "Critical Count": str(as_int(pkg.get("CriticalVulnerabilityCount"))),
            "High Count": str(as_int(pkg.get("HighVulnerabilityCount"))),
            "Medium Count": str(as_int(pkg.get("MediumVulnerabilityCount"))),
            "Low Count": str(as_int(pkg.get("LowVulnerabilityCount"))),
        }

        for chain in chains:
            primary, mapping_source, is_unmapped = infer_primary(pkg, chain, indexes)
            primary_pkg = find_pkg_for_ref(primary, indexes) or {}
            primary_latest = latest_version(primary_pkg)
            group, framework, group_reason = apply_group_rules(primary, locations, rules)
            path_display = " > ".join(x.display for x in chain) if chain else primary.display

            for location in locations:
                if len(rows) >= max_rows:
                    raise ReportError(f"Consolidated report exceeds the {max_rows}-row limit.")
                row = {
                    "Project": project,
                    "Library Group": group,
                    "Framework": framework,
                    "Primary Library": primary.display,
                    "Primary Current Version": primary.version,
                    "Primary Latest Version": primary_latest,
                    "Primary Is Latest?": is_latest(primary.version, primary_latest),
                    "Vulnerable Library": vuln_ref.display,
                    "Vulnerable Current Version": vuln_ref.version,
                    "Vulnerable Latest Version": pkg_latest,
                    "Vulnerable Is Latest?": pkg_is_latest,
                    "Dependency Type": dependency_type,
                    "Package Path": path_display,
                    "Location / File Path": location,
                    "Vulnerability / CVSS Score": vuln_display,
                    "Mapping Source": mapping_source,
                    "Group Reason": group_reason,
                    **severity_counts,
                }
                # Enforced as the row is built, so a report that amplifies a few
                # kilobytes of input into megabytes of cells is stopped here
                # rather than after every export format has been materialized.
                content_chars += sum(len(value) for value in row.values())
                if content_chars > max_content_chars:
                    raise ReportError(
                        f"Consolidated report exceeds the {max_content_chars}-character content budget."
                    )
                rows.append(row)
                if is_unmapped or primary.name == "Unmapped Primary Library":
                    # A copy, so later edits to one view never mutate the other.
                    unmapped.append(dict(row))

    diagnostics["rows_generated"] = len(rows)
    diagnostics["unmapped_rows"] = len(unmapped)
    return rows, unmapped, diagnostics


def write_csv(path: Path, rows: Sequence[Dict[str, str]], fieldnames: Sequence[str]) -> None:
    with path.open("w", newline="", encoding="utf-8-sig") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            writer.writerow({key: spreadsheet_safe(value) for key, value in row.items()})


def make_summary(rows: Sequence[Dict[str, str]]) -> List[Dict[str, str]]:
    grouped: Dict[str, Dict[str, Any]] = {}
    for row in rows:
        key = row["Library Group"]
        g = grouped.setdefault(
            key,
            {
                "Library Group": key,
                "Framework": row.get("Framework", ""),
                "Primary Versions": set(),
                "Vulnerable Libraries": set(),
                "Locations": set(),
                "Rows": 0,
            },
        )
        g["Primary Versions"].add(row.get("Primary Current Version", ""))
        g["Vulnerable Libraries"].add(row.get("Vulnerable Library", ""))
        if row.get("Location / File Path"):
            g["Locations"].add(row.get("Location / File Path"))
        g["Rows"] += 1

    out = []
    for g in sorted(grouped.values(), key=lambda x: x["Library Group"].lower()):
        out.append(
            {
                "Library Group": g["Library Group"],
                "Framework": g["Framework"],
                "Primary Versions": ", ".join(sorted(v for v in g["Primary Versions"] if v)),
                "Vulnerable Library Count": str(len(g["Vulnerable Libraries"])),
                "Location Count": str(len(g["Locations"])),
                "Rows": str(g["Rows"]),
            }
        )
    return out


def build_html_report(rows: Sequence[Dict[str, str]]) -> str:
    by_group: Dict[str, List[Dict[str, str]]] = defaultdict(list)
    for row in rows:
        by_group[row["Library Group"]].append(row)
    parts = [
        "<html><head><meta charset='utf-8'><title>Checkmarx SCA Consolidated</title>",
        "<style>body{font-family:Segoe UI,Arial,sans-serif;margin:24px}table{border-collapse:collapse;width:100%;margin-bottom:28px}th{background:#174a7c;color:white}td,th{border:1px solid #ccc;padding:6px;vertical-align:top;font-size:13px}pre{white-space:pre-wrap;margin:0}</style></head><body>",
        "<h1>Checkmarx SCA Consolidated Output</h1>",
    ]
    for group, items in sorted(by_group.items()):
        parts.append(f"<h2>{escape(group)}</h2><table><tr><th>Primary Library</th><th>Transitive Library / Package Path</th><th>Location / File Path</th><th>Vulnerability / CVSS Score</th><th>Latest?</th></tr>")
        for r in items:
            latest = f"Primary: {escape(r['Primary Is Latest?'])}<br>Vulnerable: {escape(r['Vulnerable Is Latest?'])}"
            parts.append(
                "<tr>"
                + f"<td>{escape(r['Primary Library'])}</td>"
                + f"<td><pre>{escape(r['Package Path'])}</pre></td>"
                + f"<td>{escape(r['Location / File Path'])}</td>"
                + f"<td><pre>{escape(r['Vulnerability / CVSS Score'])}</pre></td>"
                + f"<td>{latest}</td>"
                + "</tr>"
            )
        parts.append("</table>")
    parts.append("</body></html>")
    return "\n".join(parts)


def write_html(path: Path, rows: Sequence[Dict[str, str]]) -> None:
    path.write_text(build_html_report(rows), encoding="utf-8")


def write_xlsx_workbook(workbook: Any, sheets: Dict[str, Tuple[List[Dict[str, str]], List[str]]]) -> None:
    header_fmt = workbook.add_format({"bold": True, "bg_color": "#006BD5", "font_color": "white", "border": 1})
    cell_fmt = workbook.add_format({"text_wrap": True, "valign": "top", "border": 1})

    for sheet_name, (rows, columns) in sheets.items():
        ws = workbook.add_worksheet(sheet_name[:31])
        for col, name in enumerate(columns):
            ws.write(0, col, name, header_fmt)
            ws.set_column(col, col, min(max(len(name) + 2, 14), 60))
        for r_idx, row in enumerate(rows, start=1):
            for c_idx, name in enumerate(columns):
                ws.write_string(r_idx, c_idx, spreadsheet_safe(row.get(name, "")), cell_fmt)
        ws.freeze_panes(1, 0)
        ws.autofilter(0, 0, max(len(rows), 1), max(len(columns) - 1, 0))


def build_xlsx_bytes(sheets: Dict[str, Tuple[List[Dict[str, str]], List[str]]]) -> bytes | None:
    """Render the workbook in memory, or None when XlsxWriter is not installed."""
    try:
        import xlsxwriter  # type: ignore
    except ImportError:
        return None

    output = io.BytesIO()
    workbook = xlsxwriter.Workbook(output, {"in_memory": True})
    write_xlsx_workbook(workbook, sheets)
    workbook.close()
    return output.getvalue()


def write_xlsx(path: Path, sheets: Dict[str, Tuple[List[Dict[str, str]], List[str]]]) -> bool:
    payload = build_xlsx_bytes(sheets)
    if payload is None:
        return False
    path.write_bytes(payload)
    return True


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Consolidate native Checkmarx SCA JSON into Excel/CSV output")
    parser.add_argument("--input", required=True, help="Path to SCA_ScanReport.json or ZIP containing it")
    parser.add_argument("--out", required=True, help="Output directory")
    parser.add_argument("--group-config", help="Optional JSON config for extra grouping rules")
    args = parser.parse_args(argv)

    input_path = Path(args.input)
    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)
    rules = compile_rules(Path(args.group_config) if args.group_config else None)

    try:
        report = load_report(input_path)
        rows, unmapped, diagnostics = make_rows(report, rules)
    except ReportError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    if not rows:
        print("ERROR: No reportable findings remain after filtering. Check severity values and source data.", file=sys.stderr)
        (out_dir / "schema_diagnostics.json").write_text(json.dumps(diagnostics, indent=2), encoding="utf-8")
        return 2

    summary = make_summary(rows)

    write_csv(out_dir / f"{EXPORT_BASENAME}.csv", rows, OUTPUT_COLUMNS)
    write_csv(out_dir / "library_group_summary.csv", summary, SUMMARY_COLUMNS)
    write_csv(out_dir / "unmapped_libraries.csv", unmapped, OUTPUT_COLUMNS)
    write_html(out_dir / "consolidated_preview.html", rows)
    (out_dir / "schema_diagnostics.json").write_text(json.dumps(diagnostics, indent=2), encoding="utf-8")

    xlsx_written = write_xlsx(
        out_dir / f"{EXPORT_BASENAME}.xlsx",
        {
            "Consolidated": (rows, OUTPUT_COLUMNS),
            "Summary": (summary, SUMMARY_COLUMNS),
            "Unmapped": (unmapped, OUTPUT_COLUMNS),
            "Diagnostics": ([{k: str(v) for k, v in diagnostics.items()}], list(diagnostics.keys())),
        },
    )

    print(f"OK: generated {len(rows)} rows in {out_dir}")
    if xlsx_written:
        print(f"Excel: {EXPORT_BASENAME}.xlsx")
    else:
        print("Excel skipped: install with 'python -m pip install XlsxWriter'")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
