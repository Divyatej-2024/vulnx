"""Conservative CPE 2.3 matching for user-supplied software inventory entries.

Only explicit NVD vulnerable CPE criteria are considered. This is candidate
matching, not proof that an installed asset is exploitable or affected.
"""
from __future__ import annotations

import re
from typing import Any

_NUMERIC_VERSION = re.compile(r"^\\d+(?:\\.\\d+)*$")


def _parse_cpe(value: str) -> list[str] | None:
    if not isinstance(value, str) or "\\" in value:
        return None
    parts = value.strip().split(":")
    if len(parts) != 13 or parts[0:2] != ["cpe", "2.3"]:
        return None
    if any(not part for part in parts[2:]):
        return None
    return parts


def _numeric_version(value: str) -> tuple[int, ...] | None:
    if not _NUMERIC_VERSION.fullmatch(value):
        return None
    try:
        return tuple(int(part) for part in value.split("."))
    except ValueError:
        return None


def _criteria_matches(asset: list[str], entry: dict[str, Any]) -> bool:
    criteria = _parse_cpe(entry.get("criteria") or entry.get("cpe23Uri") or "")
    if criteria is None or entry.get("vulnerable") is False:
        return False

    # CPE part, vendor and product must match. NVD wildcard criteria are
    # accepted, but logical negation and escaped CPE values are not guessed.
    for index in (2, 3, 4):
        expected = criteria[index].casefold()
        actual = asset[index].casefold()
        if expected not in {"*", "-"} and expected != actual:
            return False

    expected_version = criteria[5]
    actual_version = asset[5]
    start = entry.get("versionStartIncluding") or entry.get("versionStartExcluding")
    end = entry.get("versionEndIncluding") or entry.get("versionEndExcluding")

    if start or end:
        actual = _numeric_version(actual_version)
        if actual is None:
            return False
        if start:
            bound = _numeric_version(start)
            if bound is None:
                return False
            if actual < bound or (actual == bound and entry.get("versionStartExcluding")):
                return False
        if end:
            bound = _numeric_version(end)
            if bound is None:
                return False
            if actual > bound or (actual == bound and entry.get("versionEndExcluding")):
                return False
        return True

    return expected_version in {"*", "-"} or expected_version.casefold() == actual_version.casefold()


def _walk_cpe_matches(value: Any):
    if isinstance(value, dict):
        matches = value.get("cpeMatch")
        if isinstance(matches, list):
            for entry in matches:
                if isinstance(entry, dict):
                    yield entry
        for child in value.values():
            yield from _walk_cpe_matches(child)
    elif isinstance(value, list):
        for child in value:
            yield from _walk_cpe_matches(child)


def matches_asset_cpe(raw_cve: dict[str, Any] | None, asset_cpe23: str) -> bool:
    """Return whether an NVD record contains a conservative candidate CPE match."""
    asset = _parse_cpe(asset_cpe23)
    if asset is None or not isinstance(raw_cve, dict):
        return False

    cve = raw_cve.get("cve") if isinstance(raw_cve.get("cve"), dict) else raw_cve
    configurations = cve.get("configurations", []) if isinstance(cve, dict) else []
    return any(_criteria_matches(asset, entry) for entry in _walk_cpe_matches(configurations))
