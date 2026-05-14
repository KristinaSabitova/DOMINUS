"""Subdomain enumeration phase — passive discovery via crt.sh CT logs."""
from __future__ import annotations

import re
from typing import Any

import httpx

CRT_SH_URL = "https://crt.sh/"
USER_AGENT = "DOMINUS-OSINT/0.1 (+reconnaissance)"
# Valid hostname labels: alphanumerics + hyphens (not at edges), at least one dot.
HOSTNAME_RE = re.compile(r"^[a-z0-9]([a-z0-9\-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9\-]*[a-z0-9])?)+$")


def _fetch_crtsh(target: str, timeout: float = 20.0) -> set[str]:
    params = {"q": f"%.{target}", "output": "json"}
    with httpx.Client(
        timeout=timeout,
        headers={"User-Agent": USER_AGENT},
        follow_redirects=True,
    ) as client:
        resp = client.get(CRT_SH_URL, params=params)
        resp.raise_for_status()
        data = resp.json()

    suffix = f".{target}"
    found: set[str] = set()
    for entry in data:
        for raw in (entry.get("name_value") or "").split("\n"):
            name = raw.strip().lower().lstrip("*.")
            if not name or name == target:
                continue
            if not name.endswith(suffix):
                continue
            if HOSTNAME_RE.match(name):
                found.add(name)
    return found


def run(target: str) -> dict[str, Any]:
    target = target.strip().lower().lstrip(".")

    sources: list[str] = []
    subdomains: set[str] = set()

    try:
        subdomains |= _fetch_crtsh(target)
        sources.append("crt.sh")
    except (httpx.HTTPError, ValueError) as exc:
        sources.append(f"crt.sh (failed: {type(exc).__name__})")

    result = sorted(subdomains)
    return {
        "sources": sources,
        "subdomains": result,
        "count": len(result),
    }
