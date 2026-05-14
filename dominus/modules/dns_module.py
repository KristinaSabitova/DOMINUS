"""DNS phase — A/AAAA/MX/NS/TXT/CNAME records and SPF/DMARC/DKIM posture."""
from __future__ import annotations

from typing import Any

import dns.exception
import dns.resolver

RECORD_TYPES = ("A", "AAAA", "MX", "NS", "TXT", "CNAME")
DKIM_SELECTORS = ("default", "google", "selector1", "selector2", "k1", "mail", "dkim", "s1", "s2")
SPF_POLICY_SUFFIX = {
    "-all": "strict",
    "~all": "soft",
    "?all": "neutral",
    "+all": "permissive",
}


def _resolver() -> dns.resolver.Resolver:
    r = dns.resolver.Resolver()
    r.lifetime = 5.0
    r.timeout = 3.0
    return r


def _query(resolver: dns.resolver.Resolver, name: str, rtype: str) -> list[str]:
    try:
        answers = resolver.resolve(name, rtype)
    except (
        dns.resolver.NoAnswer,
        dns.resolver.NXDOMAIN,
        dns.resolver.NoNameservers,
        dns.exception.Timeout,
    ):
        return []

    results: list[str] = []
    for rdata in answers:
        if rtype == "MX":
            results.append(f"{rdata.preference} {rdata.exchange.to_text()}")
        elif rtype == "TXT":
            txt = b"".join(rdata.strings).decode("utf-8", errors="replace")
            results.append(txt)
        else:
            results.append(rdata.to_text())
    return results


def _parse_spf(txt_records: list[str]) -> dict[str, Any] | None:
    for rec in txt_records:
        if rec.lower().startswith("v=spf1"):
            policy = "unknown"
            for suffix, label in SPF_POLICY_SUFFIX.items():
                if rec.endswith(suffix):
                    policy = label
                    break
            return {"record": rec, "policy": policy}
    return None


def _parse_dmarc(resolver: dns.resolver.Resolver, target: str) -> dict[str, Any] | None:
    for rec in _query(resolver, f"_dmarc.{target}", "TXT"):
        if not rec.lower().startswith("v=dmarc1"):
            continue
        tags = {}
        for part in rec.split(";"):
            if "=" in part:
                k, v = part.split("=", 1)
                tags[k.strip().lower()] = v.strip()
        return {
            "record": rec,
            "policy": tags.get("p", "").lower() or None,
            "subdomain_policy": tags.get("sp", "").lower() or None,
            "rua": tags.get("rua"),
            "pct": tags.get("pct"),
        }
    return None


def _check_dkim(resolver: dns.resolver.Resolver, target: str) -> list[str]:
    found: list[str] = []
    for sel in DKIM_SELECTORS:
        if _query(resolver, f"{sel}._domainkey.{target}", "TXT"):
            found.append(sel)
    return found


def run(target: str) -> dict[str, Any]:
    resolver = _resolver()

    records: dict[str, list[str]] = {}
    for rtype in RECORD_TYPES:
        records[rtype.lower()] = _query(resolver, target, rtype)

    spf = _parse_spf(records["txt"])
    dmarc = _parse_dmarc(resolver, target)
    dkim_selectors = _check_dkim(resolver, target)

    return {
        **records,
        "spf": spf,
        "dmarc": dmarc,
        "dkim_selectors": dkim_selectors,
        "has_spf": spf is not None,
        "has_dmarc": dmarc is not None,
        "has_dkim": bool(dkim_selectors),
    }
