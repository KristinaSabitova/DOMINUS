"""WHOIS phase — registrar, registrant, creation/expiration dates, name servers."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

import whois

PRIVACY_KEYWORDS = (
    "privacy",
    "redacted",
    "whoisguard",
    "withheld",
    "data protected",
    "domains by proxy",
    "contact privacy",
)


def _normalize_date(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, list):
        value = next((v for v in value if v is not None), None)
    if isinstance(value, datetime):
        if value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)
        return value.isoformat()
    return str(value) if value else None


def _as_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, (list, tuple, set)):
        return [str(v) for v in value if v]
    return [str(value)]


def _days_from_iso(iso: str | None, *, future: bool) -> int | None:
    if not iso:
        return None
    try:
        dt = datetime.fromisoformat(iso)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    delta = (dt - datetime.now(timezone.utc)).days
    return delta if future else -delta


def _detect_privacy(record: Any, registrant: str | None) -> bool:
    haystacks: list[str] = []
    if registrant:
        haystacks.append(str(registrant).lower())
    raw = getattr(record, "text", None)
    if raw:
        haystacks.append(str(raw).lower())
    return any(kw in h for h in haystacks for kw in PRIVACY_KEYWORDS)


def run(target: str) -> dict[str, Any]:
    record = whois.whois(target)

    creation = _normalize_date(getattr(record, "creation_date", None))
    expiration = _normalize_date(getattr(record, "expiration_date", None))
    updated = _normalize_date(getattr(record, "updated_date", None))

    registrant_org = getattr(record, "org", None)
    emails = _as_list(getattr(record, "emails", None))

    return {
        "registrar": getattr(record, "registrar", None),
        "creation_date": creation,
        "expiration_date": expiration,
        "updated_date": updated,
        "domain_age_days": _days_from_iso(creation, future=False),
        "days_until_expiration": _days_from_iso(expiration, future=True),
        "name_servers": sorted({ns.lower() for ns in _as_list(getattr(record, "name_servers", None))}),
        "status": _as_list(getattr(record, "status", None)),
        "emails": emails,
        "registrant_org": registrant_org,
        "country": getattr(record, "country", None),
        "privacy_protected": _detect_privacy(record, registrant_org),
    }
