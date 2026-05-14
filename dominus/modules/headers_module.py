"""HTTP headers phase — inspects security headers, TLS hints, server banners."""
from __future__ import annotations

from typing import Any

import httpx

SECURITY_HEADERS = (
    "strict-transport-security",
    "content-security-policy",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy",
)

USER_AGENT = "DOMINUS-OSINT/0.1 (+reconnaissance)"
SCHEMES = ("https", "http")


def _empty_result(error: str | None = None) -> dict[str, Any]:
    result: dict[str, Any] = {
        "url": None,
        "status": None,
        "scheme": None,
        "server": None,
        "headers": {},
        "security_headers": {h: None for h in SECURITY_HEADERS},
        "missing_security_headers": list(SECURITY_HEADERS),
        "redirect_chain": [],
    }
    if error:
        result["error"] = error
    return result


def run(target: str, timeout: float = 10.0) -> dict[str, Any]:
    base = target.strip().rstrip("/")
    explicit_scheme = base.startswith(("http://", "https://"))
    last_error: str | None = None

    with httpx.Client(
        follow_redirects=True,
        timeout=timeout,
        headers={"User-Agent": USER_AGENT},
    ) as client:
        candidates = [base] if explicit_scheme else [f"{s}://{base}" for s in SCHEMES]
        for url in candidates:
            try:
                resp = client.get(url)
            except httpx.HTTPError as exc:
                last_error = f"{type(exc).__name__}: {exc}"
                continue

            headers = {k.lower(): v for k, v in resp.headers.items()}
            security_headers = {h: headers.get(h) for h in SECURITY_HEADERS}
            missing = [h for h, v in security_headers.items() if not v]

            return {
                "url": str(resp.url),
                "status": resp.status_code,
                "scheme": resp.url.scheme,
                "server": headers.get("server"),
                "headers": headers,
                "security_headers": security_headers,
                "missing_security_headers": missing,
                "redirect_chain": [str(r.url) for r in resp.history],
            }

    return _empty_result(error=last_error or "Unable to reach target on HTTPS or HTTP")
