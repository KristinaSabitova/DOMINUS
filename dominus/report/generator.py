"""Standalone HTML report generator — renders a single self-contained file."""
from __future__ import annotations

import json
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from math import pi
from pathlib import Path
from typing import Any, Callable

from jinja2 import Environment, FileSystemLoader, select_autoescape

TEMPLATE_DIR = Path(__file__).parent / "templates"

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "unknown": 5}

PHASE_ICONS = {
    "whois": "⌬",
    "dns": "⌘",
    "subdomains": "❖",
    "ports": "⊞",
    "headers": "⌗",
}

PHASE_DESCRIPTIONS = {
    "whois": "Registrar, ownership and lifecycle metadata",
    "dns": "Resolution records and email authentication posture",
    "subdomains": "Passive subdomain enumeration via Certificate Transparency",
    "ports": "Open TCP services and version fingerprints",
    "headers": "HTTP response headers and security configuration",
}


def _subdomain_severity(match: re.Match[str]) -> str:
    count = int(match.group(1))
    if count > 100:
        return "critical"
    if count > 50:
        return "high"
    if count > 20:
        return "medium"
    return "low"


def _expiration_severity(match: re.Match[str]) -> str:
    return "critical" if int(match.group(1)) < 7 else "high"


def _port_severity(match: re.Match[str]) -> str:
    if match.group(1).lower() in {"rdp", "telnet", "smb"}:
        return "critical"
    return "high"


SEVERITY_RULES: list[tuple[re.Pattern[str], str | Callable[[re.Match[str]], str]]] = [
    (re.compile(r"expires in (\d+) days", re.I), _expiration_severity),
    (re.compile(r"high-risk port open: \d+/(\w+)", re.I), _port_severity),
    (re.compile(r"spf policy is permissive", re.I), "critical"),
    (re.compile(r"\bno (?:spf|dmarc) record\b", re.I), "high"),
    (re.compile(r"spf policy is neutral", re.I), "high"),
    (re.compile(r"missing (?:strict-transport-security|content-security-policy)", re.I), "high"),
    (re.compile(r"(\d+) subdomains exposed", re.I), _subdomain_severity),
    (re.compile(r"dmarc policy is p=none", re.I), "medium"),
    (re.compile(r"missing x-frame-options", re.I), "medium"),
    (re.compile(r"domain is only \d+ days old", re.I), "medium"),
    (re.compile(r"\d+ non-web ports open", re.I), "medium"),
    (re.compile(r"spf uses soft-fail", re.I), "low"),
    (re.compile(r"dmarc policy is p=quarantine", re.I), "low"),
    (re.compile(r"no dkim selector found", re.I), "low"),
    (re.compile(r"missing (?:x-content-type-options|referrer-policy|permissions-policy)", re.I), "low"),
    (re.compile(r"server banner exposed", re.I), "low"),
    (re.compile(r"registrant contact data exposed", re.I), "low"),
]


# (pattern, (title, body, priority)) — first match per finding wins; deduped by title.
RECOMMENDATIONS: list[tuple[re.Pattern[str], tuple[str, str, str]]] = [
    (re.compile(r"expires in \d+ days", re.I), (
        "Renew the domain registration",
        "The domain is approaching expiration. A lapsed domain can be hijacked or take down every dependent service.",
        "critical",
    )),
    (re.compile(r"high-risk port open: \d+/(?:rdp|telnet|smb)", re.I), (
        "Restrict administrative protocols",
        "Place RDP, SMB and Telnet behind a VPN or bastion host. Never expose them directly to the public internet.",
        "critical",
    )),
    (re.compile(r"spf policy is permissive", re.I), (
        "Tighten the SPF policy to <code>-all</code>",
        "A permissive SPF (<code>+all</code> or <code>?all</code>) allows anyone to spoof your domain. After verifying the sender list, switch to <code>-all</code>.",
        "critical",
    )),
    (re.compile(r"high-risk port open", re.I), (
        "Audit internet-facing services",
        "Each open port is an attack surface. Confirm the service is up-to-date and constrain reach with firewall rules or allowlists.",
        "high",
    )),
    (re.compile(r"no spf record", re.I), (
        "Publish an SPF record",
        "Add a TXT record like <code>v=spf1 include:_spf.yourprovider.com -all</code> to declare which servers may send mail on your behalf.",
        "high",
    )),
    (re.compile(r"no dmarc record", re.I), (
        "Publish a DMARC record",
        "Start with <code>_dmarc TXT \"v=DMARC1; p=none; rua=mailto:dmarc@yourdomain\"</code> to begin collecting aggregate reports.",
        "high",
    )),
    (re.compile(r"missing strict-transport-security", re.I), (
        "Enable HSTS",
        "Set <code>Strict-Transport-Security: max-age=31536000; includeSubDomains</code> to force HTTPS in compliant browsers.",
        "high",
    )),
    (re.compile(r"missing content-security-policy", re.I), (
        "Define a Content-Security-Policy",
        "Author a CSP whitelisting your script, style and frame sources. Even a permissive starter policy is a strong defense against XSS.",
        "high",
    )),
    (re.compile(r"dmarc policy is p=none", re.I), (
        "Escalate DMARC enforcement",
        "Once aggregate reports look clean, escalate from <code>p=none</code> to <code>p=quarantine</code> and eventually <code>p=reject</code>.",
        "medium",
    )),
    (re.compile(r"missing x-frame-options", re.I), (
        "Protect against clickjacking",
        "Set <code>X-Frame-Options: DENY</code> or the modern CSP <code>frame-ancestors 'none'</code> directive.",
        "medium",
    )),
    (re.compile(r"(\d+) subdomains exposed", re.I), (
        "Audit and trim the subdomain footprint",
        "A wide subdomain inventory expands the attack surface. Decommission unused subdomains and tighten DNS hygiene.",
        "medium",
    )),
    (re.compile(r"domain is only \d+ days old", re.I), (
        "Account for new-domain risk context",
        "Recently registered domains are commonly used for phishing. Factor that into threat-intel and reputation signals.",
        "medium",
    )),
    (re.compile(r"missing x-content-type-options", re.I), (
        "Set <code>X-Content-Type-Options: nosniff</code>",
        "Stops browsers from second-guessing declared MIME types and prevents a class of MIME-confusion attacks.",
        "low",
    )),
    (re.compile(r"missing referrer-policy", re.I), (
        "Add a Referrer-Policy header",
        "Configure <code>Referrer-Policy: strict-origin-when-cross-origin</code> to limit URL leakage to third-party origins.",
        "low",
    )),
    (re.compile(r"missing permissions-policy", re.I), (
        "Declare a Permissions-Policy",
        "Restrict access to powerful browser features (camera, geolocation, payment, etc.) that the site does not use.",
        "low",
    )),
    (re.compile(r"server banner exposed", re.I), (
        "Suppress the Server header",
        "Configure the web server to hide its <code>Server</code> banner so attackers can't fingerprint your stack from the response.",
        "low",
    )),
    (re.compile(r"no dkim selector found", re.I), (
        "Enable DKIM signing",
        "Generate a DKIM key in your mail provider and publish the public part as a TXT record under <code>&lt;selector&gt;._domainkey.yourdomain</code>.",
        "low",
    )),
    (re.compile(r"registrant contact data exposed", re.I), (
        "Enable WHOIS privacy",
        "Most registrars offer free WHOIS privacy. Hiding registrant contact data reduces spam, phishing, and social engineering risk.",
        "low",
    )),
    (re.compile(r"spf uses soft-fail", re.I), (
        "Consider tightening SPF to hard-fail",
        "<code>~all</code> (soft-fail) still allows non-listed senders. Once you're confident in the sender list, move to <code>-all</code>.",
        "low",
    )),
]


def classify_finding(text: str) -> str:
    for pattern, severity in SEVERITY_RULES:
        m = pattern.search(text)
        if m:
            return severity(m) if callable(severity) else severity
    return "info"


def _ring_geometry(score: int, radius: int = 70) -> dict[str, float]:
    score = max(0, min(score, 100))
    circumference = 2 * pi * radius
    return {
        "radius": radius,
        "circumference": round(circumference, 2),
        "offset": round(circumference * (1 - score / 100), 2),
    }


def _collect_findings(risk: dict[str, Any]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for phase, info in (risk.get("breakdown") or {}).items():
        for reason in info.get("reasons") or []:
            findings.append({
                "phase": phase,
                "text": reason,
                "severity": classify_finding(reason),
            })
    findings.sort(key=lambda f: (SEVERITY_ORDER.get(f["severity"], 99), f["phase"]))
    return findings


def _collect_recommendations(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen: set[str] = set()
    recs: list[dict[str, Any]] = []
    for f in findings:
        for pattern, (title, body, priority) in RECOMMENDATIONS:
            if pattern.search(f["text"]):
                if title in seen:
                    break
                seen.add(title)
                recs.append({"title": title, "body": body, "priority": priority})
                break
    recs.sort(key=lambda r: SEVERITY_ORDER.get(r["priority"], 99))
    return recs


def _phase_severity(findings: list[dict[str, Any]], phase_names: list[str]) -> dict[str, str]:
    """Highest severity among each phase's findings (or 'unknown' if none)."""
    result = {p: "unknown" for p in phase_names}
    for f in findings:
        phase = f["phase"]
        if phase not in result:
            continue
        if SEVERITY_ORDER.get(f["severity"], 99) < SEVERITY_ORDER.get(result[phase], 99):
            result[phase] = f["severity"]
    return result


@dataclass
class ReportGenerator:
    output_dir: str = "output"
    template_name: str = "report.html"

    def build(self, results: dict[str, Any]) -> Path:
        out = Path(self.output_dir)
        out.mkdir(parents=True, exist_ok=True)

        env = Environment(
            loader=FileSystemLoader(TEMPLATE_DIR),
            autoescape=select_autoescape(["html"]),
        )

        target = results.get("target", "unknown")
        risk = results.get("risk") or {}
        timestamp = datetime.now(timezone.utc)
        path = out / f"dominus-{target}-{timestamp.strftime('%Y%m%d-%H%M%S')}.html"

        findings = _collect_findings(risk)
        phase_names = list((risk.get("breakdown") or {}).keys())

        html = env.get_template(self.template_name).render(
            target=target,
            generated_at=timestamp.strftime("%Y-%m-%d %H:%M UTC"),
            elapsed=results.get("elapsed_seconds"),
            phases=results.get("phases") or {},
            timings=results.get("timings") or {},
            risk=risk,
            findings=findings,
            recommendations=_collect_recommendations(findings),
            ring=_ring_geometry(int(risk.get("total", 0))),
            phase_icons=PHASE_ICONS,
            phase_descriptions=PHASE_DESCRIPTIONS,
            phase_severity=_phase_severity(findings, phase_names),
            raw_json=json.dumps(results, indent=2, default=str, ensure_ascii=False),
        )
        path.write_text(html, encoding="utf-8")
        return path
