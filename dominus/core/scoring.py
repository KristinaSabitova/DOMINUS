"""Risk scoring engine — aggregates findings from each phase into a score and label."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass
class RiskScorer:
    """Computes a 0-100 risk score from per-phase findings.

    Each phase contributes a bounded sub-score (capped by its weight). The total
    is the sum across phases, capped at 100. Higher = more exposure.
    """

    WEIGHTS = {
        "whois": 10,
        "dns": 15,
        "subdomains": 20,
        "ports": 35,
        "headers": 20,
    }

    HIGH_RISK_PORTS = {
        21: ("ftp", 6),
        23: ("telnet", 8),
        135: ("msrpc", 4),
        139: ("netbios", 5),
        445: ("smb", 8),
        1433: ("mssql", 5),
        1521: ("oracle", 5),
        3306: ("mysql", 5),
        3389: ("rdp", 8),
        5432: ("postgres", 5),
        5900: ("vnc", 6),
        6379: ("redis", 6),
        9200: ("elasticsearch", 6),
        11211: ("memcached", 5),
        27017: ("mongodb", 6),
    }

    SECURITY_HEADER_PENALTIES = {
        "strict-transport-security": 4,
        "content-security-policy": 4,
        "x-frame-options": 3,
        "x-content-type-options": 2,
        "referrer-policy": 2,
        "permissions-policy": 2,
    }

    # --- entry point ---------------------------------------------------------

    def score(self, phases: dict[str, Any]) -> dict[str, Any]:
        scorers = {
            "whois": self._score_whois,
            "dns": self._score_dns,
            "subdomains": self._score_subdomains,
            "ports": self._score_ports,
            "headers": self._score_headers,
        }

        breakdown: dict[str, dict[str, Any]] = {}
        for phase, weight in self.WEIGHTS.items():
            data = phases.get(phase) or {}
            if not data or "error" in data:
                breakdown[phase] = {"score": 0, "weight": weight, "reasons": []}
                continue
            raw, reasons = scorers[phase](data)
            breakdown[phase] = {
                "score": min(raw, weight),
                "weight": weight,
                "reasons": reasons,
            }

        total = min(sum(b["score"] for b in breakdown.values()), 100)
        return {
            "total": total,
            "label": self._label(total),
            "breakdown": breakdown,
        }

    # --- per-phase heuristics ------------------------------------------------

    def _score_whois(self, data: dict[str, Any]) -> tuple[int, list[str]]:
        score = 0
        reasons: list[str] = []

        days_left = data.get("days_until_expiration")
        if isinstance(days_left, int):
            if days_left < 7:
                score += 6
                reasons.append(f"Domain expires in {days_left} days")
            elif days_left < 30:
                score += 3
                reasons.append(f"Domain expires in {days_left} days")

        age = data.get("domain_age_days")
        if isinstance(age, int) and 0 <= age < 90:
            score += 3
            reasons.append(f"Domain is only {age} days old")

        if data.get("privacy_protected") is False and data.get("emails"):
            score += 2
            reasons.append("Registrant contact data exposed (no WHOIS privacy)")

        return score, reasons

    def _score_dns(self, data: dict[str, Any]) -> tuple[int, list[str]]:
        score = 0
        reasons: list[str] = []

        spf = data.get("spf")
        if not spf:
            score += 5
            reasons.append("No SPF record")
        else:
            policy = spf.get("policy")
            if policy in ("neutral", "permissive"):
                score += 4
                reasons.append(f"SPF policy is {policy}")
            elif policy == "soft":
                score += 1
                reasons.append("SPF uses soft-fail (~all)")

        dmarc = data.get("dmarc")
        if not dmarc:
            score += 5
            reasons.append("No DMARC record")
        else:
            policy = (dmarc.get("policy") or "").lower()
            if policy == "none":
                score += 3
                reasons.append("DMARC policy is p=none (monitor only)")
            elif policy == "quarantine":
                score += 1
                reasons.append("DMARC policy is p=quarantine")

        if not data.get("has_dkim"):
            score += 1
            reasons.append("No DKIM selector found among common selectors")

        return score, reasons

    def _score_subdomains(self, data: dict[str, Any]) -> tuple[int, list[str]]:
        count = data.get("count") or len(data.get("subdomains") or [])
        if count <= 5:
            return 0, []
        if count <= 20:
            return 5, [f"{count} subdomains exposed"]
        if count <= 50:
            return 10, [f"{count} subdomains exposed"]
        if count <= 100:
            return 15, [f"{count} subdomains exposed"]
        return 20, [f"{count} subdomains exposed (large attack surface)"]

    def _score_ports(self, data: dict[str, Any]) -> tuple[int, list[str]]:
        score = 0
        reasons: list[str] = []

        ports: list[int] = []
        for entry in data.get("open_ports") or []:
            try:
                ports.append(int(entry["port"]) if isinstance(entry, dict) else int(entry))
            except (TypeError, ValueError, KeyError):
                continue

        for port in ports:
            if port in self.HIGH_RISK_PORTS:
                name, penalty = self.HIGH_RISK_PORTS[port]
                score += penalty
                reasons.append(f"High-risk port open: {port}/{name}")

        non_web = sum(1 for p in ports if p not in (80, 443))
        if non_web:
            score += min(non_web, 5)
            reasons.append(f"{non_web} non-web ports open")

        return score, reasons

    def _score_headers(self, data: dict[str, Any]) -> tuple[int, list[str]]:
        score = 0
        reasons: list[str] = []

        present = data.get("security_headers") or {}
        for header, penalty in self.SECURITY_HEADER_PENALTIES.items():
            if not present.get(header):
                score += penalty
                reasons.append(f"Missing {header}")

        if data.get("server"):
            score += 2
            reasons.append(f"Server banner exposed: {data['server']}")

        return score, reasons

    # --- label ---------------------------------------------------------------

    @staticmethod
    def _label(total: int) -> str:
        if total >= 75:
            return "critical"
        if total >= 50:
            return "high"
        if total >= 25:
            return "medium"
        return "low"
