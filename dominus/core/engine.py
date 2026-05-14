"""Orchestrates the reconnaissance phases and dispatches to the report generator."""
from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from dominus.core.scoring import RiskScorer
from dominus.modules import (
    dns_module,
    headers_module,
    leakradar_module,
    ports_module,
    subdomains_module,
    whois_module,
)
from dominus.report.generator import ReportGenerator
from dominus.utils.logger import get_logger

PHASES: dict[str, Callable[[str], dict[str, Any]]] = {
    "whois": whois_module.run,
    "dns": dns_module.run,
    "subdomains": subdomains_module.run,
    "ports": ports_module.run,
    "headers": headers_module.run,
    "leakradar": leakradar_module.run,
}

LABEL_COLORS = {
    "low": "green",
    "medium": "yellow",
    "high": "dark_orange",
    "critical": "red",
}


@dataclass
class Engine:
    target: str
    output_dir: str = "output"
    skip: list[str] = field(default_factory=list)
    only: list[str] = field(default_factory=list)
    verbose: bool = False
    write_html: bool = True
    write_json: bool = False

    def run(self) -> dict[str, Any]:
        log = get_logger(verbose=self.verbose)
        console = Console()

        selected = self._selected_phases()
        log.info(f"Reconnaissance for [bold]{self.target}[/bold] — {len(selected)} phases")

        started = time.perf_counter()
        results: dict[str, Any] = {
            "target": self.target,
            "started_at": datetime.now(timezone.utc).isoformat(),
            "phases": {},
            "timings": {},
        }

        for name in selected:
            log.info(f"→ {name}")
            phase_start = time.perf_counter()
            try:
                results["phases"][name] = PHASES[name](self.target)
            except Exception as exc:  # noqa: BLE001
                log.error(f"phase {name} failed: {type(exc).__name__}: {exc}")
                results["phases"][name] = {"error": f"{type(exc).__name__}: {exc}"}
            results["timings"][name] = round(time.perf_counter() - phase_start, 2)

        results["risk"] = RiskScorer().score(results["phases"])
        results["elapsed_seconds"] = round(time.perf_counter() - started, 2)
        results["finished_at"] = datetime.now(timezone.utc).isoformat()

        self._write_outputs(results, log)
        self._print_summary(console, results)
        return results

    def _selected_phases(self) -> list[str]:
        if self.only:
            unknown = [p for p in self.only if p not in PHASES]
            if unknown:
                raise ValueError(f"Unknown phases: {unknown}")
            return [p for p in PHASES if p in self.only]
        return [p for p in PHASES if p not in self.skip]

    def _write_outputs(self, results: dict[str, Any], log: Any) -> None:
        out = Path(self.output_dir)
        out.mkdir(parents=True, exist_ok=True)

        if self.write_html:
            html_path = ReportGenerator(output_dir=self.output_dir).build(results)
            log.info(f"HTML: {html_path}")

        if self.write_json:
            stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
            json_path = out / f"dominus-{results['target']}-{stamp}.json"
            json_path.write_text(
                json.dumps(results, indent=2, default=str, ensure_ascii=False),
                encoding="utf-8",
            )
            log.info(f"JSON: {json_path}")

    def _print_summary(self, console: Console, results: dict[str, Any]) -> None:
        risk = results.get("risk") or {}
        total = risk.get("total", 0)
        label = risk.get("label", "unknown")
        color = LABEL_COLORS.get(label, "white")

        console.print()
        console.print(
            Panel.fit(
                f"[bold {color}]{total}/100[/bold {color}]  "
                f"[{color}]{label.upper()}[/{color}]\n"
                f"Target: [bold]{results['target']}[/bold]   "
                f"Elapsed: {results.get('elapsed_seconds')}s",
                title="DOMINUS — Risk Summary",
                border_style=color,
            )
        )

        table = Table(title="Phase breakdown", show_header=True, header_style="bold")
        table.add_column("Phase")
        table.add_column("Score", justify="right")
        table.add_column("Weight", justify="right")
        table.add_column("Time", justify="right")
        table.add_column("Findings")

        timings = results.get("timings", {})
        for phase, info in risk.get("breakdown", {}).items():
            reasons = "\n".join(info.get("reasons") or []) or "—"
            elapsed = timings.get(phase)
            table.add_row(
                phase,
                str(info.get("score", 0)),
                str(info.get("weight", 0)),
                f"{elapsed}s" if elapsed is not None else "—",
                reasons,
            )
        console.print(table)
