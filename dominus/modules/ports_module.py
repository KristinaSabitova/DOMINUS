"""Port scanning phase — wraps python-nmap for service/version discovery.

Requires the `nmap` binary to be installed on the host system.
"""
from __future__ import annotations

from typing import Any

import nmap

DEFAULT_PORTS = "21,22,23,25,53,80,110,143,443,445,3306,3389,5432,6379,8080,8443"
# -sT TCP connect (no root) | -sV version detection | -Pn skip ping
# -T4 fast timing | --open only show open ports | --version-light quick probes
DEFAULT_ARGS = "-sT -sV -Pn -T4 --open --version-light"


def run(target: str, ports: str = DEFAULT_PORTS, arguments: str = DEFAULT_ARGS) -> dict[str, Any]:
    scanner = nmap.PortScanner()
    scanner.scan(hosts=target, ports=ports, arguments=arguments)

    open_ports: list[dict[str, Any]] = []
    services: list[str] = []

    for host in scanner.all_hosts():
        for proto in scanner[host].all_protocols():
            for port, info in scanner[host][proto].items():
                if info.get("state") != "open":
                    continue
                entry = {
                    "host": host,
                    "port": int(port),
                    "protocol": proto,
                    "service": info.get("name") or None,
                    "product": info.get("product") or None,
                    "version": info.get("version") or None,
                    "extrainfo": info.get("extrainfo") or None,
                    "state": info.get("state"),
                }
                open_ports.append(entry)
                if entry["service"]:
                    label = entry["service"]
                    if entry["product"]:
                        label += f" ({entry['product']})"
                    services.append(label)

    return {
        "ports_scanned": ports,
        "arguments": arguments,
        "hosts": scanner.all_hosts(),
        "open_ports": open_ports,
        "services": sorted(set(services)),
        "count": len(open_ports),
    }
