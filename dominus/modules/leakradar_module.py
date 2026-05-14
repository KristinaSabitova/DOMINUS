"""LeakRadar phase — busca exposiciones del dominio en Pastebin via Google dorks."""
from __future__ import annotations

import re
import time
from typing import Any

try:
    import requests as _requests
    _REQUESTS_AVAILABLE = True
except ImportError:
    _REQUESTS_AVAILABLE = False

HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/124.0.0.0 Safari/537.36"
    )
}

DORKS = [
    'site:pastebin.com "{domain}"',
    'site:pastebin.com "{domain}" password',
    'site:pastebin.com "{domain}" email',
    'site:pastebin.com "{domain}" credential',
]

PASTE_RE = re.compile(r'pastebin\.com/([a-zA-Z0-9]{6,12})')


def _clean_html(text: str) -> str:
    return re.sub(r'<[^>]+>', '', text).strip()


def _google_dork(query: str) -> list[dict[str, str]]:
    """Lanza una búsqueda en Google y extrae paste IDs de Pastebin."""
    if not _REQUESTS_AVAILABLE:
        return []
    url = "https://www.google.com/search"
    params = {"q": query, "num": 10, "hl": "es"}
    try:
        resp = _requests.get(url, headers=HEADERS, params=params, timeout=10)
        if resp.status_code != 200:
            return []
        paste_ids = list(dict.fromkeys(PASTE_RE.findall(resp.text)))
        return [
            {"url": f"https://pastebin.com/{pid}", "paste_id": pid}
            for pid in paste_ids[:5]
        ]
    except Exception:  # noqa: BLE001
        return []


def _classify_paste(paste_id: str, query: str) -> str:
    """Clasifica el paste según el dork que lo encontró."""
    if "password" in query:
        return "contraseñas"
    if "email" in query:
        return "emails"
    if "credential" in query:
        return "credenciales"
    return "mención general"


def run(target: str) -> dict[str, Any]:
    """Busca menciones del dominio *target* en Pastebin via Google dorks.

    No requiere API key ni registro.
    Devuelve:
      - pastes: lista de URLs encontradas con clasificación
      - total: número de pastes únicos
      - risk_note: texto descriptivo para el informe
      - skipped: False siempre
    """
    if not _REQUESTS_AVAILABLE:
        return {
            "skipped": True,
            "reason": "requests no instalado",
            "total": 0,
            "pastes": [],
            "risk_note": "",
        }

    found: dict[str, dict] = {}

    for dork_tpl in DORKS:
        query = dork_tpl.format(domain=target)
        results = _google_dork(query)
        for r in results:
            pid = r["paste_id"]
            if pid not in found:
                found[pid] = {
                    "url": r["url"],
                    "paste_id": pid,
                    "tipo": _classify_paste(pid, query),
                }
        time.sleep(1.2)  # evitar rate-limit de Google

    pastes = list(found.values())
    total = len(pastes)

    if total == 0:
        risk_note = "No se encontraron menciones del dominio en Pastebin."
    elif total <= 3:
        risk_note = f"{total} paste(s) encontrado(s) en Pastebin. Revisión recomendada."
    elif total <= 10:
        risk_note = (
            f"{total} pastes encontrados en Pastebin. "
            "Exposición moderada — revisar contenido manualmente."
        )
    else:
        risk_note = (
            f"{total} pastes encontrados en Pastebin. "
            "Exposición alta — posible filtración de datos sensibles."
        )

    return {
        "skipped": False,
        "total": total,
        "pastes": pastes,
        "risk_note": risk_note,
    }
