"""
SCRACHER v3 — Threat Intelligence APIs
Integración con VirusTotal v3 y abuse.ch URLhaus.
Diseñado para funcionar con la API key gratuita de VT (4 req/min).
"""

import os
import time
import requests
from pathlib import Path

# ─────────────────────────────────────────────────────────────────────────────
#  CONFIG — cargada desde .env / variables de entorno
# ─────────────────────────────────────────────────────────────────────────────

VT_API_KEY    = os.getenv("VT_API_KEY", "")
VT_BASE       = "https://www.virustotal.com/api/v3"
VT_RATE_DELAY = 16  # segundos entre llamadas (free tier: 4/min)

URLHAUS_BASE  = "https://urlhaus-api.abuse.ch/v1"

# ─────────────────────────────────────────────────────────────────────────────
#  VIRUSTOTAL
# ─────────────────────────────────────────────────────────────────────────────

def _vt_headers() -> dict:
    return {"x-apikey": VT_API_KEY, "Accept": "application/json"}

def vt_check_domain(domain: str, rate_limit: bool = True) -> dict:
    """
    Consulta reputación de dominio en VirusTotal.
    Devuelve dict con: malicious, suspicious, harmless, undetected, engines (list), reputation.
    """
    if not VT_API_KEY:
        return {"error": "VT_API_KEY no configurada", "available": False}

    if rate_limit:
        time.sleep(VT_RATE_DELAY)

    try:
        r = requests.get(
            f"{VT_BASE}/domains/{domain}",
            headers=_vt_headers(),
            timeout=20,
        )
        if r.status_code == 404:
            return {"available": True, "found": False, "domain": domain}
        if r.status_code == 401:
            return {"error": "API key inválida", "available": False}
        r.raise_for_status()
        data = r.json().get("data", {}).get("attributes", {})
        stats = data.get("last_analysis_stats", {})
        engines = [
            {"engine": k, "result": v.get("result"), "category": v.get("category")}
            for k, v in data.get("last_analysis_results", {}).items()
            if v.get("category") in ("malicious", "suspicious")
        ]
        return {
            "available":   True,
            "found":       True,
            "domain":      domain,
            "malicious":   stats.get("malicious", 0),
            "suspicious":  stats.get("suspicious", 0),
            "harmless":    stats.get("harmless", 0),
            "undetected":  stats.get("undetected", 0),
            "reputation":  data.get("reputation", 0),
            "categories":  data.get("categories", {}),
            "engines":     engines[:20],
        }
    except Exception as e:
        return {"error": str(e), "available": False}


def vt_check_url(url: str, rate_limit: bool = True) -> dict:
    """
    Envía una URL a VirusTotal para análisis.
    Devuelve stats de detección.
    """
    if not VT_API_KEY:
        return {"error": "VT_API_KEY no configurada", "available": False}

    if rate_limit:
        time.sleep(VT_RATE_DELAY)

    try:
        import base64
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        r = requests.get(
            f"{VT_BASE}/urls/{url_id}",
            headers=_vt_headers(),
            timeout=20,
        )
        if r.status_code == 404:
            # Enviar para análisis
            r2 = requests.post(
                f"{VT_BASE}/urls",
                headers=_vt_headers(),
                data={"url": url},
                timeout=20,
            )
            if r2.status_code == 200:
                return {"available": True, "submitted": True, "url": url}
            return {"error": f"HTTP {r2.status_code}", "available": False}

        r.raise_for_status()
        data = r.json().get("data", {}).get("attributes", {})
        stats = data.get("last_analysis_stats", {})
        return {
            "available":  True,
            "found":      True,
            "url":        url,
            "malicious":  stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless":   stats.get("harmless", 0),
        }
    except Exception as e:
        return {"error": str(e), "available": False}


# ─────────────────────────────────────────────────────────────────────────────
#  ABUSE.CH — URLhaus
#  No requiere API key. Gratuito y abierto.
# ─────────────────────────────────────────────────────────────────────────────

def urlhaus_check_url(url: str) -> dict:
    """
    Verifica si una URL está en la base de datos de URLhaus (abuse.ch).
    No requiere API key. Tiempo real.
    """
    try:
        r = requests.post(
            f"{URLHAUS_BASE}/url/",
            data={"url": url},
            timeout=15,
        )
        r.raise_for_status()
        data = r.json()
        if data.get("query_status") == "no_results":
            return {"available": True, "found": False, "url": url}
        return {
            "available":   True,
            "found":       True,
            "url":         url,
            "urlhaus_id":  data.get("id"),
            "status":      data.get("url_status"),     # online / offline
            "threat":      data.get("threat"),          # malware_download, botnet_cc...
            "tags":        data.get("tags", []),
            "reporter":    data.get("reporter"),
            "date_added":  data.get("date_added"),
            "urlhaus_ref": data.get("urlhaus_reference"),
        }
    except Exception as e:
        return {"error": str(e), "available": False}


def urlhaus_check_host(host: str) -> dict:
    """
    Verifica un host/dominio en URLhaus.
    """
    try:
        r = requests.post(
            f"{URLHAUS_BASE}/host/",
            data={"host": host},
            timeout=15,
        )
        r.raise_for_status()
        data = r.json()
        if data.get("query_status") == "no_results":
            return {"available": True, "found": False, "host": host}
        urls_count = len(data.get("urls", []))
        return {
            "available":   True,
            "found":       True,
            "host":        host,
            "urlhaus_ref": data.get("urlhaus_reference"),
            "urls_count":  urls_count,
            "blacklists":  data.get("blacklists", {}),
            "urls":        data.get("urls", [])[:10],
        }
    except Exception as e:
        return {"error": str(e), "available": False}


# ─────────────────────────────────────────────────────────────────────────────
#  COMBINED CHECK — llamado desde scrape.py
# ─────────────────────────────────────────────────────────────────────────────

def run_threat_intel(domain: str, url: str, rate_limit: bool = True) -> dict:
    """
    Ejecuta todas las comprobaciones de inteligencia externa.
    Devuelve dict consolidado.
    """
    result = {
        "virustotal":  None,
        "urlhaus_url": None,
        "urlhaus_host": None,
        "external_risk": "unknown",  # clean / suspicious / malicious
    }

    # URLhaus (sin API key — siempre disponible)
    result["urlhaus_url"]  = urlhaus_check_url(url)
    result["urlhaus_host"] = urlhaus_check_host(domain)

    # VirusTotal (solo si hay API key)
    if VT_API_KEY:
        result["virustotal"] = vt_check_domain(domain, rate_limit=rate_limit)

    # Calcular riesgo externo consolidado
    ext_malicious = False
    ext_suspicious = False

    uh_url = result["urlhaus_url"]
    if uh_url.get("found"):
        if uh_url.get("status") == "online":
            ext_malicious = True
        else:
            ext_suspicious = True

    uh_host = result["urlhaus_host"]
    if uh_host.get("found"):
        ext_suspicious = True
        if uh_host.get("urls_count", 0) > 5:
            ext_malicious = True

    vt = result["virustotal"]
    if vt and vt.get("found"):
        if vt.get("malicious", 0) >= 3:
            ext_malicious = True
        elif vt.get("malicious", 0) >= 1 or vt.get("suspicious", 0) >= 2:
            ext_suspicious = True

    if ext_malicious:
        result["external_risk"] = "malicious"
    elif ext_suspicious:
        result["external_risk"] = "suspicious"
    else:
        result["external_risk"] = "clean"

    return result
