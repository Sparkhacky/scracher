"""
SCRACHER v3 — Scraper
Integra: threat intel APIs, crypto extraction, OCR, alertas.
"""

import re
import hashlib
import os
import warnings
from urllib.parse import urlparse
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from urllib3.exceptions import InsecureRequestWarning

from collector.tech_detect    import detect_from_headers, detect_from_html, merge_unique
from collector.capture        import take_screenshot
from collector.content_analyze import analyze_content, detect_language
from collector.link_extract   import extract_onion_links
from collector.crypto_extract import extract_wallets, wallets_summary
from collector.ocr_extract    import ocr_screenshot

warnings.filterwarnings("ignore", category=InsecureRequestWarning)

TOR_SOCKS  = os.getenv("TOR_SOCKS", "socks5h://127.0.0.1:9050")
USE_VT     = bool(os.getenv("VT_API_KEY", ""))
ENABLE_OCR = os.getenv("ENABLE_OCR", "true").lower() == "true"
ENABLE_TI  = os.getenv("ENABLE_THREAT_INTEL", "true").lower() == "true"

def _make_session():
    s = requests.Session()
    s.proxies = {"http": TOR_SOCKS, "https": TOR_SOCKS}
    s.headers.update({
        "User-Agent":      "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                           "(KHTML, like Gecko) Chrome/122 Safari/537.36",
        "Accept-Language": "en-US,en;q=0.9",
        "Accept":          "text/html,application/xhtml+xml,*/*;q=0.8",
    })
    adapter = HTTPAdapter(
        max_retries=Retry(total=2, backoff_factor=1.5,
                          status_forcelist=[500,502,503,504]))
    s.mount("http://", adapter)
    s.mount("https://", adapter)
    return s

session = _make_session()

def get_domain(url): return urlparse(url).netloc

def extract_title(html):
    m = re.search(r"<title[^>]*>(.*?)</title>", html, re.I|re.S)
    if not m: return None
    return " ".join(m.group(1).strip().split()) or None

def content_hash(html):
    return hashlib.sha256(html.encode("utf-8", errors="replace")).hexdigest()[:16]

def fetch(url, timeout=60):
    r = session.get(url, timeout=timeout, allow_redirects=True, verify=False)
    r.raise_for_status()
    return r.url, dict(r.headers), r.text

def scrape_one(url: str, run_threat_intel: bool = None) -> dict:
    """
    Escaneo completo de una URL .onion.
    run_threat_intel: si None, usa ENABLE_TI del entorno.
    """
    do_ti = run_threat_intel if run_threat_intel is not None else ENABLE_TI

    final_url, headers, html = fetch(url)
    domain = get_domain(final_url)
    title  = extract_title(html)
    chash  = content_hash(html)
    lang   = detect_language(html)

    # Tecnologías
    tech = merge_unique(detect_from_headers(headers) + detect_from_html(html))

    # Análisis de amenazas (local, siempre)
    threat = analyze_content(html, title=title or "", url=final_url)

    # Crypto wallets
    wallets = extract_wallets(html, title=title or "", url=final_url)

    # Links .onion descubiertos
    onion_links = extract_onion_links(html, base_url=final_url)

    # Screenshot + OCR
    screenshot = {"path": None, "width": None, "height": None}
    ocr_result = {"available": False, "text": ""}
    try:
        rel_path, w, h = take_screenshot(final_url)
        screenshot = {"path": rel_path, "width": w, "height": h}
        if ENABLE_OCR and rel_path:
            ocr_result = ocr_screenshot(rel_path)
    except Exception as e:
        screenshot["error"] = str(e)

    # Threat Intelligence externa (URLhaus + VirusTotal)
    threat_intel = {"external_risk": "unknown"}
    if do_ti:
        try:
            from collector.threat_intel import run_threat_intel as _run_ti
            threat_intel = _run_ti(domain, final_url, rate_limit=True)
        except Exception as e:
            threat_intel = {"error": str(e), "external_risk": "unknown"}

    return {
        "url":          final_url,
        "domain":       domain,
        "title":        title,
        "content_hash": chash,
        "language":     lang,
        "tech":         tech,
        "threat":       threat,
        "threat_intel": threat_intel,
        "wallets":      wallets,
        "wallets_summary": wallets_summary(wallets),
        "screenshot":   screenshot,
        "ocr":          ocr_result,
        "onion_links":  onion_links,
    }
