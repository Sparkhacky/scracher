# collector/scrape.py
import re
from urllib.parse import urlparse
import requests

from collector.tech_detect import detect_from_headers, detect_from_html, merge_unique
from collector.capture import take_screenshot

TOR_SOCKS = "socks5h://127.0.0.1:9050"  # socks5h IMPORTANTÍSIMO para .onion

session = requests.Session()
session.proxies = {"http": TOR_SOCKS, "https": TOR_SOCKS}
session.headers.update({
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122 Safari/537.36",
    "Accept-Language": "en-US,en;q=0.9",
})

def get_domain(url: str) -> str:
    return urlparse(url).netloc

def extract_title(html: str) -> str | None:
    m = re.search(r"<title[^>]*>(.*?)</title>", html, flags=re.I | re.S)
    if not m:
        return None
    title = " ".join(m.group(1).strip().split())
    return title or None

def fetch(url: str, timeout: int = 60) -> tuple[str, dict[str, str], str]:
    # Muchos .onion son http (no https). No fuerces https.
    r = session.get(url, timeout=timeout, allow_redirects=True, verify=False)
    r.raise_for_status()
    final_url = r.url
    headers = dict(r.headers)
    html = r.text
    return final_url, headers, html

def scrape_one(url: str) -> dict:
    final_url, headers, html = fetch(url)
    domain = get_domain(final_url)
    title = extract_title(html)

    tech = []
    tech += detect_from_headers(headers)
    tech += detect_from_html(html)
    tech = merge_unique(tech)

    screenshot_rel, w, h = take_screenshot(final_url)  # también via Tor (ver abajo)

    return {
        "url": final_url,
        "domain": domain,
        "title": title,
        "tech": tech,
        "screenshot": {"path": screenshot_rel, "width": w, "height": h},
    }
