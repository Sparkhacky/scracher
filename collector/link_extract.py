"""
SCRACHER — .onion Link Extractor (v2)
Extrae todos los enlaces .onion encontrados en HTML para descubrimiento pasivo.
"""

import re
from urllib.parse import urlparse, urljoin

# v3 .onion (56 chars base32) o v2 (16 chars)
ONION_RE = re.compile(
    r"https?://([a-z2-7]{56}|[a-z2-7]{16})\.onion(?:/[^\s\"'>)]*)?",
    re.IGNORECASE
)

def extract_onion_links(html: str, base_url: str = "") -> list[str]:
    """
    Extrae URLs .onion del HTML.
    Devuelve lista de URLs únicas normalizadas.
    """
    found = set()

    # Buscar en texto/HTML
    for m in ONION_RE.finditer(html):
        url = m.group(0).strip().rstrip(".,;)>\"'")
        # Normalizar a http://
        url = re.sub(r'^https://', 'http://', url, flags=re.I)
        found.add(url)

    # Buscar href/src sin esquema
    bare = re.compile(r'(?:href|src|action)=["\']([a-z2-7]{56}|[a-z2-7]{16})\.onion[^"\']*["\']', re.I)
    for m in bare.finditer(html):
        url = "http://" + m.group(1) + ".onion"
        found.add(url)

    # Excluir la URL base
    if base_url:
        base_domain = urlparse(base_url).netloc
        found = {u for u in found if urlparse(u).netloc != base_domain}

    return sorted(found)
