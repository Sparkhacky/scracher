"""
SCRACHER v3 — Crypto Wallet Extractor
Extrae direcciones de Bitcoin, Monero, Ethereum y Litecoin del HTML/texto.
Útil para trazabilidad financiera en investigaciones.
"""

import re
from collections import defaultdict

# ─────────────────────────────────────────────────────────────────────────────
#  REGEX PATTERNS
# ─────────────────────────────────────────────────────────────────────────────

# Bitcoin — P2PKH (1...), P2SH (3...), Bech32 (bc1...)
BTC_P2PKH   = re.compile(r"\b1[a-km-zA-HJ-NP-Z1-9]{25,34}\b")
BTC_P2SH    = re.compile(r"\b3[a-km-zA-HJ-NP-Z1-9]{25,34}\b")
BTC_BECH32  = re.compile(r"\bbc1[a-z0-9]{6,90}\b", re.IGNORECASE)

# Monero — Direcciones estándar (4...) y subaddress (8...) — 95 chars base58
XMR_STANDARD = re.compile(r"\b4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}\b")
XMR_SUBADDR  = re.compile(r"\b8[0-9AB][1-9A-HJ-NP-Za-km-z]{93}\b")

# Ethereum — 0x + 40 hex
ETH = re.compile(r"\b0x[a-fA-F0-9]{40}\b")

# Litecoin — L... (legacy) o ltc1... (bech32)
LTC_LEGACY  = re.compile(r"\b[LM][a-km-zA-HJ-NP-Z1-9]{26,33}\b")
LTC_BECH32  = re.compile(r"\bltc1[a-z0-9]{6,90}\b", re.IGNORECASE)

# ─────────────────────────────────────────────────────────────────────────────

def _extract_all(pattern: re.Pattern, text: str) -> list[str]:
    return list(set(pattern.findall(text)))

def extract_wallets(html: str, title: str = "", url: str = "") -> dict:
    """
    Extrae todas las direcciones de crypto del contenido.
    Devuelve dict por moneda con lista de direcciones únicas.
    """
    # Texto limpio (quitar HTML tags para mejor detección)
    text_raw = f"{title} {url} {html}"
    text_clean = re.sub(r"<[^>]+>", " ", text_raw)

    results = defaultdict(list)

    # Bitcoin
    for addr in _extract_all(BTC_P2PKH, text_clean):
        results["BTC"].append({"address": addr, "type": "P2PKH"})
    for addr in _extract_all(BTC_P2SH, text_clean):
        results["BTC"].append({"address": addr, "type": "P2SH"})
    for addr in _extract_all(BTC_BECH32, text_clean):
        results["BTC"].append({"address": addr.lower(), "type": "Bech32"})

    # Monero (alta relevancia en dark web)
    for addr in _extract_all(XMR_STANDARD, text_clean):
        results["XMR"].append({"address": addr, "type": "standard"})
    for addr in _extract_all(XMR_SUBADDR, text_clean):
        results["XMR"].append({"address": addr, "type": "subaddress"})

    # Ethereum
    for addr in _extract_all(ETH, text_clean):
        # Filtrar falsos positivos comunes (hashes cortos tipo color CSS)
        if len(addr) == 42:
            results["ETH"].append({"address": addr, "type": "EIP-55"})

    # Litecoin
    for addr in _extract_all(LTC_LEGACY, text_clean):
        results["LTC"].append({"address": addr, "type": "legacy"})
    for addr in _extract_all(LTC_BECH32, text_clean):
        results["LTC"].append({"address": addr.lower(), "type": "Bech32"})

    # Deduplicar por dirección dentro de cada coin
    for coin in results:
        seen = set()
        deduped = []
        for w in results[coin]:
            if w["address"] not in seen:
                seen.add(w["address"])
                deduped.append(w)
        results[coin] = deduped

    return dict(results)


def wallets_summary(wallets: dict) -> str:
    """Resumen legible para consola."""
    parts = []
    for coin, addrs in wallets.items():
        parts.append(f"{coin}:{len(addrs)}")
    return " ".join(parts) if parts else "ninguna"


def explorer_url(coin: str, address: str) -> str:
    """URL del block explorer para la dirección."""
    explorers = {
        "BTC": f"https://mempool.space/address/{address}",
        "XMR": f"https://xmrchain.net/search?value={address}",
        "ETH": f"https://etherscan.io/address/{address}",
        "LTC": f"https://litecoinspace.org/address/{address}",
    }
    return explorers.get(coin.upper(), "#")
