"""
SCRACHER — Threat Content Analyzer (v2)
Detecta keywords de actividad criminal en páginas .onion.
Categorías: drugs, weapons, fraud, exploitation, cybercrime, counterfeit, violence, hitman.
"""

import re
from collections import Counter

# ─────────────────────────────────────────────────────────────────────────────
#  THREAT KEYWORD DATABASE
#  severity: critical / high / medium / low
# ─────────────────────────────────────────────────────────────────────────────

THREAT_DB: list[dict] = [

    # ── CRITICAL ──────────────────────────────────────────────────────────────
    # CSAM / Explotación infantil
    {"keyword": "child",            "category": "exploitation",  "severity": "critical"},
    {"keyword": "minor",            "category": "exploitation",  "severity": "critical"},
    {"keyword": "underage",         "category": "exploitation",  "severity": "critical"},
    {"keyword": "loli",             "category": "exploitation",  "severity": "critical"},
    {"keyword": "preteen",          "category": "exploitation",  "severity": "critical"},
    {"keyword": "jailbait",         "category": "exploitation",  "severity": "critical"},
    # Hitman / violencia contratada
    {"keyword": "hitman",           "category": "violence",      "severity": "critical"},
    {"keyword": "murder for hire",  "category": "violence",      "severity": "critical"},
    {"keyword": "kill service",     "category": "violence",      "severity": "critical"},
    {"keyword": "assassination",    "category": "violence",      "severity": "critical"},
    # Armas de destrucción masiva
    {"keyword": "ricin",            "category": "weapons",       "severity": "critical"},
    {"keyword": "sarin",            "category": "weapons",       "severity": "critical"},
    {"keyword": "anthrax",          "category": "weapons",       "severity": "critical"},
    {"keyword": "dirty bomb",       "category": "weapons",       "severity": "critical"},
    {"keyword": "ied",              "category": "weapons",       "severity": "critical"},
    {"keyword": "explosives",       "category": "weapons",       "severity": "critical"},

    # ── HIGH ─────────────────────────────────────────────────────────────────
    # Drogas
    {"keyword": "cocaine",          "category": "drugs",         "severity": "high"},
    {"keyword": "heroin",           "category": "drugs",         "severity": "high"},
    {"keyword": "fentanyl",         "category": "drugs",         "severity": "high"},
    {"keyword": "methamphetamine",  "category": "drugs",         "severity": "high"},
    {"keyword": "meth",             "category": "drugs",         "severity": "high"},
    {"keyword": "mdma",             "category": "drugs",         "severity": "high"},
    {"keyword": "ecstasy",          "category": "drugs",         "severity": "high"},
    {"keyword": "ketamine",         "category": "drugs",         "severity": "high"},
    {"keyword": "lsd",              "category": "drugs",         "severity": "high"},
    {"keyword": "xanax",            "category": "drugs",         "severity": "high"},
    {"keyword": "oxycodone",        "category": "drugs",         "severity": "high"},
    {"keyword": "drug market",      "category": "drugs",         "severity": "high"},
    {"keyword": "drug store",       "category": "drugs",         "severity": "high"},
    {"keyword": "narcotics",        "category": "drugs",         "severity": "high"},
    # Armas
    {"keyword": "firearms",         "category": "weapons",       "severity": "high"},
    {"keyword": "handgun",          "category": "weapons",       "severity": "high"},
    {"keyword": "assault rifle",    "category": "weapons",       "severity": "high"},
    {"keyword": "glock",            "category": "weapons",       "severity": "high"},
    {"keyword": "silencer",         "category": "weapons",       "severity": "high"},
    {"keyword": "suppressor",       "category": "weapons",       "severity": "high"},
    {"keyword": "gun shop",         "category": "weapons",       "severity": "high"},
    {"keyword": "ammo",             "category": "weapons",       "severity": "high"},
    # Fraude financiero
    {"keyword": "carding",          "category": "fraud",         "severity": "high"},
    {"keyword": "stolen cards",     "category": "fraud",         "severity": "high"},
    {"keyword": "credit card dump", "category": "fraud",         "severity": "high"},
    {"keyword": "fullz",            "category": "fraud",         "severity": "high"},
    {"keyword": "bank logs",        "category": "fraud",         "severity": "high"},
    {"keyword": "money laundering", "category": "fraud",         "severity": "high"},
    {"keyword": "money mule",       "category": "fraud",         "severity": "high"},
    {"keyword": "bitcoin mixer",    "category": "fraud",         "severity": "high"},
    {"keyword": "crypto mixer",     "category": "fraud",         "severity": "high"},
    {"keyword": "tumbler",          "category": "fraud",         "severity": "high"},
    # Cibercriminalidad
    {"keyword": "ransomware",       "category": "cybercrime",    "severity": "high"},
    {"keyword": "malware",          "category": "cybercrime",    "severity": "high"},
    {"keyword": "botnet",           "category": "cybercrime",    "severity": "high"},
    {"keyword": "ddos for hire",    "category": "cybercrime",    "severity": "high"},
    {"keyword": "stresser",         "category": "cybercrime",    "severity": "high"},
    {"keyword": "keylogger",        "category": "cybercrime",    "severity": "high"},
    {"keyword": "rat for sale",     "category": "cybercrime",    "severity": "high"},
    {"keyword": "exploit kit",      "category": "cybercrime",    "severity": "high"},
    {"keyword": "zero-day",         "category": "cybercrime",    "severity": "high"},
    {"keyword": "database dump",    "category": "cybercrime",    "severity": "high"},
    # Trata de personas
    {"keyword": "human trafficking","category": "exploitation",  "severity": "high"},
    {"keyword": "escort service",   "category": "exploitation",  "severity": "high"},
    {"keyword": "sex work",         "category": "exploitation",  "severity": "high"},

    # ── MEDIUM ───────────────────────────────────────────────────────────────
    # Documentos falsos
    {"keyword": "fake id",          "category": "counterfeit",   "severity": "medium"},
    {"keyword": "fake passport",    "category": "counterfeit",   "severity": "medium"},
    {"keyword": "counterfeit",      "category": "counterfeit",   "severity": "medium"},
    {"keyword": "forged documents", "category": "counterfeit",   "severity": "medium"},
    {"keyword": "fake diploma",     "category": "counterfeit",   "severity": "medium"},
    {"keyword": "ssn",              "category": "counterfeit",   "severity": "medium"},
    # Fraude leve
    {"keyword": "phishing",         "category": "fraud",         "severity": "medium"},
    {"keyword": "scam",             "category": "fraud",         "severity": "medium"},
    {"keyword": "dumps",            "category": "fraud",         "severity": "medium"},
    {"keyword": "paypal logs",      "category": "fraud",         "severity": "medium"},
    {"keyword": "hacked accounts",  "category": "fraud",         "severity": "medium"},
    {"keyword": "stealer",          "category": "cybercrime",    "severity": "medium"},
    {"keyword": "spyware",          "category": "cybercrime",    "severity": "medium"},
    {"keyword": "crypter",          "category": "cybercrime",    "severity": "medium"},
    {"keyword": "hacking service",  "category": "cybercrime",    "severity": "medium"},
    # Drogas leves
    {"keyword": "cannabis",         "category": "drugs",         "severity": "medium"},
    {"keyword": "weed",             "category": "drugs",         "severity": "medium"},
    {"keyword": "marijuana",        "category": "drugs",         "severity": "medium"},
    {"keyword": "dispensary",       "category": "drugs",         "severity": "medium"},

    # ── LOW ──────────────────────────────────────────────────────────────────
    {"keyword": "anonymous",        "category": "opsec",         "severity": "low"},
    {"keyword": "darknet",          "category": "opsec",         "severity": "low"},
    {"keyword": "dark web",         "category": "opsec",         "severity": "low"},
    {"keyword": "marketplace",      "category": "market",        "severity": "low"},
    {"keyword": "vendor",           "category": "market",        "severity": "low"},
    {"keyword": "pgp",              "category": "opsec",         "severity": "low"},
    {"keyword": "monero",           "category": "opsec",         "severity": "low"},
    {"keyword": "escrow",           "category": "market",        "severity": "low"},
    {"keyword": "autoshop",         "category": "market",        "severity": "low"},
]

# Compilar patrones una sola vez
_PATTERNS: list[tuple[re.Pattern, dict]] = [
    (re.compile(r"\b" + re.escape(entry["keyword"]) + r"\b", re.IGNORECASE), entry)
    for entry in THREAT_DB
]

SEVERITY_WEIGHT = {"critical": 40, "high": 15, "medium": 5, "low": 1}

# ─────────────────────────────────────────────────────────────────────────────

def analyze_content(html: str, title: str = "", url: str = "") -> dict:
    """
    Analiza HTML + título + URL buscando indicadores de amenaza.
    Devuelve:
      - keywords: lista de matches con conteos
      - tags: categorías detectadas
      - threat_score: puntuación cruda de amenaza (0..∞)
      - risk_score: 0.0 – 1.0 normalizado
      - risk_level: critical / high / medium / low / clean
    """
    text = f"{title} {url} {html}"

    # Contar matches por keyword
    matches: dict[str, dict] = {}
    for pattern, entry in _PATTERNS:
        found = pattern.findall(text)
        if found:
            kw = entry["keyword"]
            if kw not in matches:
                matches[kw] = {
                    "keyword":  kw,
                    "category": entry["category"],
                    "severity": entry["severity"],
                    "count":    0,
                }
            matches[kw]["count"] += len(found)

    keyword_list = list(matches.values())

    # Calcular threat score
    threat_score = sum(
        SEVERITY_WEIGHT.get(m["severity"], 0) * min(m["count"], 10)
        for m in keyword_list
    )

    # Tags únicos de categorías
    tags = sorted(set(m["category"] for m in keyword_list))

    # Determinar risk_level
    has_critical = any(m["severity"] == "critical" for m in keyword_list)
    has_high     = any(m["severity"] == "high"     for m in keyword_list)
    has_medium   = any(m["severity"] == "medium"   for m in keyword_list)

    if has_critical or threat_score >= 100:
        risk_level = "critical"
    elif has_high or threat_score >= 40:
        risk_level = "high"
    elif has_medium or threat_score >= 10:
        risk_level = "medium"
    elif keyword_list:
        risk_level = "low"
    else:
        risk_level = "clean"

    # Normalizar risk_score 0-1
    risk_score = min(1.0, threat_score / 200.0)

    return {
        "keywords":     keyword_list,
        "tags":         tags,
        "threat_score": threat_score,
        "risk_score":   round(risk_score, 4),
        "risk_level":   risk_level,
    }


def detect_language(html: str) -> str | None:
    """Detección básica de idioma por patrones comunes."""
    low = html[:5000].lower()
    checks = [
        ("es", ["comprar", "precio", "envío", "tienda"]),
        ("ru", ["купить", "цена", "магазин"]),
        ("de", ["kaufen", "preis", "lieferung"]),
        ("fr", ["acheter", "prix", "boutique"]),
        ("en", ["buy", "price", "shop", "vendor"]),
    ]
    scores = Counter()
    for lang, words in checks:
        for w in words:
            if w in low:
                scores[lang] += 1
    if not scores:
        return None
    return scores.most_common(1)[0][0]
