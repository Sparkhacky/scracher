import re

def detect_from_headers(headers: dict[str, str]) -> list[dict]:
    h = {k.lower(): v for k, v in headers.items()}
    out = []

    # Server
    server = h.get("server", "")
    if server:
        out.append({"name": server.split()[0], "category": "server", "version": None, "confidence": 0.55, "source": "headers"})

    # Cloudflare
    if "cloudflare" in (h.get("server", "").lower() + " " + h.get("cf-ray", "").lower()):
        out.append({"name": "Cloudflare", "category": "cdn", "version": None, "confidence": 0.9, "source": "headers"})

    # Shopify hints
    if "shopify" in (h.get("x-shopify-stage", "").lower() + " " + h.get("x-shopify-shop-api-call-limit", "").lower()):
        out.append({"name": "Shopify", "category": "ecommerce", "version": None, "confidence": 0.95, "source": "headers"})

    return out

def detect_from_html(html: str) -> list[dict]:
    out = []
    low = html.lower()

    # Shopify
    if "cdn.shopify.com" in low or "x-shopify" in low or "shopify" in low and "myshopify" in low:
        out.append({"name": "Shopify", "category": "ecommerce", "version": None, "confidence": 0.9, "source": "html"})

    # WooCommerce
    if "woocommerce" in low or "/wp-content/" in low:
        if "woocommerce" in low:
            out.append({"name": "WooCommerce", "category": "ecommerce", "version": None, "confidence": 0.85, "source": "html"})
        out.append({"name": "WordPress", "category": "cms", "version": None, "confidence": 0.8, "source": "html"})

    # Magento
    if "mage/" in low or "magento" in low:
        out.append({"name": "Magento", "category": "ecommerce", "version": None, "confidence": 0.75, "source": "html"})

    # Google Analytics
    if "googletagmanager.com/gtm.js" in low or "google-analytics.com" in low or "gtag(" in low:
        out.append({"name": "Google Analytics", "category": "analytics", "version": None, "confidence": 0.85, "source": "html"})

    # Stripe
    if "stripe" in low:
        out.append({"name": "Stripe", "category": "payments", "version": None, "confidence": 0.6, "source": "html"})

    # React
    if re.search(r"react(\.production|min)?\.js", low) or "data-reactroot" in low:
        out.append({"name": "React", "category": "frontend", "version": None, "confidence": 0.6, "source": "html"})

    return out

def merge_unique(items: list[dict]) -> list[dict]:
    # Deduplicar por name+category priorizando mayor confidence
    best = {}
    for t in items:
        key = (t.get("name"), t.get("category"))
        c = float(t.get("confidence", 0.0) or 0.0)
        if key not in best or c > float(best[key].get("confidence", 0.0) or 0.0):
            best[key] = t
    return list(best.values())
