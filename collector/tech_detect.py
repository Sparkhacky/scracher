"""
SCRACHER v3 — Technology Detector con extracción de versiones
Cada firma intenta extraer la versión exacta desde headers y/o HTML.
Fuentes: HTTP headers, meta tags, script src, comentarios HTML, atributos data-*.
"""

import re

# ─────────────────────────────────────────────────────────────────────────────
#  HELPERS
# ─────────────────────────────────────────────────────────────────────────────

def _v(pattern: str, text: str, flags=re.I) -> str | None:
    """Extrae primer grupo de captura o None."""
    m = re.search(pattern, text, flags)
    return m.group(1).strip() if m else None

def _meta_generator(html: str) -> str:
    """Extrae el contenido del meta generator."""
    return _v(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)["\']', html) or \
           _v(r'<meta[^>]+content=["\']([^"\']+)["\'][^>]+name=["\']generator["\']', html) or ""

# ─────────────────────────────────────────────────────────────────────────────
#  DETECCIÓN DESDE HEADERS HTTP
# ─────────────────────────────────────────────────────────────────────────────

def detect_from_headers(headers: dict) -> list[dict]:
    h = {k.lower(): v for k, v in headers.items()}
    out = []

    def add(name, category, confidence=0.8, version=None):
        out.append({"name": name, "category": category,
                    "version": version, "confidence": confidence, "source": "headers"})

    server  = h.get("server", "")
    powered = h.get("x-powered-by", "")
    via     = h.get("via", "")
    cookie  = h.get("set-cookie", "")

    # ── SERVIDORES WEB ────────────────────────────────────────────────────────
    if re.search(r"nginx", server, re.I):
        add("Nginx",     "server", 0.95, _v(r"nginx/([\d.]+)", server))
    if re.search(r"apache", server, re.I):
        add("Apache",    "server", 0.95, _v(r"Apache/([\d.]+)", server))
    if re.search(r"lighttpd", server, re.I):
        add("lighttpd",  "server", 0.95, _v(r"lighttpd/([\d.]+)", server))
    if re.search(r"openresty", server, re.I):
        add("OpenResty", "server", 0.95, _v(r"openresty/([\d.]+)", server))
    if re.search(r"litespeed", server, re.I):
        add("LiteSpeed", "server", 0.95, _v(r"LiteSpeed/([\d.]+)", server))
    if re.search(r"caddy", server, re.I):
        add("Caddy",     "server", 0.90, _v(r"Caddy/([\d.]+)", server))
    if re.search(r"\bIIS\b", server, re.I):
        add("IIS",       "server", 0.90, _v(r"IIS/([\d.]+)", server))
    if re.search(r"gunicorn", server, re.I):
        add("Gunicorn",  "server", 0.90, _v(r"gunicorn/([\d.]+)", server))
    if re.search(r"tornado", server, re.I):
        add("Tornado",   "server", 0.85, _v(r"TornadoServer/([\d.]+)", server))
    if re.search(r"uvicorn", server, re.I):
        add("Uvicorn",   "server", 0.90, _v(r"uvicorn/([\d.]+)", server))
    if re.search(r"werkzeug", server, re.I):
        add("Werkzeug",  "server", 0.85, _v(r"Werkzeug/([\d.]+)", server))

    # ── LENGUAJES / RUNTIMES ──────────────────────────────────────────────────
    if re.search(r"php", powered, re.I):
        add("PHP",       "language", 0.97, _v(r"PHP/([\d.]+)", powered))
    if re.search(r"asp\.net", powered, re.I):
        add("ASP.NET",   "language", 0.95, _v(r"ASP\.NET/([\d.]+)", powered))
    if re.search(r"node\.?js", powered, re.I) or re.search(r"express", powered, re.I):
        add("Node.js",   "language", 0.85, _v(r"Node\.js/(v?[\d.]+)", powered))
    if re.search(r"ruby", powered, re.I):
        add("Ruby",      "language", 0.85, _v(r"Ruby/([\d.]+)", powered))
    if re.search(r"python", powered, re.I):
        add("Python",    "language", 0.85, _v(r"Python/([\d.]+)", powered))
    if re.search(r"java", powered, re.I) and "javascript" not in powered.lower():
        add("Java",      "language", 0.80, _v(r"Java/([\d._]+)", powered))
    if re.search(r"perl", powered, re.I):
        add("Perl",      "language", 0.80, _v(r"Perl/([\d.]+)", powered))

    # ── CDN / PROXY / CACHE ───────────────────────────────────────────────────
    if "cloudflare" in server.lower() or "cf-ray" in h:
        add("Cloudflare", "cdn",   0.97)
    if "varnish" in server.lower() or "x-varnish" in h:
        add("Varnish",    "cache", 0.93, _v(r"varnish/([\d.]+)", server))
    if "squid" in server.lower() or "x-squid" in h.get("x-cache",""):
        add("Squid",      "cache", 0.88, _v(r"squid/([\d.]+)", server))
    if "akamai" in server.lower() or "akamai" in h.get("x-check-cacheable",""):
        add("Akamai",     "cdn",   0.90)
    if "fastly" in h.get("x-served-by","") or "fastly" in h.get("x-cache",""):
        add("Fastly",     "cdn",   0.90)
    if re.search(r"haproxy", server, re.I):
        add("HAProxy",    "proxy", 0.90, _v(r"HAProxy/([\d.]+)", server))

    # ── CMS / ECOMMERCE via headers ───────────────────────────────────────────
    if "x-shopify-stage" in h or "x-shopid" in h:
        add("Shopify",   "ecommerce", 0.98)
    if "x-wp-total" in h or "x-wp-totalpages" in h:
        ver = _v(r"WordPress/([\d.]+)", h.get("link",""))
        add("WordPress", "cms",       0.92, ver)
    if "x-drupal-cache" in h or "x-drupal-dynamic-cache" in h:
        add("Drupal",    "cms",       0.95)
    if "x-joomla" in h or "joomla" in h.get("x-content-encoded-by","").lower():
        add("Joomla",    "cms",       0.93)
    if "x-magento" in h or "x-magento-cache-control" in h:
        add("Magento",   "ecommerce", 0.93,
            _v(r"magento/([\d.]+)", h.get("x-magento-version",""), re.I))
    if "x-wc-store-id" in h or "woocommerce" in h.get("x-powered-by","").lower():
        add("WooCommerce", "ecommerce", 0.90)
    if "x-wix-request-id" in h:
        add("Wix",       "website-builder", 0.97)
    if "x-squarespace-id" in h or "squarespace" in h.get("server","").lower():
        add("Squarespace", "website-builder", 0.97)

    # ── FRAMEWORKS BACKEND via headers ────────────────────────────────────────
    if "x-powered-by" in h and "django" in powered.lower():
        add("Django",    "backend", 0.88)
    if "x-flask" in h or "werkzeug" in powered.lower():
        add("Flask",     "backend", 0.85, _v(r"Werkzeug/([\d.]+)", powered))
    if "x-laravel-session" in h or "laravel_session" in cookie:
        add("Laravel",   "backend", 0.90, _v(r"laravel/([\d.]+)", powered, re.I))
    if "x-rails-cache" in h or "_rails_session" in cookie:
        add("Ruby on Rails", "backend", 0.88)
    if "x-symfony" in h or re.search(r"symfony", powered, re.I):
        add("Symfony",   "backend", 0.85, _v(r"symfony/([\d.]+)", powered, re.I))
    if "x-aspnet-version" in h:
        add("ASP.NET",   "language", 0.97, h.get("x-aspnet-version"))
    if "x-runtime" in h and re.search(r"\d+\.\d+", h.get("x-runtime","")):
        # Rails siempre pone X-Runtime en segundos
        add("Ruby on Rails", "backend", 0.75)

    # ── SEGURIDAD (informativo forense) ───────────────────────────────────────
    if "strict-transport-security" in h:
        add("HSTS",            "security", 0.90)
    if "content-security-policy" in h:
        add("CSP",             "security", 0.90)
    if "x-frame-options" in h:
        add("X-Frame-Options", "security", 0.85)
    if "x-xss-protection" in h:
        add("X-XSS-Protection","security", 0.80)
    if "permissions-policy" in h:
        add("Permissions-Policy","security",0.80)

    return out


# ─────────────────────────────────────────────────────────────────────────────
#  DETECCIÓN DESDE HTML
# ─────────────────────────────────────────────────────────────────────────────

def detect_from_html(html: str) -> list[dict]:
    out  = []
    low  = html.lower()
    meta_gen = _meta_generator(html)

    def add(name, category, confidence=0.8, version=None, source="html"):
        out.append({"name": name, "category": category,
                    "version": version, "confidence": confidence, "source": source})

    # ── WORDPRESS ─────────────────────────────────────────────────────────────
    if "/wp-content/" in low or "/wp-includes/" in low or "wp-json" in low:
        # Meta generator: "WordPress 6.4.2"
        ver = _v(r"WordPress ([\d.]+)", meta_gen) or \
              _v(r'content=["\']WordPress ([\d.]+)', html, re.I) or \
              _v(r'ver=([\d.]+)["\'].*?wp-', html, re.I) or \
              _v(r'/wp-includes/js/wp-embed\.min\.js\?ver=([\d.]+)', html, re.I)
        add("WordPress", "cms", 0.93, ver)

    # ── WOOCOMMERCE ───────────────────────────────────────────────────────────
    if "woocommerce" in low:
        ver = _v(r'woocommerce[_-]([\d.]+)\.(?:js|css)', html, re.I) or \
              _v(r'"woocommerce":\{"version":"([\d.]+)"', html, re.I) or \
              _v(r'wc-version.*?([\d.]+)', html, re.I)
        add("WooCommerce", "ecommerce", 0.90, ver)

    # ── SHOPIFY ───────────────────────────────────────────────────────────────
    if "cdn.shopify.com" in low or "myshopify.com" in low:
        add("Shopify", "ecommerce", 0.95)

    # ── MAGENTO ───────────────────────────────────────────────────────────────
    if "mage/" in low or "magento" in low or "mage/cookies" in low:
        ver = _v(r'"Magento_[\w]+":"([\d.]+)"', html, re.I) or \
              _v(r'Mage\.VERSION\s*=\s*["\']([^"\']+)', html, re.I) or \
              _v(r'magento\s+([\d.]+)', meta_gen, re.I) or \
              _v(r'magento/([\d.]+)', html, re.I)
        add("Magento", "ecommerce", 0.85, ver)

    # ── PRESTASHOP ────────────────────────────────────────────────────────────
    if "prestashop" in low:
        ver = _v(r'prestashop\s+([\d.]+)', meta_gen, re.I) or \
              _v(r"prestashop[_-]([\d.]+)\.js", html, re.I) or \
              _v(r'"ps_version"\s*:\s*"([\d.]+)"', html, re.I)
        add("PrestaShop", "ecommerce", 0.87, ver)

    # ── OPENCART ──────────────────────────────────────────────────────────────
    if "opencart" in low or "catalog/view/javascript" in low:
        ver = _v(r'opencart\s+([\d.]+)', meta_gen, re.I) or \
              _v(r'"opencart_version"\s*:\s*"([\d.]+)"', html, re.I)
        add("OpenCart", "ecommerce", 0.83, ver)

    # ── DRUPAL ────────────────────────────────────────────────────────────────
    if "drupal" in low or "/sites/default/files" in low:
        ver = _v(r'Drupal ([\d.]+)', meta_gen, re.I) or \
              _v(r'"drupalSettings".*?"version"\s*:\s*"([\d.]+)"', html, re.I) or \
              _v(r'drupal\.js\?[a-z]=([\d.]+)', html, re.I) or \
              _v(r'/core/misc/drupal\.js\?v=([\d.]+)', html, re.I)
        add("Drupal", "cms", 0.88, ver)

    # ── JOOMLA ────────────────────────────────────────────────────────────────
    if "joomla" in low:
        ver = _v(r'Joomla!\s*([\d.]+)', meta_gen, re.I) or \
              _v(r'/media/jui/js/jquery\.min\.js\?[\d.]+&([\d.]+)', html, re.I) or \
              _v(r'"joomla_version"\s*:\s*"([\d.]+)"', html, re.I)
        add("Joomla", "cms", 0.87, ver)

    # ── GHOST ─────────────────────────────────────────────────────────────────
    if "ghost.org" in low or "ghost-theme" in low or '{"ghost"' in low:
        ver = _v(r'Ghost/([\d.]+)', meta_gen, re.I) or \
              _v(r'"ghost_version"\s*:\s*"([\d.]+)"', html, re.I) or \
              _v(r'ghost@([\d.]+)', html, re.I)
        add("Ghost", "cms", 0.83, ver)

    # ── JQUERY ────────────────────────────────────────────────────────────────
    if "jquery" in low:
        ver = _v(r'jquery[.-]([\d.]+)(?:\.min)?\.js', html, re.I) or \
              _v(r'jQuery v([\d.]+)', html) or \
              _v(r'"jquery"\s*:\s*"([\d.]+)"', html, re.I) or \
              _v(r'jQuery JavaScript Library v([\d.]+)', html)
        add("jQuery", "frontend", 0.85, ver)

    # ── REACT ─────────────────────────────────────────────────────────────────
    if re.search(r"react(?:\.production|\.min|\.development)?\.js", low) or \
       "data-reactroot" in low or "__reactfiber" in low:
        ver = _v(r'react(?:\.production\.min)?\.js\?v=([\d.]+)', html, re.I) or \
              _v(r'react[@/]([\d.]+)', html, re.I) or \
              _v(r'"react"\s*:\s*"[\^~]?([\d.]+)"', html, re.I) or \
              _v(r'React\.version\s*=\s*["\']([^"\']+)', html)
        add("React", "frontend", 0.82, ver)

    # ── VUE.JS ────────────────────────────────────────────────────────────────
    if re.search(r"vue(?:\.min|\.runtime)?\.js", low) or "__vue_app__" in low or \
       "data-v-app" in low:
        ver = _v(r'vue(?:\.min)?\.js\?v=([\d.]+)', html, re.I) or \
              _v(r'vue[@/]([\d.]+)', html, re.I) or \
              _v(r'"version"\s*:\s*"([\d.]+)"\s*,\s*"Vue"', html) or \
              _v(r'Vue\.version\s*=\s*["\']([^"\']+)', html)
        add("Vue.js", "frontend", 0.82, ver)

    # ── ANGULAR ───────────────────────────────────────────────────────────────
    if re.search(r"angular(?:\.min)?\.js", low) or "ng-version" in low:
        ver = _v(r'ng-version="([^"]+)"', html) or \
              _v(r'angular(?:\.min)?\.js\?v=([\d.]+)', html, re.I) or \
              _v(r'angular[@/]([\d.]+)', html, re.I) or \
              _v(r'angular\.version\s*=\s*\{[^}]*full:\s*["\']([^"\']+)', html)
        add("Angular", "frontend", 0.82, ver)

    # ── BOOTSTRAP ─────────────────────────────────────────────────────────────
    if "bootstrap" in low:
        ver = _v(r'bootstrap(?:\.min)?\.(?:js|css)\?v=([\d.]+)', html, re.I) or \
              _v(r'bootstrap[@/]([\d.]+)', html, re.I) or \
              _v(r'Bootstrap v([\d.]+)', html) or \
              _v(r'"bootstrap"\s*:\s*"[\^~]?([\d.]+)"', html, re.I)
        add("Bootstrap", "frontend", 0.80, ver)

    # ── TAILWIND CSS ──────────────────────────────────────────────────────────
    if "tailwind" in low:
        ver = _v(r'tailwindcss[@/]([\d.]+)', html, re.I) or \
              _v(r'tailwind\.css\?v=([\d.]+)', html, re.I)
        add("TailwindCSS", "frontend", 0.78, ver)

    # ── NEXT.JS ───────────────────────────────────────────────────────────────
    if "__next" in low or "_next/static" in low or "next.js" in low:
        ver = _v(r'"next"\s*:\s*"[\^~]?([\d.]+)"', html, re.I) or \
              _v(r'next[@/]([\d.]+)', html, re.I) or \
              _v(r'<meta name="next-head-count"', html, re.I) and \
              _v(r'next/([\d.]+)', html, re.I)
        add("Next.js", "frontend", 0.88, ver)

    # ── NUXT.JS ───────────────────────────────────────────────────────────────
    if "__nuxt" in low or "_nuxt/" in low:
        ver = _v(r'nuxt[@/]([\d.]+)', html, re.I) or \
              _v(r'"nuxt"\s*:\s*"[\^~]?([\d.]+)"', html, re.I)
        add("Nuxt.js", "frontend", 0.87, ver)

    # ── SVELTE ────────────────────────────────────────────────────────────────
    if "svelte" in low or "__svelte" in low:
        ver = _v(r'svelte[@/]([\d.]+)', html, re.I)
        add("Svelte", "frontend", 0.80, ver)

    # ── DJANGO ────────────────────────────────────────────────────────────────
    if "csrfmiddlewaretoken" in low or "django" in low:
        ver = _v(r'django/([\d.]+)', html, re.I) or \
              _v(r'Django/([\d.]+)', meta_gen)
        add("Django", "backend", 0.83, ver)

    # ── FLASK ─────────────────────────────────────────────────────────────────
    if "werkzeug" in low or ("flask" in low and "python" in low):
        ver = _v(r'Flask/([\d.]+)', html, re.I) or \
              _v(r'Werkzeug/([\d.]+)', html, re.I)
        add("Flask", "backend", 0.75, ver)

    # ── LARAVEL ───────────────────────────────────────────────────────────────
    if "laravel" in low or "laravel_session" in low:
        ver = _v(r'laravel/([\d.]+)', html, re.I) or \
              _v(r'"laravel_version"\s*:\s*"([\d.]+)"', html, re.I)
        add("Laravel", "backend", 0.85, ver)

    # ── SYMFONY ───────────────────────────────────────────────────────────────
    if "symfony" in low:
        ver = _v(r'Symfony ([\d.]+)', meta_gen, re.I) or \
              _v(r'symfony/([\d.]+)', html, re.I)
        add("Symfony", "backend", 0.82, ver)

    # ── RUBY ON RAILS ─────────────────────────────────────────────────────────
    if "rails" in low or "rails-ujs" in low or "actiondispatch" in low:
        ver = _v(r'rails/([\d.]+)', html, re.I) or \
              _v(r'"railsVersion"\s*:\s*"([\d.]+)"', html, re.I)
        add("Ruby on Rails", "backend", 0.80, ver)

    # ── ASP.NET ───────────────────────────────────────────────────────────────
    if "__viewstate" in low or "asp.net" in low:
        ver = _v(r'ASP\.NET\s+([\d.]+)', meta_gen, re.I)
        add("ASP.NET", "language", 0.90, ver)

    # ── GOOGLE ANALYTICS ─────────────────────────────────────────────────────
    if "google-analytics.com" in low or "googletagmanager.com" in low or \
       "gtag(" in low or "ga(" in low:
        ver = "GA4" if "gtag(" in low else ("UA" if re.search(r"UA-\d+", html) else None)
        add("Google Analytics", "analytics", 0.90, ver)

    # ── MATOMO ────────────────────────────────────────────────────────────────
    if "matomo" in low or "piwik" in low:
        ver = _v(r'matomo/([\d.]+)', html, re.I) or \
              _v(r'piwik/([\d.]+)', html, re.I)
        add("Matomo", "analytics", 0.87, ver)

    # ── STRIPE ────────────────────────────────────────────────────────────────
    if "stripe" in low and ("js.stripe.com" in low or "stripe.js" in low or
                             "stripe-js" in low):
        ver = _v(r'js\.stripe\.com/v(\d)', html, re.I)
        ver = f"v{ver}" if ver else None
        add("Stripe", "payments", 0.88, ver)

    # ── PAYPAL ────────────────────────────────────────────────────────────────
    if "paypalobjects.com" in low or "paypal.com/sdk" in low:
        ver = _v(r'paypal\.com/sdk/js\?.*?version=([\d.]+)', html, re.I)
        add("PayPal", "payments", 0.88, ver)

    # ── CLOUDFLARE ROCKET LOADER ──────────────────────────────────────────────
    if "cloudflare" in low and "rocket-loader" in low:
        add("Cloudflare Rocket Loader", "cdn", 0.88)

    # ── RECAPTCHA ─────────────────────────────────────────────────────────────
    if "recaptcha" in low:
        ver = "v3" if "recaptcha/api.js" in low and "render=" in low else \
              "v2" if "recaptcha/api.js" in low else None
        add("reCAPTCHA", "security", 0.88, ver)

    # ── HCAPTCHA ──────────────────────────────────────────────────────────────
    if "hcaptcha.com" in low:
        add("hCaptcha", "security", 0.90)

    # ── CRYPTO (dark web relevance) ───────────────────────────────────────────
    if re.search(r"\b(bitcoin|btc)\b", low):
        add("Bitcoin",  "crypto", 0.82)
    if re.search(r"\b(monero|xmr)\b", low):
        add("Monero",   "crypto", 0.92)
    if re.search(r"\b(ethereum|eth)\b", low):
        add("Ethereum", "crypto", 0.78)
    if re.search(r"\blitecoin\b|\bltc\b", low):
        add("Litecoin", "crypto", 0.75)

    # ── TOR ───────────────────────────────────────────────────────────────────
    if ".onion" in low and ("hidden service" in low or "onion service" in low):
        ver = "v3" if re.search(r"[a-z2-7]{56}\.onion", low) else \
              "v2" if re.search(r"[a-z2-7]{16}\.onion", low) else None
        add("Tor Hidden Service", "network", 0.92, ver)

    return out


# ─────────────────────────────────────────────────────────────────────────────
#  MERGE — prioriza mayor confidence, conserva versión si la tiene
# ─────────────────────────────────────────────────────────────────────────────

def merge_unique(items: list[dict]) -> list[dict]:
    best: dict[tuple, dict] = {}
    for t in items:
        key = (t.get("name"), t.get("category"))
        c   = float(t.get("confidence", 0.0) or 0.0)
        existing = best.get(key)
        if existing is None:
            best[key] = t
        else:
            # Si el nuevo tiene mayor confidence → reemplaza
            # Si tiene la misma confidence pero agrega versión → toma la versión
            ec = float(existing.get("confidence", 0.0) or 0.0)
            if c > ec:
                best[key] = t
            elif c == ec and not existing.get("version") and t.get("version"):
                existing["version"] = t["version"]
    return list(best.values())
