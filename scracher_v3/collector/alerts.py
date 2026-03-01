"""
SCRACHER v3 — Alert System
Notificaciones automáticas via Slack (webhook) y email (SMTP).
Se disparan cuando se detecta un sitio con risk_level >= umbral configurado.
"""

import os
import smtplib
import json
import requests
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime, timezone

# ─────────────────────────────────────────────────────────────────────────────
#  CONFIG desde .env
# ─────────────────────────────────────────────────────────────────────────────

SLACK_WEBHOOK     = os.getenv("SLACK_WEBHOOK_URL", "")
ALERT_MIN_LEVEL   = os.getenv("ALERT_MIN_LEVEL", "high")   # critical / high / medium

SMTP_HOST         = os.getenv("SMTP_HOST", "")
SMTP_PORT         = int(os.getenv("SMTP_PORT", "587"))
SMTP_USER         = os.getenv("SMTP_USER", "")
SMTP_PASS         = os.getenv("SMTP_PASS", "")
SMTP_FROM         = os.getenv("SMTP_FROM", "scracher@localhost")
SMTP_TO           = os.getenv("SMTP_TO", "")   # múltiples: a@b.com,c@d.com

RISK_ORDER = ["clean", "unknown", "low", "medium", "high", "critical"]

RISK_EMOJI = {
    "critical": "🔴",
    "high":     "🟠",
    "medium":   "🟡",
    "low":      "🟢",
    "clean":    "⚪",
    "unknown":  "⚫",
}

# ─────────────────────────────────────────────────────────────────────────────

def _should_alert(risk_level: str) -> bool:
    """Decide si el nivel de riesgo supera el umbral configurado."""
    try:
        return RISK_ORDER.index(risk_level) >= RISK_ORDER.index(ALERT_MIN_LEVEL)
    except ValueError:
        return False


def _build_message(site: dict) -> dict:
    """Construye el payload de alerta con datos del sitio."""
    rl    = site.get("risk_level", "unknown")
    emoji = RISK_EMOJI.get(rl, "⚫")
    ts    = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    tags    = ", ".join(site.get("tags", [])) or "—"
    keywords= ", ".join(k["keyword"] for k in site.get("keywords", [])[:8]) or "—"
    wallets = site.get("wallets_summary", "—")
    ext_risk= site.get("external_risk", "unknown")

    title = (
        f"{emoji} SCRACHER ALERT — {rl.upper()} — {site.get('domain','?')}"
    )
    body = (
        f"*URL:* {site.get('url','?')}\n"
        f"*Título:* {site.get('title','?')}\n"
        f"*Nivel de riesgo:* {rl.upper()}  (score: {site.get('risk_score',0):.3f})\n"
        f"*Riesgo externo (VT/URLhaus):* {ext_risk}\n"
        f"*Categorías:* {tags}\n"
        f"*Keywords detectadas:* {keywords}\n"
        f"*Wallets cripto:* {wallets}\n"
        f"*Idioma:* {site.get('language','?')}\n"
        f"*Timestamp:* {ts}\n"
        f"*Dashboard:* http://127.0.0.1:8000/shop/{site.get('shop_id','?')}"
    )
    return {"title": title, "body": body, "risk_level": rl, "emoji": emoji}


# ─────────────────────────────────────────────────────────────────────────────
#  SLACK
# ─────────────────────────────────────────────────────────────────────────────

def send_slack(site: dict) -> dict:
    """Envía alerta a Slack via Incoming Webhook."""
    if not SLACK_WEBHOOK:
        return {"sent": False, "reason": "SLACK_WEBHOOK_URL no configurada"}

    msg = _build_message(site)
    payload = {
        "text": msg["title"],
        "blocks": [
            {
                "type": "header",
                "text": {"type": "plain_text", "text": msg["title"]}
            },
            {
                "type": "section",
                "text": {"type": "mrkdwn", "text": msg["body"]}
            },
            {
                "type": "divider"
            }
        ]
    }

    try:
        r = requests.post(SLACK_WEBHOOK, json=payload, timeout=10)
        if r.status_code == 200 and r.text == "ok":
            return {"sent": True, "channel": "slack"}
        return {"sent": False, "reason": f"HTTP {r.status_code}: {r.text}"}
    except Exception as e:
        return {"sent": False, "reason": str(e)}


# ─────────────────────────────────────────────────────────────────────────────
#  EMAIL
# ─────────────────────────────────────────────────────────────────────────────

def send_email(site: dict) -> dict:
    """Envía alerta por email via SMTP."""
    if not all([SMTP_HOST, SMTP_USER, SMTP_PASS, SMTP_TO]):
        return {"sent": False, "reason": "SMTP no configurado completamente"}

    msg_data = _build_message(site)
    recipients = [r.strip() for r in SMTP_TO.split(",") if r.strip()]

    msg = MIMEMultipart("alternative")
    msg["Subject"] = msg_data["title"]
    msg["From"]    = SMTP_FROM
    msg["To"]      = ", ".join(recipients)

    # Plain text
    plain = msg_data["body"].replace("*", "")
    msg.attach(MIMEText(plain, "plain"))

    # HTML
    rl    = site.get("risk_level", "unknown")
    color = {"critical":"#ef4444","high":"#f97316","medium":"#eab308",
             "low":"#22c55e","clean":"#6b7280"}.get(rl,"#6b7280")
    html_body = f"""
    <div style="font-family:Arial,sans-serif;max-width:600px;margin:0 auto">
      <div style="background:{color};color:#fff;padding:16px;border-radius:8px 8px 0 0">
        <h2 style="margin:0">{msg_data['title']}</h2>
      </div>
      <div style="background:#f9f9f9;padding:16px;border:1px solid #ddd;border-radius:0 0 8px 8px">
        <pre style="font-size:14px;white-space:pre-wrap">{plain}</pre>
      </div>
      <p style="font-size:11px;color:#999;margin-top:8px">
        SCRACHER v3 — Threat Intelligence Tool — Uso investigativo autorizado
      </p>
    </div>
    """
    msg.attach(MIMEText(html_body, "html"))

    try:
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=15) as server:
            server.ehlo()
            server.starttls()
            server.login(SMTP_USER, SMTP_PASS)
            server.sendmail(SMTP_FROM, recipients, msg.as_string())
        return {"sent": True, "channel": "email", "recipients": recipients}
    except Exception as e:
        return {"sent": False, "reason": str(e)}


# ─────────────────────────────────────────────────────────────────────────────
#  DISPATCHER — llámalo desde run.py/scrape.py
# ─────────────────────────────────────────────────────────────────────────────

def dispatch_alerts(site: dict) -> list[dict]:
    """
    Envía alertas a todos los canales configurados si el riesgo supera el umbral.
    site: dict con url, domain, title, risk_level, risk_score, tags, keywords, etc.
    Devuelve lista de resultados por canal.
    """
    if not _should_alert(site.get("risk_level", "clean")):
        return []

    results = []
    if SLACK_WEBHOOK:
        results.append(send_slack(site))
    if SMTP_HOST and SMTP_TO:
        results.append(send_email(site))

    return results


def alerts_status() -> dict:
    """Estado de los canales de alerta para mostrar en consola/dashboard."""
    return {
        "slack":       bool(SLACK_WEBHOOK),
        "email":       bool(SMTP_HOST and SMTP_TO),
        "min_level":   ALERT_MIN_LEVEL,
        "any_enabled": bool(SLACK_WEBHOOK or (SMTP_HOST and SMTP_TO)),
    }
