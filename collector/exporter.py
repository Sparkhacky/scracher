"""
SCRACHER — Exporter (v2)
Exporta datos a JSON, CSV y reporte HTML para análisis forense / entrega a LEA.
"""

import json
import csv
import io
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EXPORT_DIR = ROOT / "data" / "exports"


def _ensure_dir():
    EXPORT_DIR.mkdir(parents=True, exist_ok=True)


def _ts() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")


def export_json(shops: list[dict]) -> Path:
    _ensure_dir()
    path = EXPORT_DIR / f"scracher_export_{_ts()}.json"
    with open(path, "w", encoding="utf-8") as f:
        json.dump({
            "exported_at": datetime.now(timezone.utc).isoformat(),
            "tool": "SCRACHER v2",
            "count": len(shops),
            "sites": shops,
        }, f, indent=2, ensure_ascii=False, default=str)
    return path


def export_csv(shops: list[dict]) -> Path:
    _ensure_dir()
    path = EXPORT_DIR / f"scracher_export_{_ts()}.csv"
    fieldnames = ["id", "url", "domain", "title", "status", "risk_level",
                  "risk_score", "language", "detected_at", "scan_count",
                  "tags", "keywords", "tech"]
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
        w.writeheader()
        for s in shops:
            row = dict(s)
            row["tags"]     = "|".join(s.get("tags", []))
            row["keywords"] = "|".join(k["keyword"] for k in s.get("keywords", []))
            row["tech"]     = "|".join(t["name"] for t in s.get("tech", []))
            w.writerow(row)
    return path


def export_html_report(shops: list[dict], stats: dict) -> Path:
    """Genera informe HTML legible para entrega a autoridades / CERT."""
    _ensure_dir()
    path = EXPORT_DIR / f"scracher_report_{_ts()}.html"

    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    RISK_COLOR = {
        "critical": "#ef4444",
        "high":     "#f97316",
        "medium":   "#eab308",
        "low":      "#22c55e",
        "clean":    "#6b7280",
        "unknown":  "#6b7280",
    }

    rows_html = ""
    for s in shops:
        rl = s.get("risk_level", "unknown")
        color = RISK_COLOR.get(rl, "#6b7280")
        tags = ", ".join(s.get("tags", []))
        kwds = ", ".join(k["keyword"] for k in s.get("keywords", [])[:8])
        rows_html += f"""
        <tr>
          <td>{s.get('id','')}</td>
          <td style="word-break:break-all;max-width:220px">{s.get('url','')}</td>
          <td>{s.get('title','') or '-'}</td>
          <td><span style="background:{color};color:#fff;padding:2px 8px;border-radius:4px;font-size:12px">{rl.upper()}</span></td>
          <td>{s.get('risk_score',0):.2f}</td>
          <td style="font-size:12px">{tags}</td>
          <td style="font-size:12px;color:#666">{kwds}</td>
          <td>{s.get('scan_count',1)}</td>
          <td style="font-size:12px">{s.get('detected_at','')}</td>
        </tr>"""

    threat_rows = ""
    for t in stats.get("top_threats", []):
        threat_rows += f"<tr><td>{t['category']}</td><td>{t['c']}</td></tr>"

    html = f"""<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="utf-8">
<title>SCRACHER — Informe Forense {now}</title>
<style>
  body {{ font-family: Arial, sans-serif; background: #f9f9f9; color: #222; padding: 32px; }}
  h1 {{ color: #111; }}
  .stats {{ display:flex; gap:16px; flex-wrap:wrap; margin-bottom:24px; }}
  .stat {{ background:#fff; border:1px solid #ddd; border-radius:8px; padding:12px 20px; min-width:120px; }}
  .stat .val {{ font-size:2em; font-weight:bold; }}
  .stat .lbl {{ font-size:12px; color:#666; }}
  table {{ border-collapse:collapse; width:100%; background:#fff; }}
  th,td {{ border:1px solid #ddd; padding:8px 10px; vertical-align:top; }}
  th {{ background:#222; color:#fff; font-size:13px; }}
  tr:nth-child(even) {{ background:#f4f4f4; }}
  .footer {{ margin-top:24px; font-size:12px; color:#999; }}
</style>
</head>
<body>
<h1>🔍 SCRACHER — Informe de Inteligencia .onion</h1>
<p style="color:#666">Generado: {now} &nbsp;|&nbsp; Herramienta: SCRACHER v2 &nbsp;|&nbsp; Uso exclusivo investigativo</p>

<div class="stats">
  <div class="stat"><div class="val">{stats.get('total',0)}</div><div class="lbl">Sitios escaneados</div></div>
  <div class="stat"><div class="val" style="color:#ef4444">{stats.get('critical',0)}</div><div class="lbl">CRÍTICOS</div></div>
  <div class="stat"><div class="val" style="color:#f97316">{stats.get('high',0)}</div><div class="lbl">ALTOS</div></div>
  <div class="stat"><div class="val" style="color:#eab308">{stats.get('medium',0)}</div><div class="lbl">MEDIOS</div></div>
  <div class="stat"><div class="val" style="color:#22c55e">{stats.get('low',0)}</div><div class="lbl">BAJOS</div></div>
  <div class="stat"><div class="val">{stats.get('total_links',0)}</div><div class="lbl">Links descubiertos</div></div>
</div>

<h2>Categorías de amenaza más frecuentes</h2>
<table style="max-width:400px;margin-bottom:24px">
  <tr><th>Categoría</th><th>Ocurrencias</th></tr>
  {threat_rows}
</table>

<h2>Resultados ({len(shops)} sitios)</h2>
<table>
  <tr>
    <th>#</th><th>URL</th><th>Título</th><th>Riesgo</th>
    <th>Score</th><th>Tags</th><th>Keywords</th><th>Scans</th><th>Fecha</th>
  </tr>
  {rows_html}
</table>

<div class="footer">
  ⚠️ Información confidencial — solo para investigación autorizada y cumplimiento legal.<br>
  SCRACHER v2 — Generado automáticamente
</div>
</body>
</html>"""

    with open(path, "w", encoding="utf-8") as f:
        f.write(html)
    return path
