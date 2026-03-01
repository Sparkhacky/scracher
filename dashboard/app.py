"""
SCRACHER v3 — Dashboard FastAPI
Nuevas rutas: /wallets, /intel, /scheduler, /api/wallets, /api/rescan_log
"""

import json
import sqlite3
from pathlib import Path
from fastapi import FastAPI, Request, Query
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

BASE_DIR = Path(__file__).resolve().parent
ROOT     = BASE_DIR.parent
DB_PATH  = (ROOT / "data" / "scrs.db").resolve()

app = FastAPI(title="SCRACHER v3", version="3.0")
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))

# Crear carpetas si no existen y montar static
_static_dir = BASE_DIR / "static"
_static_dir.mkdir(parents=True, exist_ok=True)
(_static_dir / "screenshots").mkdir(exist_ok=True)
app.mount("/static", StaticFiles(directory=str(_static_dir)), name="static")

def db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def get_stats_db():
    conn = db()
    s = {
        "total":    conn.execute("SELECT COUNT(*) FROM shops").fetchone()[0],
        "ok":       conn.execute("SELECT COUNT(*) FROM shops WHERE status='ok'").fetchone()[0],
        "errors":   conn.execute("SELECT COUNT(*) FROM shops WHERE status='error'").fetchone()[0],
        "critical": conn.execute("SELECT COUNT(*) FROM shops WHERE risk_level='critical'").fetchone()[0],
        "high":     conn.execute("SELECT COUNT(*) FROM shops WHERE risk_level='high'").fetchone()[0],
        "medium":   conn.execute("SELECT COUNT(*) FROM shops WHERE risk_level='medium'").fetchone()[0],
        "low":      conn.execute("SELECT COUNT(*) FROM shops WHERE risk_level='low'").fetchone()[0],
        "clean":    conn.execute("SELECT COUNT(*) FROM shops WHERE risk_level='clean'").fetchone()[0],
        "pending_links": conn.execute("SELECT COUNT(*) FROM discovered_links WHERE scanned=0").fetchone()[0],
        "total_links":   conn.execute("SELECT COUNT(*) FROM discovered_links").fetchone()[0],
        "wallets_total": conn.execute("SELECT COUNT(*) FROM wallets").fetchone()[0] if _table_exists(conn,"wallets") else 0,
        "alerts_sent":   conn.execute("SELECT COUNT(*) FROM alert_log WHERE sent=1").fetchone()[0] if _table_exists(conn,"alert_log") else 0,
    }
    s["top_threats"] = [dict(r) for r in conn.execute("""
        SELECT category, COUNT(*) AS c FROM threat_keywords
        GROUP BY category ORDER BY c DESC LIMIT 8
    """).fetchall()]
    s["top_coins"] = [dict(r) for r in conn.execute("""
        SELECT coin, COUNT(DISTINCT address) AS c FROM wallets
        GROUP BY coin ORDER BY c DESC
    """).fetchall()] if _table_exists(conn,"wallets") else []
    conn.close()
    return s

def _table_exists(conn, name):
    return conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (name,)
    ).fetchone() is not None

# ── ROUTES ────────────────────────────────────────────────────────────────────

@app.get("/", response_class=HTMLResponse)
def index(request: Request, q: str="", tech: str="", status: str="", risk: str="", ext_risk: str=""):
    conn = db()
    sql = """
    SELECT s.*,
           (SELECT path FROM screenshots WHERE shop_id=s.id ORDER BY created_at DESC LIMIT 1) AS screenshot
    FROM shops s WHERE 1=1
    """
    params = []
    if q:
        like = f"%{q}%"
        sql += " AND (s.url LIKE ? OR s.domain LIKE ? OR s.title LIKE ?)"
        params += [like,like,like]
    if status:   sql += " AND s.status=?";      params.append(status)
    if risk:     sql += " AND s.risk_level=?";  params.append(risk)
    if ext_risk: sql += " AND s.external_risk=?"; params.append(ext_risk)
    if tech:
        sql += " AND EXISTS (SELECT 1 FROM tech t WHERE t.shop_id=s.id AND t.name=?)"
        params.append(tech)
    sql += " ORDER BY s.risk_score DESC, s.detected_at DESC LIMIT 500"
    shops = conn.execute(sql, params).fetchall()
    techs = conn.execute("SELECT name, COUNT(*) AS c FROM tech GROUP BY name ORDER BY c DESC LIMIT 50").fetchall()
    stats = get_stats_db()
    conn.close()
    return templates.TemplateResponse("index.html", {
        "request":request,"shops":shops,"techs":techs,
        "q":q,"tech":tech,"status":status,"risk":risk,"ext_risk":ext_risk,"stats":stats,
    })


@app.get("/shop/{shop_id}", response_class=HTMLResponse)
def shop_detail(request: Request, shop_id: int):
    conn = db()
    shop = conn.execute("SELECT * FROM shops WHERE id=?", (shop_id,)).fetchone()
    if not shop:
        conn.close(); return HTMLResponse("Not found", status_code=404)
    tech = conn.execute("""
        SELECT category,name,version,confidence,source FROM tech
        WHERE shop_id=? ORDER BY confidence DESC,name
    """, (shop_id,)).fetchall()
    screenshots = conn.execute("""
        SELECT path,created_at,ocr_text FROM screenshots
        WHERE shop_id=? ORDER BY created_at DESC LIMIT 10
    """, (shop_id,)).fetchall()
    keywords = conn.execute("""
        SELECT keyword,category,severity,count FROM threat_keywords
        WHERE shop_id=? ORDER BY
          CASE severity WHEN 'critical' THEN 1 WHEN 'high' THEN 2
                        WHEN 'medium' THEN 3 ELSE 4 END, count DESC
    """, (shop_id,)).fetchall()
    tags   = [r["tag"] for r in conn.execute("SELECT tag FROM tags WHERE shop_id=?", (shop_id,)).fetchall()]
    links  = conn.execute("SELECT url,domain,discovered_at,scanned FROM discovered_links WHERE source_id=? ORDER BY discovered_at DESC LIMIT 100", (shop_id,)).fetchall()
    wallets = conn.execute("SELECT coin,address,addr_type FROM wallets WHERE shop_id=? ORDER BY coin,address", (shop_id,)).fetchall() if _table_exists(conn,"wallets") else []
    ti = conn.execute("SELECT * FROM threat_intel WHERE shop_id=?", (shop_id,)).fetchone() if _table_exists(conn,"threat_intel") else None
    alerts = conn.execute("SELECT channel,risk_level,sent,reason,sent_at FROM alert_log WHERE shop_id=? ORDER BY sent_at DESC LIMIT 10", (shop_id,)).fetchall() if _table_exists(conn,"alert_log") else []
    conn.close()
    return templates.TemplateResponse("shop.html", {
        "request":request,"shop":shop,"tech":tech,"screenshots":screenshots,
        "keywords":keywords,"tags":tags,"links":links,"wallets":wallets,
        "threat_intel":dict(ti) if ti else {},"alerts":alerts,
    })


@app.get("/wallets", response_class=HTMLResponse)
def wallets_view(request: Request, coin: str="", q: str=""):
    conn = db()
    sql = """
        SELECT w.coin, w.address, w.addr_type,
               s.id AS shop_id, s.domain, s.title, s.risk_level
        FROM wallets w JOIN shops s ON w.shop_id=s.id
        WHERE 1=1
    """
    params = []
    if coin: sql += " AND w.coin=?"; params.append(coin.upper())
    if q:
        like = f"%{q}%"
        sql += " AND (w.address LIKE ? OR s.domain LIKE ?)"
        params += [like,like]
    sql += " ORDER BY s.risk_score DESC LIMIT 500"
    rows   = conn.execute(sql, params).fetchall()
    coins  = [dict(r) for r in conn.execute("SELECT coin, COUNT(*) AS c FROM wallets GROUP BY coin ORDER BY c DESC").fetchall()]
    stats  = get_stats_db()
    conn.close()
    return templates.TemplateResponse("wallets.html", {
        "request":request,"rows":rows,"coins":coins,
        "selected_coin":coin,"q":q,"stats":stats,
    })


@app.get("/discovered", response_class=HTMLResponse)
def discovered(request: Request, scanned: str=""):
    conn = db()
    sql = "SELECT * FROM discovered_links WHERE 1=1"
    params = []
    if scanned == "0": sql += " AND scanned=0"
    elif scanned == "1": sql += " AND scanned=1"
    sql += " ORDER BY discovered_at DESC LIMIT 500"
    links = conn.execute(sql, params).fetchall()
    stats = get_stats_db()
    conn.close()
    return templates.TemplateResponse("discovered.html", {
        "request":request,"links":links,"scanned":scanned,"stats":stats,
    })


@app.get("/api/stats")
def api_stats(): return JSONResponse(get_stats_db())

@app.get("/api/export")
def api_export():
    conn = db()
    shops = [dict(r) for r in conn.execute("SELECT * FROM shops ORDER BY risk_score DESC").fetchall()]
    for s in shops:
        sid = s["id"]
        s["tech"]     = [dict(r) for r in conn.execute("SELECT name,category,version,confidence FROM tech WHERE shop_id=?", (sid,)).fetchall()]
        s["keywords"] = [dict(r) for r in conn.execute("SELECT keyword,category,severity,count FROM threat_keywords WHERE shop_id=?", (sid,)).fetchall()]
        s["tags"]     = [r["tag"] for r in conn.execute("SELECT tag FROM tags WHERE shop_id=?", (sid,)).fetchall()]
        s["wallets"]  = [dict(r) for r in conn.execute("SELECT coin,address,addr_type FROM wallets WHERE shop_id=?", (sid,)).fetchall()] if _table_exists(conn,"wallets") else []
    conn.close()
    return JSONResponse({"count":len(shops),"sites":shops})

@app.get("/api/wallets")
def api_wallets(coin: str=""):
    conn = db()
    sql = "SELECT coin,address,addr_type,shop_id FROM wallets WHERE 1=1"
    params = []
    if coin: sql += " AND coin=?"; params.append(coin.upper())
    rows = [dict(r) for r in conn.execute(sql, params).fetchall()]
    conn.close()
    return JSONResponse(rows)

@app.get("/api/threats/top")
def api_threats_top():
    conn = db()
    rows = [dict(r) for r in conn.execute("""
        SELECT category,severity,keyword,SUM(count) AS total
        FROM threat_keywords GROUP BY keyword
        ORDER BY total DESC LIMIT 50
    """).fetchall()]
    conn.close()
    return JSONResponse(rows)
