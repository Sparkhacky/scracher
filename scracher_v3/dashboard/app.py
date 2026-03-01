"""
SCRACHER v3 — Dashboard completo
Toda la funcionalidad operativa accesible desde el browser.
Escaneo en tiempo real via SSE, gestión DB, exportación, estadísticas.
"""

import json
import sqlite3
import asyncio
import threading
import queue
import os
import sys
from pathlib import Path
from datetime import datetime, timezone
from typing import AsyncGenerator

from fastapi import FastAPI, Request, Form, BackgroundTasks
from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

# Añadir raíz del proyecto al path para importar collector.*
ROOT     = Path(__file__).resolve().parents[1]
BASE_DIR = Path(__file__).resolve().parent
DB_PATH  = ROOT / "data" / "scrs.db"
sys.path.insert(0, str(ROOT))

app       = FastAPI(title="SCRACHER v3")
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))

_static = BASE_DIR / "static"
_static.mkdir(parents=True, exist_ok=True)
(_static / "screenshots").mkdir(exist_ok=True)
app.mount("/static", StaticFiles(directory=str(_static)), name="static")

# Cola global para SSE del escaneo
_scan_queue: queue.Queue = queue.Queue()
_scan_running = False

# ─────────────────────────────────────────────────────────────────────────────
#  DB HELPERS
# ─────────────────────────────────────────────────────────────────────────────

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys=ON")
    return conn

def table_exists(conn, name: str) -> bool:
    return conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (name,)
    ).fetchone() is not None

def get_stats():
    conn = get_db()
    s = {
        "total":         conn.execute("SELECT COUNT(*) FROM shops").fetchone()[0],
        "ok":            conn.execute("SELECT COUNT(*) FROM shops WHERE status='ok'").fetchone()[0],
        "errors":        conn.execute("SELECT COUNT(*) FROM shops WHERE status='error'").fetchone()[0],
        "critical":      conn.execute("SELECT COUNT(*) FROM shops WHERE risk_level='critical'").fetchone()[0],
        "high":          conn.execute("SELECT COUNT(*) FROM shops WHERE risk_level='high'").fetchone()[0],
        "medium":        conn.execute("SELECT COUNT(*) FROM shops WHERE risk_level='medium'").fetchone()[0],
        "low":           conn.execute("SELECT COUNT(*) FROM shops WHERE risk_level='low'").fetchone()[0],
        "clean":         conn.execute("SELECT COUNT(*) FROM shops WHERE risk_level='clean'").fetchone()[0],
        "pending_links": conn.execute("SELECT COUNT(*) FROM discovered_links WHERE scanned=0").fetchone()[0],
        "total_links":   conn.execute("SELECT COUNT(*) FROM discovered_links").fetchone()[0],
        "wallets_total": conn.execute("SELECT COUNT(*) FROM wallets").fetchone()[0] if table_exists(conn,"wallets") else 0,
        "alerts_sent":   conn.execute("SELECT COUNT(*) FROM alert_log WHERE sent=1").fetchone()[0] if table_exists(conn,"alert_log") else 0,
    }
    s["top_threats"] = [dict(r) for r in conn.execute("""
        SELECT category, COUNT(*) AS c FROM threat_keywords
        GROUP BY category ORDER BY c DESC LIMIT 8
    """).fetchall()]
    s["top_coins"] = [dict(r) for r in conn.execute("""
        SELECT coin, COUNT(DISTINCT address) AS c FROM wallets
        GROUP BY coin ORDER BY c DESC
    """).fetchall()] if table_exists(conn,"wallets") else []
    conn.close()
    return s

# ─────────────────────────────────────────────────────────────────────────────
#  INDEX
# ─────────────────────────────────────────────────────────────────────────────

@app.get("/", response_class=HTMLResponse)
def index(request: Request, q: str="", tech: str="", risk: str="", ext_risk: str=""):
    conn = get_db()
    sql = """
        SELECT s.*,
               (SELECT path FROM screenshots WHERE shop_id=s.id
                ORDER BY created_at DESC LIMIT 1) AS screenshot
        FROM shops s WHERE 1=1
    """
    params = []
    if q:
        like = f"%{q}%"
        sql += " AND (s.url LIKE ? OR s.domain LIKE ? OR s.title LIKE ?)"
        params += [like, like, like]
    if risk:     sql += " AND s.risk_level=?";   params.append(risk)
    if ext_risk: sql += " AND s.external_risk=?"; params.append(ext_risk)
    if tech:
        sql += " AND EXISTS (SELECT 1 FROM tech t WHERE t.shop_id=s.id AND t.name=?)"
        params.append(tech)
    sql += " ORDER BY s.risk_score DESC, s.detected_at DESC LIMIT 500"
    shops = conn.execute(sql, params).fetchall()
    techs = conn.execute("SELECT name, COUNT(*) AS c FROM tech GROUP BY name ORDER BY c DESC LIMIT 60").fetchall()
    stats = get_stats()
    conn.close()
    return templates.TemplateResponse("index.html", {
        "request": request, "shops": shops, "techs": techs,
        "q": q, "tech": tech, "risk": risk, "ext_risk": ext_risk, "stats": stats,
    })

# ─────────────────────────────────────────────────────────────────────────────
#  SHOP DETAIL
# ─────────────────────────────────────────────────────────────────────────────

@app.get("/shop/{shop_id}", response_class=HTMLResponse)
def shop_detail(request: Request, shop_id: int):
    conn = get_db()
    shop = conn.execute("SELECT * FROM shops WHERE id=?", (shop_id,)).fetchone()
    if not shop:
        conn.close()
        return HTMLResponse("Not found", status_code=404)
    tech        = conn.execute("""
        SELECT category, name, version, confidence, source FROM tech
        WHERE shop_id=? ORDER BY confidence DESC, name
    """, (shop_id,)).fetchall()
    screenshots = conn.execute("""
        SELECT path, created_at, ocr_text FROM screenshots
        WHERE shop_id=? ORDER BY created_at DESC LIMIT 10
    """, (shop_id,)).fetchall()
    keywords    = conn.execute("""
        SELECT keyword, category, severity, count FROM threat_keywords
        WHERE shop_id=? ORDER BY
          CASE severity WHEN 'critical' THEN 1 WHEN 'high' THEN 2
          WHEN 'medium' THEN 3 ELSE 4 END, count DESC
    """, (shop_id,)).fetchall()
    tags        = [r["tag"] for r in conn.execute(
        "SELECT tag FROM tags WHERE shop_id=?", (shop_id,)).fetchall()]
    links       = conn.execute("""
        SELECT url, domain, discovered_at, scanned FROM discovered_links
        WHERE source_id=? ORDER BY discovered_at DESC LIMIT 100
    """, (shop_id,)).fetchall()
    wallets     = conn.execute("""
        SELECT coin, address, addr_type FROM wallets
        WHERE shop_id=? ORDER BY coin, address
    """, (shop_id,)).fetchall() if table_exists(conn,"wallets") else []
    ti          = conn.execute(
        "SELECT * FROM threat_intel WHERE shop_id=?", (shop_id,)
    ).fetchone() if table_exists(conn,"threat_intel") else None
    alerts      = conn.execute("""
        SELECT channel, risk_level, sent, reason, sent_at FROM alert_log
        WHERE shop_id=? ORDER BY sent_at DESC LIMIT 10
    """, (shop_id,)).fetchall() if table_exists(conn,"alert_log") else []
    conn.close()
    return templates.TemplateResponse("shop.html", {
        "request": request, "shop": shop, "tech": tech,
        "screenshots": screenshots, "keywords": keywords, "tags": tags,
        "links": links, "wallets": wallets,
        "threat_intel": dict(ti) if ti else {}, "alerts": alerts,
    })

@app.post("/shop/{shop_id}/delete")
def delete_shop(shop_id: int):
    from collector.db import delete_shop_by_id
    delete_shop_by_id(shop_id)
    return JSONResponse({"ok": True})

# ─────────────────────────────────────────────────────────────────────────────
#  SCAN — página + SSE stream
# ─────────────────────────────────────────────────────────────────────────────

@app.get("/scan", response_class=HTMLResponse)
def scan_page(request: Request):
    stats = get_stats()
    return templates.TemplateResponse("scan.html", {"request": request, "stats": stats})

def _run_scan_thread(urls: list, use_ti: bool):
    """Escaneo en hilo separado, emite eventos a _scan_queue."""
    global _scan_running
    _scan_running = True

    def emit(event: str, data: dict):
        _scan_queue.put({"event": event, "data": data})

    try:
        from collector.db import (
            init_db, upsert_shop, replace_tech, add_screenshot,
            replace_keywords, replace_tags, replace_wallets,
            add_discovered_links, upsert_threat_intel, log_alert,
        )
        from collector.scrape import scrape_one
        from collector.alerts import dispatch_alerts
        from collector.scheduler import schedule_rescan
        import time

        init_db()
        emit("start", {"total": len(urls), "threat_intel": use_ti})

        ok = fail = new_links = new_wallets = 0
        t_all = time.perf_counter()

        for i, url in enumerate(urls, 1):
            emit("progress", {"i": i, "total": len(urls), "url": url})
            t0 = time.perf_counter()
            try:
                data    = scrape_one(url, run_threat_intel=use_ti)
                elapsed = time.perf_counter() - t0
                threat  = data.get("threat", {})
                ti      = data.get("threat_intel", {})
                rl      = threat.get("risk_level", "unknown")
                ext     = ti.get("external_risk", "unknown")

                sid = upsert_shop(
                    url=data["url"], domain=data.get("domain"),
                    title=data.get("title"), status="ok",
                    risk_score=threat.get("risk_score", 0), risk_level=rl,
                    external_risk=ext, content_hash=data.get("content_hash"),
                    language=data.get("language"),
                )
                replace_tech(sid, data.get("tech", []))
                replace_keywords(sid, threat.get("keywords", []))
                replace_tags(sid, threat.get("tags", []))
                wallets = data.get("wallets", {})
                replace_wallets(sid, wallets)
                if use_ti and ti:
                    upsert_threat_intel(sid, ti)
                sc = data.get("screenshot") or {}
                if sc.get("path"):
                    add_screenshot(sid, sc["path"], sc.get("width"), sc.get("height"),
                                   data.get("ocr", {}).get("text"))
                onion_links = data.get("onion_links", [])
                if onion_links:
                    add_discovered_links(sid, onion_links)
                    new_links += len(onion_links)
                wcount = sum(len(v) for v in wallets.values())
                new_wallets += wcount

                alert_results = dispatch_alerts({
                    "shop_id": sid, "url": data["url"],
                    "domain": data.get("domain"), "title": data.get("title"),
                    "risk_level": rl, "risk_score": threat.get("risk_score", 0),
                    "tags": threat.get("tags", []),
                    "keywords": threat.get("keywords", []),
                    "external_risk": ext,
                })
                for ar in alert_results:
                    log_alert(sid, ar.get("channel","?"), rl,
                              ar.get("sent", False), ar.get("reason"))
                schedule_rescan(sid, data["url"], rl)
                ok += 1

                emit("result", {
                    "i": i, "total": len(urls),
                    "url": data["url"], "domain": data.get("domain",""),
                    "title": data.get("title",""),
                    "risk_level": rl, "risk_score": threat.get("risk_score", 0),
                    "external_risk": ext,
                    "keywords": len(threat.get("keywords", [])),
                    "tech": len(data.get("tech", [])),
                    "links": len(onion_links),
                    "wallets": wcount,
                    "elapsed": round(elapsed, 1),
                    "shop_id": sid,
                    "status": "ok",
                })
            except Exception as e:
                elapsed = time.perf_counter() - t0
                fail += 1
                try:
                    upsert_shop(url=url, domain=None, title=None,
                                status="error", notes=str(e))
                except Exception:
                    pass
                emit("result", {
                    "i": i, "total": len(urls),
                    "url": url, "status": "error",
                    "error": str(e)[:120], "elapsed": round(elapsed, 1),
                })

        emit("done", {
            "ok": ok, "fail": fail,
            "links": new_links, "wallets": new_wallets,
            "elapsed": round(time.perf_counter() - t_all, 1),
        })
    except Exception as e:
        emit("error", {"message": str(e)})
    finally:
        _scan_running = False

@app.post("/scan/start")
async def scan_start(request: Request):
    global _scan_running
    if _scan_running:
        return JSONResponse({"error": "Scan already running"}, status_code=409)
    body    = await request.json()
    raw     = body.get("urls", "")
    use_ti  = body.get("threat_intel", False)
    urls    = []
    seen    = set()
    for line in raw.strip().split("\n"):
        u = line.strip()
        if not u or u.startswith("#"): continue
        if not u.startswith("http"): u = "http://" + u
        if u not in seen:
            urls.append(u); seen.add(u)
    if not urls:
        return JSONResponse({"error": "No valid URLs"}, status_code=400)
    t = threading.Thread(target=_run_scan_thread, args=(urls, use_ti), daemon=True)
    t.start()
    return JSONResponse({"ok": True, "count": len(urls)})

@app.get("/scan/stream")
async def scan_stream():
    async def generator() -> AsyncGenerator[str, None]:
        loop = asyncio.get_event_loop()
        while True:
            try:
                msg = await loop.run_in_executor(None, _scan_queue.get, True, 0.3)
                yield f"event: {msg['event']}\ndata: {json.dumps(msg['data'])}\n\n"
                if msg["event"] == "done" or msg["event"] == "error":
                    break
            except queue.Empty:
                yield ": ping\n\n"
                if not _scan_running and _scan_queue.empty():
                    break
    return StreamingResponse(generator(), media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})

@app.get("/api/scan/status")
def scan_status():
    return JSONResponse({"running": _scan_running})

# ─────────────────────────────────────────────────────────────────────────────
#  CRAWL DISCOVERED
# ─────────────────────────────────────────────────────────────────────────────

@app.post("/scan/crawl")
async def crawl_discovered(request: Request):
    global _scan_running
    if _scan_running:
        return JSONResponse({"error": "Scan already running"}, status_code=409)
    body  = await request.json()
    limit = int(body.get("limit", 50))
    from collector.db import get_pending_discovered, mark_discovered_scanned
    pending = get_pending_discovered(limit=limit)
    if not pending:
        return JSONResponse({"error": "No pending links"}, status_code=400)
    urls = [r["url"] for r in pending]
    ids  = [r["id"]  for r in pending]

    def run():
        _run_scan_thread(urls, False)
        for lid in ids:
            mark_discovered_scanned(lid)

    t = threading.Thread(target=run, daemon=True)
    t.start()
    return JSONResponse({"ok": True, "count": len(urls)})

# ─────────────────────────────────────────────────────────────────────────────
#  WALLETS
# ─────────────────────────────────────────────────────────────────────────────

@app.get("/wallets", response_class=HTMLResponse)
def wallets_view(request: Request, coin: str="", q: str=""):
    conn = get_db()
    sql = """
        SELECT w.coin, w.address, w.addr_type,
               s.id AS shop_id, s.domain, s.title, s.risk_level
        FROM wallets w JOIN shops s ON w.shop_id=s.id WHERE 1=1
    """
    params = []
    if coin: sql += " AND w.coin=?"; params.append(coin.upper())
    if q:
        like = f"%{q}%"
        sql += " AND (w.address LIKE ? OR s.domain LIKE ?)"
        params += [like, like]
    sql += " ORDER BY s.risk_score DESC LIMIT 500"
    rows  = conn.execute(sql, params).fetchall()
    coins = [dict(r) for r in conn.execute(
        "SELECT coin, COUNT(*) AS c FROM wallets GROUP BY coin ORDER BY c DESC"
    ).fetchall()]
    stats = get_stats()
    conn.close()
    return templates.TemplateResponse("wallets.html", {
        "request": request, "rows": rows, "coins": coins,
        "selected_coin": coin, "q": q, "stats": stats,
    })

# ─────────────────────────────────────────────────────────────────────────────
#  DISCOVERED LINKS
# ─────────────────────────────────────────────────────────────────────────────

@app.get("/discovered", response_class=HTMLResponse)
def discovered(request: Request, scanned: str=""):
    conn = get_db()
    sql = "SELECT * FROM discovered_links WHERE 1=1"
    if scanned == "0": sql += " AND scanned=0"
    elif scanned == "1": sql += " AND scanned=1"
    sql += " ORDER BY discovered_at DESC LIMIT 500"
    links = conn.execute(sql).fetchall()
    stats = get_stats()
    conn.close()
    return templates.TemplateResponse("discovered.html", {
        "request": request, "links": links, "scanned": scanned, "stats": stats,
    })

# ─────────────────────────────────────────────────────────────────────────────
#  MANAGE DB
# ─────────────────────────────────────────────────────────────────────────────

@app.get("/manage", response_class=HTMLResponse)
def manage_page(request: Request, q: str="", risk: str=""):
    conn = get_db()
    sql = "SELECT id,url,domain,title,risk_level,risk_score,status,detected_at,scan_count FROM shops WHERE 1=1"
    params = []
    if q:
        like = f"%{q}%"
        sql += " AND (url LIKE ? OR domain LIKE ? OR title LIKE ?)"
        params += [like, like, like]
    if risk: sql += " AND risk_level=?"; params.append(risk)
    sql += " ORDER BY detected_at DESC LIMIT 200"
    shops = conn.execute(sql, params).fetchall()
    stats = get_stats()
    conn.close()
    return templates.TemplateResponse("manage.html", {
        "request": request, "shops": shops, "q": q, "risk": risk, "stats": stats,
    })

@app.post("/api/delete")
async def api_delete(request: Request):
    body = await request.json()
    ids  = body.get("ids", [])
    if not ids:
        return JSONResponse({"error": "No IDs"}, status_code=400)
    from collector.db import delete_shop_by_id
    deleted = sum(1 for sid in ids if delete_shop_by_id(int(sid)))
    return JSONResponse({"ok": True, "deleted": deleted})

@app.post("/api/delete/errors")
def api_delete_errors():
    conn = get_db()
    conn.execute("DELETE FROM shops WHERE status='error'")
    conn.commit()
    conn.close()
    return JSONResponse({"ok": True})

# ─────────────────────────────────────────────────────────────────────────────
#  EXPORT
# ─────────────────────────────────────────────────────────────────────────────

@app.get("/export", response_class=HTMLResponse)
def export_page(request: Request):
    stats = get_stats()
    export_dir = ROOT / "data" / "exports"
    files = []
    if export_dir.exists():
        files = sorted(export_dir.glob("*"), key=lambda f: f.stat().st_mtime, reverse=True)
        files = [{"name": f.name, "size": f.stat().st_size, "path": str(f)} for f in files[:20]]
    return templates.TemplateResponse("export.html", {
        "request": request, "stats": stats, "files": files,
    })

@app.post("/api/export/{fmt}")
def api_export_fmt(fmt: str):
    if fmt not in ("json","csv","html","all"):
        return JSONResponse({"error": "Invalid format"}, status_code=400)
    from collector.db import export_all_json
    from collector.exporter import export_json, export_csv, export_html_report
    shops = export_all_json()
    stats = get_stats()
    paths = []
    if fmt in ("json","all"): paths.append(export_json(shops))
    if fmt in ("csv","all"):  paths.append(export_csv(shops))
    if fmt in ("html","all"): paths.append(export_html_report(shops, stats))
    return JSONResponse({"ok": True, "files": paths})

@app.get("/api/export/download/{filename}")
def download_export(filename: str):
    p = ROOT / "data" / "exports" / filename
    if not p.exists() or not p.is_file():
        return JSONResponse({"error": "Not found"}, status_code=404)
    return FileResponse(str(p), filename=filename)

# ─────────────────────────────────────────────────────────────────────────────
#  API
# ─────────────────────────────────────────────────────────────────────────────

@app.get("/api/stats")
def api_stats(): return JSONResponse(get_stats())

@app.get("/api/export")
def api_export_json():
    from collector.db import export_all_json
    shops = export_all_json()
    return JSONResponse({"count": len(shops), "sites": shops})

@app.get("/api/wallets")
def api_wallets(coin: str=""):
    conn = get_db()
    sql = "SELECT coin,address,addr_type,shop_id FROM wallets WHERE 1=1"
    params = []
    if coin: sql += " AND coin=?"; params.append(coin.upper())
    rows = [dict(r) for r in conn.execute(sql, params).fetchall()]
    conn.close()
    return JSONResponse(rows)

@app.get("/api/threats/top")
def api_threats():
    conn = get_db()
    rows = [dict(r) for r in conn.execute("""
        SELECT category,severity,keyword,SUM(count) AS total
        FROM threat_keywords GROUP BY keyword
        ORDER BY total DESC LIMIT 50
    """).fetchall()]
    conn.close()
    return JSONResponse(rows)
