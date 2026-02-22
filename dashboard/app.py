from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
import sqlite3
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
ROOT = BASE_DIR.parent
DB_PATH = (ROOT / "data" / "scrs.db").resolve()

app = FastAPI()
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))

# static contiene /screenshots/*
app.mount("/static", StaticFiles(directory=str(BASE_DIR / "static")), name="static")

def db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

@app.get("/", response_class=HTMLResponse)
def index(request: Request, q: str = "", tech: str = "", status: str = ""):
    conn = db()

    sql = """
    SELECT s.*,
           (SELECT path FROM screenshots WHERE shop_id = s.id ORDER BY created_at DESC LIMIT 1) AS screenshot
    FROM shops s
    WHERE 1=1
    """
    params = []

    if q:
        like = f"%{q}%"
        sql += " AND (s.url LIKE ? OR s.domain LIKE ? OR s.title LIKE ?)"
        params += [like, like, like]

    if status:
        sql += " AND s.status = ?"
        params.append(status)

    if tech:
        sql += """
        AND EXISTS (
            SELECT 1 FROM tech t
            WHERE t.shop_id = s.id AND t.name = ?
        )
        """
        params.append(tech)

    sql += " ORDER BY s.detected_at DESC LIMIT 500"
    shops = conn.execute(sql, params).fetchall()

    techs = conn.execute("""
        SELECT name, COUNT(*) AS c
        FROM tech
        GROUP BY name
        ORDER BY c DESC
        LIMIT 50
    """).fetchall()

    conn.close()

    return templates.TemplateResponse("index.html", {
        "request": request,
        "shops": shops,
        "techs": techs,
        "q": q,
        "tech": tech,
        "status": status
    })

@app.get("/shop/{shop_id}", response_class=HTMLResponse)
def shop_detail(request: Request, shop_id: int):
    conn = db()
    shop = conn.execute("SELECT * FROM shops WHERE id = ?", (shop_id,)).fetchone()
    if not shop:
        conn.close()
        return HTMLResponse("Not found", status_code=404)

    tech = conn.execute("""
        SELECT category, name, version, confidence, source
        FROM tech WHERE shop_id = ?
        ORDER BY category, confidence DESC, name
    """, (shop_id,)).fetchall()

    screenshots = conn.execute("""
        SELECT path, created_at
        FROM screenshots WHERE shop_id = ?
        ORDER BY created_at DESC
        LIMIT 10
    """, (shop_id,)).fetchall()

    conn.close()

    return templates.TemplateResponse("shop.html", {
        "request": request,
        "shop": shop,
        "tech": tech,
        "screenshots": screenshots
    })
