import sqlite3
from pathlib import Path
from datetime import datetime, timezone

ROOT = Path(__file__).resolve().parents[1]
DB_PATH = ROOT / "data" / "scrs.db"

def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")

def connect():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = connect()
    conn.executescript("""
    CREATE TABLE IF NOT EXISTS shops (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      url TEXT UNIQUE NOT NULL,
      domain TEXT,
      title TEXT,
      detected_at TEXT,
      status TEXT,
      notes TEXT
    );

    CREATE TABLE IF NOT EXISTS tech (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      shop_id INTEGER NOT NULL,
      name TEXT NOT NULL,
      category TEXT,
      version TEXT,
      confidence REAL,
      source TEXT,
      FOREIGN KEY(shop_id) REFERENCES shops(id)
    );

    CREATE TABLE IF NOT EXISTS screenshots (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      shop_id INTEGER NOT NULL,
      path TEXT NOT NULL,
      width INTEGER,
      height INTEGER,
      created_at TEXT,
      FOREIGN KEY(shop_id) REFERENCES shops(id)
    );

    CREATE INDEX IF NOT EXISTS idx_tech_shop ON tech(shop_id);
    CREATE INDEX IF NOT EXISTS idx_shops_domain ON shops(domain);
    """)
    conn.commit()
    conn.close()

def upsert_shop(url: str, domain: str | None, title: str | None, status: str, notes: str | None = None) -> int:
    conn = connect()
    now = utc_now_iso()
    conn.execute("""
        INSERT INTO shops(url, domain, title, detected_at, status, notes)
        VALUES (?, ?, ?, ?, ?, ?)
        ON CONFLICT(url) DO UPDATE SET
          domain=excluded.domain,
          title=excluded.title,
          detected_at=excluded.detected_at,
          status=excluded.status,
          notes=excluded.notes
    """, (url, domain, title, now, status, notes))
    conn.commit()
    row = conn.execute("SELECT id FROM shops WHERE url = ?", (url,)).fetchone()
    conn.close()
    return int(row["id"])

def replace_tech(shop_id: int, tech_items: list[dict]):
    conn = connect()
    conn.execute("DELETE FROM tech WHERE shop_id = ?", (shop_id,))
    conn.executemany("""
        INSERT INTO tech(shop_id, name, category, version, confidence, source)
        VALUES (?, ?, ?, ?, ?, ?)
    """, [
        (
            shop_id,
            t.get("name"),
            t.get("category"),
            t.get("version"),
            float(t.get("confidence", 0.0)) if t.get("confidence") is not None else None,
            t.get("source"),
        )
        for t in tech_items
    ])
    conn.commit()
    conn.close()

def add_screenshot(shop_id: int, rel_path: str, width: int | None, height: int | None):
    conn = connect()
    now = utc_now_iso()
    conn.execute("""
        INSERT INTO screenshots(shop_id, path, width, height, created_at)
        VALUES (?, ?, ?, ?, ?)
    """, (shop_id, rel_path, width, height, now))
    conn.commit()
    conn.close()

def list_shops(limit: int = 50, q: str = "") -> list[sqlite3.Row]:
    conn = connect()
    sql = """
      SELECT id, url, domain, title, detected_at, status
      FROM shops
      WHERE 1=1
    """
    params = []
    if q:
        like = f"%{q}%"
        sql += " AND (url LIKE ? OR domain LIKE ? OR title LIKE ?)"
        params += [like, like, like]
    sql += " ORDER BY detected_at DESC LIMIT ?"
    params.append(limit)
    rows = conn.execute(sql, params).fetchall()
    conn.close()
    return rows

def delete_shop_by_id(shop_id: int) -> int:
    """
    Borra una tienda y todo lo asociado (tech + screenshots).
    Devuelve cuántas filas de 'shops' fueron borradas (0 o 1).
    """
    conn = connect()
    # por si foreign keys no están activas en sqlite:
    conn.execute("DELETE FROM tech WHERE shop_id = ?", (shop_id,))
    conn.execute("DELETE FROM screenshots WHERE shop_id = ?", (shop_id,))
    cur = conn.execute("DELETE FROM shops WHERE id = ?", (shop_id,))
    conn.commit()
    conn.close()
    return cur.rowcount

def delete_shop_by_url(url: str) -> int:
    conn = connect()
    row = conn.execute("SELECT id FROM shops WHERE url = ?", (url,)).fetchone()
    conn.close()
    if not row:
        return 0
    return delete_shop_by_id(int(row["id"]))
