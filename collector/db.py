"""
SCRACHER v3 — Database layer
Schema v3: añade wallets, threat_intel, alert_log, rescan_log.
"""

import sqlite3
from pathlib import Path
from datetime import datetime, timezone

ROOT    = Path(__file__).resolve().parents[1]
DB_PATH = ROOT / "data" / "scrs.db"

def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")

def connect() -> sqlite3.Connection:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn

def init_db():
    conn = connect()
    conn.executescript("""
    CREATE TABLE IF NOT EXISTS shops (
      id            INTEGER PRIMARY KEY AUTOINCREMENT,
      url           TEXT UNIQUE NOT NULL,
      domain        TEXT,
      title         TEXT,
      detected_at   TEXT,
      last_scanned  TEXT,
      scan_count    INTEGER DEFAULT 1,
      status        TEXT,
      risk_score    REAL DEFAULT 0,
      risk_level    TEXT DEFAULT 'unknown',
      external_risk TEXT DEFAULT 'unknown',
      content_hash  TEXT,
      notes         TEXT,
      language      TEXT
    );

    CREATE TABLE IF NOT EXISTS tech (
      id         INTEGER PRIMARY KEY AUTOINCREMENT,
      shop_id    INTEGER NOT NULL,
      name       TEXT NOT NULL,
      category   TEXT,
      version    TEXT,
      confidence REAL,
      source     TEXT,
      FOREIGN KEY(shop_id) REFERENCES shops(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS screenshots (
      id         INTEGER PRIMARY KEY AUTOINCREMENT,
      shop_id    INTEGER NOT NULL,
      path       TEXT NOT NULL,
      width      INTEGER,
      height     INTEGER,
      ocr_text   TEXT,
      created_at TEXT,
      FOREIGN KEY(shop_id) REFERENCES shops(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS threat_keywords (
      id       INTEGER PRIMARY KEY AUTOINCREMENT,
      shop_id  INTEGER NOT NULL,
      keyword  TEXT NOT NULL,
      category TEXT NOT NULL,
      severity TEXT NOT NULL,
      count    INTEGER DEFAULT 1,
      FOREIGN KEY(shop_id) REFERENCES shops(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS tags (
      id      INTEGER PRIMARY KEY AUTOINCREMENT,
      shop_id INTEGER NOT NULL,
      tag     TEXT NOT NULL,
      FOREIGN KEY(shop_id) REFERENCES shops(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS wallets (
      id         INTEGER PRIMARY KEY AUTOINCREMENT,
      shop_id    INTEGER NOT NULL,
      coin       TEXT NOT NULL,
      address    TEXT NOT NULL,
      addr_type  TEXT,
      FOREIGN KEY(shop_id) REFERENCES shops(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS threat_intel (
      id            INTEGER PRIMARY KEY AUTOINCREMENT,
      shop_id       INTEGER NOT NULL UNIQUE,
      vt_malicious  INTEGER DEFAULT 0,
      vt_suspicious INTEGER DEFAULT 0,
      vt_harmless   INTEGER DEFAULT 0,
      vt_engines    TEXT,
      uh_found      INTEGER DEFAULT 0,
      uh_status     TEXT,
      uh_threat     TEXT,
      uh_tags       TEXT,
      external_risk TEXT DEFAULT 'unknown',
      checked_at    TEXT,
      FOREIGN KEY(shop_id) REFERENCES shops(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS alert_log (
      id         INTEGER PRIMARY KEY AUTOINCREMENT,
      shop_id    INTEGER,
      channel    TEXT,
      risk_level TEXT,
      sent       INTEGER DEFAULT 0,
      reason     TEXT,
      sent_at    TEXT
    );

    CREATE TABLE IF NOT EXISTS discovered_links (
      id            INTEGER PRIMARY KEY AUTOINCREMENT,
      source_id     INTEGER,
      url           TEXT UNIQUE NOT NULL,
      domain        TEXT,
      discovered_at TEXT,
      scanned       INTEGER DEFAULT 0,
      FOREIGN KEY(source_id) REFERENCES shops(id) ON DELETE SET NULL
    );

    CREATE TABLE IF NOT EXISTS rescan_log (
      id      INTEGER PRIMARY KEY AUTOINCREMENT,
      shop_id INTEGER,
      url     TEXT,
      status  TEXT,
      detail  TEXT,
      ran_at  TEXT
    );

    CREATE INDEX IF NOT EXISTS idx_tech_shop        ON tech(shop_id);
    CREATE INDEX IF NOT EXISTS idx_shops_domain     ON shops(domain);
    CREATE INDEX IF NOT EXISTS idx_shops_risk       ON shops(risk_score);
    CREATE INDEX IF NOT EXISTS idx_shops_risk_level ON shops(risk_level);
    CREATE INDEX IF NOT EXISTS idx_kwds_shop        ON threat_keywords(shop_id);
    CREATE INDEX IF NOT EXISTS idx_tags_shop        ON tags(shop_id);
    CREATE INDEX IF NOT EXISTS idx_wallets_shop     ON wallets(shop_id);
    CREATE INDEX IF NOT EXISTS idx_wallets_coin     ON wallets(coin);
    CREATE INDEX IF NOT EXISTS idx_disc_scanned     ON discovered_links(scanned);
    """)

    # Migración: añadir columnas v3 si la DB viene de v2
    migrations = [
        "ALTER TABLE shops ADD COLUMN external_risk TEXT DEFAULT 'unknown'",
        "ALTER TABLE screenshots ADD COLUMN ocr_text TEXT",
    ]
    for sql in migrations:
        try:
            conn.execute(sql)
        except Exception:
            pass

    conn.commit()
    conn.close()

# ─────────────────────────────────────────────────────────────────────────────
#  SHOPS
# ─────────────────────────────────────────────────────────────────────────────

def upsert_shop(url, domain, title, status, risk_score=0.0, risk_level="unknown",
                external_risk="unknown", content_hash=None, language=None, notes=None):
    conn = connect()
    now = utc_now_iso()
    conn.execute("""
        INSERT INTO shops(url,domain,title,detected_at,last_scanned,scan_count,
                          status,risk_score,risk_level,external_risk,content_hash,language,notes)
        VALUES (?,?,?,?,?,1,?,?,?,?,?,?,?)
        ON CONFLICT(url) DO UPDATE SET
          domain=excluded.domain, title=excluded.title,
          last_scanned=excluded.last_scanned, scan_count=shops.scan_count+1,
          status=excluded.status, risk_score=excluded.risk_score,
          risk_level=excluded.risk_level, external_risk=excluded.external_risk,
          content_hash=excluded.content_hash, language=excluded.language,
          notes=excluded.notes
    """, (url,domain,title,now,now,status,risk_score,risk_level,external_risk,
          content_hash,language,notes))
    conn.commit()
    row = conn.execute("SELECT id FROM shops WHERE url=?", (url,)).fetchone()
    conn.close()
    return int(row["id"])

def replace_tech(shop_id, tech_items):
    conn = connect()
    conn.execute("DELETE FROM tech WHERE shop_id=?", (shop_id,))
    conn.executemany("""
        INSERT INTO tech(shop_id,name,category,version,confidence,source)
        VALUES (?,?,?,?,?,?)
    """, [(shop_id,t.get("name"),t.get("category"),t.get("version"),
           float(t.get("confidence",0.0) or 0.0),t.get("source")) for t in tech_items])
    conn.commit(); conn.close()

def add_screenshot(shop_id, rel_path, width, height, ocr_text=None):
    conn = connect()
    conn.execute("""
        INSERT INTO screenshots(shop_id,path,width,height,ocr_text,created_at)
        VALUES (?,?,?,?,?,?)
    """, (shop_id,rel_path,width,height,ocr_text,utc_now_iso()))
    conn.commit(); conn.close()

def replace_keywords(shop_id, keywords):
    conn = connect()
    conn.execute("DELETE FROM threat_keywords WHERE shop_id=?", (shop_id,))
    conn.executemany("""
        INSERT INTO threat_keywords(shop_id,keyword,category,severity,count)
        VALUES (?,?,?,?,?)
    """, [(shop_id,k["keyword"],k["category"],k["severity"],k.get("count",1))
          for k in keywords])
    conn.commit(); conn.close()

def replace_tags(shop_id, tag_list):
    conn = connect()
    conn.execute("DELETE FROM tags WHERE shop_id=?", (shop_id,))
    conn.executemany("INSERT INTO tags(shop_id,tag) VALUES (?,?)",
                     [(shop_id,t) for t in set(tag_list)])
    conn.commit(); conn.close()

def replace_wallets(shop_id, wallets: dict):
    """wallets: {"BTC": [{"address":..., "type":...}], "XMR": [...]}"""
    conn = connect()
    conn.execute("DELETE FROM wallets WHERE shop_id=?", (shop_id,))
    rows = []
    for coin, addrs in wallets.items():
        for w in addrs:
            rows.append((shop_id, coin, w["address"], w.get("type")))
    if rows:
        conn.executemany("""
            INSERT INTO wallets(shop_id,coin,address,addr_type) VALUES (?,?,?,?)
        """, rows)
    conn.commit(); conn.close()

def upsert_threat_intel(shop_id, ti: dict):
    import json
    conn = connect()
    vt = ti.get("virustotal") or {}
    uh_url = ti.get("urlhaus_url") or {}
    conn.execute("""
        INSERT INTO threat_intel(shop_id,vt_malicious,vt_suspicious,vt_harmless,
          vt_engines,uh_found,uh_status,uh_threat,uh_tags,external_risk,checked_at)
        VALUES (?,?,?,?,?,?,?,?,?,?,?)
        ON CONFLICT(shop_id) DO UPDATE SET
          vt_malicious=excluded.vt_malicious,
          vt_suspicious=excluded.vt_suspicious,
          vt_harmless=excluded.vt_harmless,
          vt_engines=excluded.vt_engines,
          uh_found=excluded.uh_found,
          uh_status=excluded.uh_status,
          uh_threat=excluded.uh_threat,
          uh_tags=excluded.uh_tags,
          external_risk=excluded.external_risk,
          checked_at=excluded.checked_at
    """, (
        shop_id,
        vt.get("malicious",0), vt.get("suspicious",0), vt.get("harmless",0),
        json.dumps(vt.get("engines",[])[:10]),
        1 if uh_url.get("found") else 0,
        uh_url.get("status"), uh_url.get("threat"),
        json.dumps(uh_url.get("tags",[])),
        ti.get("external_risk","unknown"),
        utc_now_iso(),
    ))
    conn.commit(); conn.close()

def log_alert(shop_id, channel, risk_level, sent, reason=None):
    conn = connect()
    conn.execute("""
        INSERT INTO alert_log(shop_id,channel,risk_level,sent,reason,sent_at)
        VALUES (?,?,?,?,?,?)
    """, (shop_id,channel,risk_level,1 if sent else 0,reason,utc_now_iso()))
    conn.commit(); conn.close()

def add_discovered_links(source_id, links):
    from urllib.parse import urlparse
    conn = connect()
    now = utc_now_iso()
    for lnk in links:
        domain = urlparse(lnk).netloc
        try:
            conn.execute("""
                INSERT OR IGNORE INTO discovered_links(source_id,url,domain,discovered_at)
                VALUES (?,?,?,?)
            """, (source_id,lnk,domain,now))
        except Exception:
            pass
    conn.commit(); conn.close()

def get_pending_discovered(limit=50):
    conn = connect()
    rows = conn.execute("""
        SELECT id,url FROM discovered_links WHERE scanned=0
        ORDER BY discovered_at ASC LIMIT ?
    """, (limit,)).fetchall()
    conn.close(); return rows

def mark_discovered_scanned(link_id):
    conn = connect()
    conn.execute("UPDATE discovered_links SET scanned=1 WHERE id=?", (link_id,))
    conn.commit(); conn.close()

def list_shops(limit=50, q="", risk_level=""):
    conn = connect()
    sql = """
      SELECT id,url,domain,title,detected_at,last_scanned,
             scan_count,status,risk_score,risk_level,external_risk,language
      FROM shops WHERE 1=1
    """
    params = []
    if q:
        like = f"%{q}%"
        sql += " AND (url LIKE ? OR domain LIKE ? OR title LIKE ?)"
        params += [like,like,like]
    if risk_level:
        sql += " AND risk_level=?"; params.append(risk_level)
    sql += " ORDER BY detected_at DESC LIMIT ?"; params.append(limit)
    rows = conn.execute(sql,params).fetchall()
    conn.close(); return rows

def delete_shop_by_id(shop_id):
    conn = connect()
    cur = conn.execute("DELETE FROM shops WHERE id=?", (shop_id,))
    conn.commit(); conn.close(); return cur.rowcount

def delete_shop_by_url(url):
    conn = connect()
    row = conn.execute("SELECT id FROM shops WHERE url=?", (url,)).fetchone()
    conn.close()
    if not row: return 0
    return delete_shop_by_id(int(row["id"]))

def get_stats():
    conn = connect()
    s = {}
    s["total"]    = conn.execute("SELECT COUNT(*) FROM shops").fetchone()[0]
    s["ok"]       = conn.execute("SELECT COUNT(*) FROM shops WHERE status='ok'").fetchone()[0]
    s["errors"]   = conn.execute("SELECT COUNT(*) FROM shops WHERE status='error'").fetchone()[0]
    s["critical"] = conn.execute("SELECT COUNT(*) FROM shops WHERE risk_level='critical'").fetchone()[0]
    s["high"]     = conn.execute("SELECT COUNT(*) FROM shops WHERE risk_level='high'").fetchone()[0]
    s["medium"]   = conn.execute("SELECT COUNT(*) FROM shops WHERE risk_level='medium'").fetchone()[0]
    s["low"]      = conn.execute("SELECT COUNT(*) FROM shops WHERE risk_level='low'").fetchone()[0]
    s["clean"]    = conn.execute("SELECT COUNT(*) FROM shops WHERE risk_level='clean'").fetchone()[0]
    s["pending_links"] = conn.execute("SELECT COUNT(*) FROM discovered_links WHERE scanned=0").fetchone()[0]
    s["total_links"]   = conn.execute("SELECT COUNT(*) FROM discovered_links").fetchone()[0]
    s["wallets_total"] = conn.execute("SELECT COUNT(*) FROM wallets").fetchone()[0]
    s["top_threats"]   = [dict(r) for r in conn.execute("""
        SELECT category,COUNT(*) AS c FROM threat_keywords
        GROUP BY category ORDER BY c DESC LIMIT 8
    """).fetchall()]
    s["top_coins"] = [dict(r) for r in conn.execute("""
        SELECT coin,COUNT(DISTINCT address) AS c FROM wallets
        GROUP BY coin ORDER BY c DESC
    """).fetchall()]
    s["alerts_sent"] = conn.execute("SELECT COUNT(*) FROM alert_log WHERE sent=1").fetchone()[0]
    conn.close(); return s

def export_all_json():
    conn = connect()
    shops = [dict(r) for r in conn.execute("SELECT * FROM shops ORDER BY risk_score DESC").fetchall()]
    for s in shops:
        sid = s["id"]
        s["tech"]     = [dict(r) for r in conn.execute("SELECT name,category,version,confidence FROM tech WHERE shop_id=?", (sid,)).fetchall()]
        s["keywords"] = [dict(r) for r in conn.execute("SELECT keyword,category,severity,count FROM threat_keywords WHERE shop_id=?", (sid,)).fetchall()]
        s["tags"]     = [r["tag"] for r in conn.execute("SELECT tag FROM tags WHERE shop_id=?", (sid,)).fetchall()]
        s["wallets"]  = [dict(r) for r in conn.execute("SELECT coin,address,addr_type FROM wallets WHERE shop_id=?", (sid,)).fetchall()]
        s["screenshots"] = [r["path"] for r in conn.execute("SELECT path FROM screenshots WHERE shop_id=? ORDER BY created_at DESC", (sid,)).fetchall()]
        ti = conn.execute("SELECT * FROM threat_intel WHERE shop_id=?", (sid,)).fetchone()
        s["threat_intel"] = dict(ti) if ti else {}
    conn.close(); return shops
