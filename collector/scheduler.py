"""
SCRACHER v3 — Scheduler
Re-escaneo periódico automático de sitios conocidos.
FIX: job function a nivel de módulo para ser serializable por APScheduler.
"""

import os
import logging
from pathlib import Path
from datetime import datetime, timezone

try:
    from apscheduler.schedulers.background import BackgroundScheduler
    from apscheduler.jobstores.sqlalchemy import SQLAlchemyJobStore
    from apscheduler.executors.pool import ThreadPoolExecutor
    APSCHEDULER_AVAILABLE = True
except ImportError:
    APSCHEDULER_AVAILABLE = False

ROOT   = Path(__file__).resolve().parents[1]
DB_URL = f"sqlite:///{ROOT / 'data' / 'scheduler.db'}"

RESCAN_INTERVALS = {
    "critical": int(os.getenv("RESCAN_CRITICAL_H", "6")),
    "high":     int(os.getenv("RESCAN_HIGH_H",     "12")),
    "medium":   int(os.getenv("RESCAN_MEDIUM_H",   "24")),
    "low":      int(os.getenv("RESCAN_LOW_H",       "48")),
}

logging.getLogger("apscheduler").setLevel(logging.WARNING)

_scheduler = None


# ─────────────────────────────────────────────────────────────────────────────
#  JOB FUNCTION — DEBE estar a nivel de módulo para ser serializable
# ─────────────────────────────────────────────────────────────────────────────

def _rescan_job(shop_id: int, url: str):
    """
    Función de re-escaneo periódico.
    Definida a nivel de módulo para que APScheduler pueda serializarla.
    """
    from collector.scrape import scrape_one
    from collector.db import (
        upsert_shop, replace_tech, add_screenshot,
        replace_keywords, replace_tags, add_discovered_links,
    )
    from collector.alerts import dispatch_alerts

    try:
        data   = scrape_one(url)
        threat = data.get("threat", {})
        rl     = threat.get("risk_level", "unknown")

        sid = upsert_shop(
            url=data["url"], domain=data.get("domain"),
            title=data.get("title"), status="ok",
            risk_score=threat.get("risk_score", 0), risk_level=rl,
            content_hash=data.get("content_hash"),
            language=data.get("language"),
        )
        replace_tech(sid, data.get("tech", []))
        replace_keywords(sid, threat.get("keywords", []))
        replace_tags(sid, threat.get("tags", []))

        sc = data.get("screenshot") or {}
        if sc.get("path"):
            add_screenshot(sid, sc["path"], sc.get("width"), sc.get("height"))

        if data.get("onion_links"):
            add_discovered_links(sid, data["onion_links"])

        dispatch_alerts({
            "shop_id": sid, "url": data["url"],
            "domain": data.get("domain"), "title": data.get("title"),
            "risk_level": rl,
            "risk_score": threat.get("risk_score", 0),
            "tags": threat.get("tags", []),
            "keywords": threat.get("keywords", []),
        })

        _log_rescan(shop_id, url, "ok", rl)

    except Exception as e:
        _log_rescan(shop_id, url, "error", str(e))


# ─────────────────────────────────────────────────────────────────────────────

def get_scheduler():
    global _scheduler
    if not APSCHEDULER_AVAILABLE:
        return None
    if _scheduler is None:
        jobstores    = {"default": SQLAlchemyJobStore(url=DB_URL)}
        executors    = {"default": ThreadPoolExecutor(max_workers=2)}
        job_defaults = {"coalesce": True, "max_instances": 1, "misfire_grace_time": 3600}
        _scheduler   = BackgroundScheduler(
            jobstores=jobstores,
            executors=executors,
            job_defaults=job_defaults,
        )
    return _scheduler


def start_scheduler():
    sched = get_scheduler()
    if sched and not sched.running:
        sched.start()
        return True
    return False


def stop_scheduler():
    sched = get_scheduler()
    if sched and sched.running:
        sched.shutdown(wait=False)


def schedule_rescan(shop_id: int, url: str, risk_level: str = "low") -> bool:
    sched = get_scheduler()
    if not sched:
        return False

    hours  = RESCAN_INTERVALS.get(risk_level, 48)
    job_id = f"rescan_{shop_id}"

    sched.add_job(
        _rescan_job,
        trigger="interval",
        hours=hours,
        id=job_id,
        kwargs={"shop_id": int(shop_id), "url": str(url)},
        name=f"Rescan [{risk_level.upper()}] {url[:60]}",
        replace_existing=True,
    )
    return True


def unschedule_rescan(shop_id: int) -> bool:
    sched = get_scheduler()
    if not sched:
        return False
    job_id = f"rescan_{shop_id}"
    if sched.get_job(job_id):
        sched.remove_job(job_id)
        return True
    return False


def list_jobs() -> list[dict]:
    sched = get_scheduler()
    if not sched:
        return []
    jobs = []
    for job in sched.get_jobs():
        next_run = job.next_run_time
        jobs.append({
            "id":       job.id,
            "name":     job.name,
            "next_run": next_run.isoformat() if next_run else None,
            "trigger":  str(job.trigger),
        })
    return sorted(jobs, key=lambda j: j["next_run"] or "")


def _log_rescan(shop_id: int, url: str, status: str, detail: str):
    try:
        from collector.db import connect
        conn = connect()
        conn.execute("""
            CREATE TABLE IF NOT EXISTS rescan_log (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              shop_id INTEGER, url TEXT, status TEXT, detail TEXT, ran_at TEXT
            )
        """)
        conn.execute("""
            INSERT INTO rescan_log(shop_id, url, status, detail, ran_at)
            VALUES (?, ?, ?, ?, ?)
        """, (shop_id, url, status, str(detail)[:500],
              datetime.now(timezone.utc).isoformat(timespec="seconds")))
        conn.commit()
        conn.close()
    except Exception:
        pass


def scheduler_status() -> dict:
    return {
        "available": APSCHEDULER_AVAILABLE,
        "running":   (_scheduler is not None and _scheduler.running),
        "job_count": len(list_jobs()),
        "intervals": RESCAN_INTERVALS,
    }
