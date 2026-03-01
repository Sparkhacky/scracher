"""
SCRACHER v3 - CLI Interface
ASCII puro, compatible con cualquier bash/terminal Linux.
"""

import re
import os
import sys
import shutil
import threading
import itertools
from time import perf_counter, sleep
from datetime import datetime

from collector.db import (
    init_db, upsert_shop, replace_tech, add_screenshot, list_shops,
    delete_shop_by_id, replace_keywords, replace_tags, replace_wallets,
    add_discovered_links, upsert_threat_intel, log_alert,
    get_pending_discovered, mark_discovered_scanned, get_stats, export_all_json,
)
from collector.scrape import scrape_one
from collector.dashboard_launcher import start_dashboard
from collector.alerts import dispatch_alerts, alerts_status
from collector.scheduler import scheduler_status, start_scheduler, list_jobs, schedule_rescan
from collector.ocr_extract import ocr_check_status

# ─────────────────────────────────────────────────────────────────────────────
#  ANSI COLORS - solo los basicos que funcionan en cualquier terminal
# ─────────────────────────────────────────────────────────────────────────────

R  = "\033[0m"
B  = "\033[1m"
CY = "\033[36m"
GR = "\033[32m"
YL = "\033[33m"
RD = "\033[31m"
BL = "\033[34m"
WH = "\033[37m"
GY = "\033[90m"

RISK_C = {
    "critical": RD, "high": YL, "medium": YL,
    "low": GR, "clean": GY, "unknown": GY,
}

RISK_TAG = {
    "critical": "[CRIT]",
    "high":     "[HIGH]",
    "medium":   "[MED] ",
    "low":      "[LOW] ",
    "clean":    "[OK]  ",
    "unknown":  "[???] ",
}

def W():
    # Ancho fijo — no adaptativo para evitar colapsos en terminales estrechas
    return 80

def strip_ansi(s):
    return re.sub(r'\033\[[0-9;]*m', '', s)

def vlen(s):
    return len(strip_ansi(s))

def pad(s, width):
    """ljust con ancho visual correcto (ignora ANSI)."""
    return s + ' ' * max(0, width - vlen(s))

# ─────────────────────────────────────────────────────────────────────────────
#  LAYOUT BASICO
# ─────────────────────────────────────────────────────────────────────────────

def hr(char='='):
    print(GY + char * 80 + R)

def thinhr():
    print(GY + '-' * 80 + R)

def section(title):
    dashes = max(2, 76 - len(title))
    print(f"\n{GY}-- {R}{CY}{B}{title}{R}  {GY}{'─' * dashes}{R}")
    print()

def pok(msg=''):
    print(f"  {GR}[OK]{R}  {msg}")

def pwarn(msg=''):
    print(f"  {YL}[!!]{R}  {msg}")

def perr(msg=''):
    print(f"  {RD}[ERR]{R} {msg}")

def prompt(label=''):
    try:
        lbl = f"{GY}{label}{R} " if label else ''
        return input(f"\n  {CY}>{R} {lbl}").strip()
    except (EOFError, KeyboardInterrupt):
        return ''

def pause():
    try:
        input(f"\n  {GY}[Enter to continue]{R} ")
    except (EOFError, KeyboardInterrupt):
        pass

def _fmt_s(t):
    if t < 1:  return f"{int(t*1000)}ms"
    if t < 60: return f"{t:.1f}s"
    return f"{int(t//60)}m{int(t%60):02d}s"

def normalize_url(u):
    u = u.strip()
    if not u: return u
    if not re.match(r'^https?://', u, re.I):
        u = 'http://' + u
    return u

def _dedup(urls):
    seen, out = set(), []
    for u in urls:
        if u and u not in seen:
            out.append(u); seen.add(u)
    return out

def _short(u, n):
    u = re.sub(r'https?://', '', u)
    return (u[:n-1] + '>') if len(u) > n else u

# ─────────────────────────────────────────────────────────────────────────────
#  SPINNER - solo ASCII
# ─────────────────────────────────────────────────────────────────────────────

class Spinner:
    FRAMES = ['-', '\\', '|', '/']

    def __init__(self):
        self._stop   = threading.Event()
        self._thread = None
        self._label  = ''

    def _spin(self):
        for f in itertools.cycle(self.FRAMES):
            if self._stop.is_set(): break
            sys.stdout.write(f"\r  [{CY}{f}{R}]  {GY}{self._label}{R}   ")
            sys.stdout.flush()
            sleep(0.1)
        sys.stdout.write('\r' + ' ' * min(80, W()) + '\r')
        sys.stdout.flush()

    def start(self, label=''):
        self._label = label
        self._stop.clear()
        self._thread = threading.Thread(target=self._spin, daemon=True)
        self._thread.start()

    def stop(self):
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=1)

# ─────────────────────────────────────────────────────────────────────────────
#  BANNER
# ─────────────────────────────────────────────────────────────────────────────

LOGO = [
    r" ____   ____ ____      _    ____ _   _ _____ ____  ",
    r"/ ___| / ___|  _ \    / \  / ___| | | | ____|  _ \ ",
    r"\___ \| |   | |_) |  / _ \| |   | |_| |  _| | |_) |",
    r" ___) | |___|  _ <  / ___ \ |___| _ | | |___|  _ < ",
    r"|____/ \____|_| \_\/_/   \_\____|_| |_|_____|_| \_" + "\\",
]

def banner():
    os.system('clear')
    now = datetime.now().strftime('%Y-%m-%d  %H:%M:%S')
    print()
    print(f"{GY}{'='*80}{R}")
    for ln in LOGO:
        print(f"  {CY}{B}{ln}{R}")
    print()
    print(f"  {GY}.onion Collector  |  Threat Intelligence  |  Crypto Tracer  |  v3.0{R}")
    print(f"  {GY}{now}{R}")
    print(f"{GY}{'='*80}{R}")

# ─────────────────────────────────────────────────────────────────────────────
#  STATUS PANEL
# ─────────────────────────────────────────────────────────────────────────────

def status_panel(stats):
    al  = alerts_status()
    sc  = scheduler_status()
    ocr = ocr_check_status()
    vt  = bool(os.getenv('VT_API_KEY', ''))

    print(f"\n  {GY}SITES{R}    "
          f"{WH}{B}{stats.get('total',0):>4}{R}  "
          f"{RD}CRIT:{B}{stats.get('critical',0)}{R}  "
          f"{YL}HIGH:{B}{stats.get('high',0)}{R}  "
          f"{YL}MED:{B}{stats.get('medium',0)}{R}  "
          f"{GR}LOW:{B}{stats.get('low',0)}{R}  "
          f"{GY}ERR:{stats.get('errors',0)}{R}")

    print(f"  {GY}INTEL{R}    "
          f"{YL}wallets:{B}{stats.get('wallets_total',0)}{R}  "
          f"{CY}links:{B}{stats.get('total_links',0)}{R}  "
          f"{YL}pending:{B}{stats.get('pending_links',0)}{R}  "
          f"{GR}alerts:{B}{stats.get('alerts_sent',0)}{R}")

    def mod(name, on, detail=''):
        dot = f"{GR}[ON] {R}" if on else f"{RD}[--] {R}"
        d   = f"{GY}({detail}){R}" if detail else ''
        return f"{dot}{name}{d}"

    print(f"\n  {mod('TOR',        True,                        '9050'  )} "
          f"  {mod('VT',         vt,                          'key'   )} "
          f"  {mod('URLhaus',    True,                        'free'  )} "
          f"  {mod('OCR',        ocr.get('available', False)          )}")
    print(f"  {mod('SCHEDULER',  sc.get('running', False), str(sc.get('job_count',0))+' jobs')} "
          f"  {mod('SLACK',      al.get('slack', False)               )} "
          f"  {mod('EMAIL',      al.get('email', False)               )}")

    top = stats.get('top_threats', [])
    if top:
        t_str = '  |  '.join(
            f"{GY}{t['category']}{R}:{CY}{t['c']}{R}" for t in top[:6]
        )
        print(f"\n  {GY}TOP THREATS:{R}  {t_str}")

# ─────────────────────────────────────────────────────────────────────────────
#  MENU
# ─────────────────────────────────────────────────────────────────────────────

def main_menu_draw(stats):
    sc      = scheduler_status()
    pending = stats.get('pending_links', 0)

    section('MENU')
    print()

    def opt(key, label, desc, kc=CY, dc=GY):
        print(f"  {GY}[{R}{kc}{B}{key}{R}{GY}]{R}  {WH}{label:<24}{R}  {dc}{desc}{R}")

    opt('1', 'Scan URLs',       'enter .onion targets manually')
    opt('2', 'Scan from file',  'load targets from a .txt file')
    opt('3', 'Crawl discovered',
        f"{pending} links pending" if pending else 'no pending links',
        YL if pending else CY,
        YL if pending else GY)
    print()
    opt('4', 'Dashboard',       'open http://127.0.0.1:8000',   GR)
    opt('5', 'Statistics',      'full intel & risk breakdown',   GR)
    opt('6', 'Export',          'JSON / CSV / HTML report',      GR)
    opt('7', 'Scheduler',
        f"{'RUNNING' if sc.get('running') else 'STOPPED'} - {sc.get('job_count',0)} jobs",
        GR if sc.get('running') else YL)
    opt('8', 'Manage DB',       'search / delete records',       YL)
    print()
    opt('0', 'Exit',            '',                              RD)
    print()
    thinhr()

# ─────────────────────────────────────────────────────────────────────────────
#  SCAN
# ─────────────────────────────────────────────────────────────────────────────

# Columnas: (header, ancho_visible)
_COLS = [
    ('#',     4),
    ('URL',  46),
    ('RISK', 10),
    ('SCR',   6),
    ('KW',    5),
    ('TECH',  5),
    ('LNK',   5),
    ('TIME',  7),
]

def _scan_table_header():
    row = '  '
    for h, w in _COLS:
        row += f"{GY}{B}{h:<{w}}{R}"
    print(f"\n{row}")
    thinhr()

def _score_c(s):
    if s >= 0.7: return RD
    if s >= 0.3: return YL
    return GR

def _kw_c(n):
    if n >= 10: return RD
    if n >= 3:  return YL
    return GY

def scan_header(total, use_ti):
    section('SCAN SESSION')
    now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    print(f"  {GY}Started:{R} {WH}{now}{R}   "
          f"{GY}Targets:{R} {CY}{B}{total}{R}   "
          f"{GY}ThreatIntel:{R} {''+GR+B+'ON'+R if use_ti else GY+'OFF'+R}")
    _scan_table_header()

def scan_row_ok(i, data, elapsed):
    threat = data.get('threat', {})
    rl     = threat.get('risk_level', 'unknown')
    score  = threat.get('risk_score', 0.0)
    url    = data.get('url', '')
    kw     = len(threat.get('keywords', []))
    tech   = len(data.get('tech', []))
    links  = len(data.get('onion_links', []))

    tag    = RISK_TAG.get(rl, '[???]')
    rc     = RISK_C.get(rl, GY)
    sc_c   = _score_c(score)
    kw_c   = _kw_c(kw)

    c0 = pad(f"{GY}{i:>{_COLS[0][1]-1}}{R}", _COLS[0][1])
    c1 = pad(f"{WH}{_short(url, _COLS[1][1]-1)}{R}", _COLS[1][1])
    c2 = pad(f"{rc}{B}{tag}{R}", _COLS[2][1])
    c3 = pad(f"{sc_c}{score:.2f}{R}", _COLS[3][1])
    c4 = pad(f"{kw_c}{kw}{R}", _COLS[4][1])
    c5 = pad(f"{CY}{tech}{R}", _COLS[5][1])
    c6 = pad(f"{BL}{links}{R}", _COLS[6][1])
    c7 = f"{GY}{_fmt_s(elapsed)}{R}"

    print(f"  {c0}{c1}{c2}{c3}{c4}{c5}{c6}{c7}")

def scan_row_err(i, url, error, elapsed):
    c0  = pad(f"{GY}{i:>{_COLS[0][1]-1}}{R}", _COLS[0][1])
    c1  = pad(f"{GY}{_short(url, _COLS[1][1]-1)}{R}", _COLS[1][1])
    msg = (error[:42] + '>') if len(error) > 43 else error
    print(f"  {c0}{c1}{RD}[FAIL] {msg}{R}  {GY}{_fmt_s(elapsed)}{R}")

def scan_progress(done, total, ok_n, fail_n, elapsed):
    pct    = done / total if total else 0
    bar_w  = 28
    filled = int(bar_w * pct)
    bar    = f"{CY}{'#'*filled}{GY}{'.'*(bar_w-filled)}{R}"
    eta    = ''
    if 0 < done < total:
        rem = (elapsed / done) * (total - done)
        eta = f"  ETA:{WH}{_fmt_s(rem)}{R}"
    sys.stdout.write(
        f"\r  [{bar}] {WH}{pct*100:5.1f}%{R}"
        f"  {GR}ok:{ok_n}{R}  {RD}err:{fail_n}{R}{eta}   "
    )
    sys.stdout.flush()

def scan_footer(ok_n, fail_n, links_n, wallets_n, t):
    sys.stdout.write('\r' + ' ' * min(100, W()) + '\r')
    sys.stdout.flush()
    thinhr()
    print(
        f"  {CY}{B}DONE{R}  "
        f"{GR}ok:{ok_n}{R}  "
        f"{RD}fail:{fail_n}{R}  "
        f"{BL}links:{links_n}{R}  "
        f"{YL}wallets:{wallets_n}{R}  "
        f"{GY}time:{WH}{_fmt_s(t)}{R}"
    )
    thinhr()
    print()

def read_urls_multiline():
    section('ENTER TARGETS')
    print(f"  {GY}One URL per line. Blank line to start.{R}\n")
    urls = []
    while True:
        try:
            raw = input(f"  {CY}>{R} ").strip()
        except (EOFError, KeyboardInterrupt):
            break
        if not raw: break
        u = normalize_url(raw)
        if u:
            urls.append(u)
            print(f"    {GY}+ {u}{R}")
    result = _dedup(urls)
    if result:
        pok(f"{len(result)} target(s) queued")
    return result

def read_urls_from_file():
    section('LOAD FROM FILE')
    path = prompt('File path:')
    if not os.path.isfile(path):
        perr(f"File not found: {path}")
        return []
    with open(path, encoding='utf-8', errors='ignore') as f:
        lines = [normalize_url(l.strip()) for l in f
                 if l.strip() and not l.startswith('#')]
    result = _dedup(lines)
    pok(f"{len(result)} targets loaded")
    return result

def ask_threat_intel():
    ans = prompt(f"Enable VirusTotal/URLhaus? {GY}[Y/n]{R}")
    return ans.lower() != 'n'

def run_scan(urls, use_threat_intel=None):
    if not urls:
        pwarn('No targets provided.')
        return

    if use_threat_intel is None:
        use_threat_intel = ask_threat_intel()

    init_db()
    scan_header(len(urls), use_threat_intel)

    ok_n = fail_n = new_links = new_wallets = 0
    t_all   = perf_counter()
    spinner = Spinner()

    for i, u in enumerate(urls, 1):
        spinner.start(f"[{i}/{len(urls)}]  {_short(u, 55)}")
        t0 = perf_counter()

        try:
            data    = scrape_one(u, run_threat_intel=use_threat_intel)
            elapsed = perf_counter() - t0
            spinner.stop()

            threat   = data.get('threat', {})
            ti       = data.get('threat_intel', {})
            rl       = threat.get('risk_level', 'unknown')
            ext_risk = ti.get('external_risk', 'unknown')

            shop_id = upsert_shop(
                url=data['url'], domain=data.get('domain'),
                title=data.get('title'), status='ok',
                risk_score=threat.get('risk_score', 0), risk_level=rl,
                external_risk=ext_risk,
                content_hash=data.get('content_hash'),
                language=data.get('language'),
            )
            replace_tech(shop_id, data.get('tech', []))
            replace_keywords(shop_id, threat.get('keywords', []))
            replace_tags(shop_id, threat.get('tags', []))
            wallets = data.get('wallets', {})
            replace_wallets(shop_id, wallets)
            if use_threat_intel and ti:
                upsert_threat_intel(shop_id, ti)

            sc_d     = data.get('screenshot') or {}
            ocr_text = data.get('ocr', {}).get('text') or None
            if sc_d.get('path'):
                add_screenshot(shop_id, sc_d['path'],
                               sc_d.get('width'), sc_d.get('height'), ocr_text)

            onion_links = data.get('onion_links', [])
            if onion_links:
                add_discovered_links(shop_id, onion_links)
                new_links += len(onion_links)

            wallet_count = sum(len(v) for v in wallets.values())
            new_wallets += wallet_count

            alert_results = dispatch_alerts({
                'shop_id': shop_id, 'url': data['url'],
                'domain': data.get('domain'), 'title': data.get('title'),
                'risk_level': rl, 'risk_score': threat.get('risk_score', 0),
                'tags': threat.get('tags', []),
                'keywords': threat.get('keywords', []),
                'wallets_summary': data.get('wallets_summary', ''),
                'external_risk': ext_risk,
                'language': data.get('language'),
            })
            for ar in alert_results:
                log_alert(shop_id, ar.get('channel','?'), rl,
                          ar.get('sent', False), ar.get('reason'))

            schedule_rescan(shop_id, data['url'], rl)
            ok_n += 1
            scan_row_ok(i, data, elapsed)

        except Exception as e:
            elapsed = perf_counter() - t0
            spinner.stop()
            fail_n += 1
            upsert_shop(url=u, domain=None, title=None, status='error', notes=str(e))
            scan_row_err(i, u, str(e), elapsed)

        scan_progress(i, len(urls), ok_n, fail_n, perf_counter() - t_all)

    scan_footer(ok_n, fail_n, new_links, new_wallets, perf_counter() - t_all)

# ─────────────────────────────────────────────────────────────────────────────
#  STATISTICS
# ─────────────────────────────────────────────────────────────────────────────

def show_stats():
    stats = get_stats()
    total = max(stats.get('total', 1), 1)
    bar_w = 36

    section('STATISTICS')
    print(f"\n  {GY}Risk distribution:{R}\n")

    for label, key, color in [
        ('CRITICAL', 'critical', RD),
        ('HIGH',     'high',     YL),
        ('MEDIUM',   'medium',   YL),
        ('LOW',      'low',      GR),
        ('CLEAN',    'clean',    GY),
        ('ERRORS',   'errors',   RD),
    ]:
        n      = stats.get(key, 0)
        filled = int((n / total) * bar_w)
        bar    = f"{color}{'|'*filled}{GY}{'.'*(bar_w-filled)}{R}"
        print(f"  {color}{label:<10}{R}  [{bar}]  {color}{B}{n:>4}{R}  {GY}{n/total*100:5.1f}%{R}")

    print(f"\n  {GY}wallets:{R}  {YL}{B}{stats.get('wallets_total',0)}{R}"
          f"   {GY}links:{R}  {CY}{stats.get('total_links',0)}{R}"
          f"   {GY}pending:{R}  {YL}{stats.get('pending_links',0)}{R}"
          f"   {GY}alerts:{R}  {GR}{stats.get('alerts_sent',0)}{R}")

    top = stats.get('top_threats', [])
    if top:
        max_c = max(t['c'] for t in top) or 1
        print(f"\n  {GY}Top threat categories:{R}\n")
        for t in top:
            bar = f"{RD}{'*' * int((t['c'] / max_c) * 25)}{R}"
            print(f"  {WH}{t['category']:<18}{R}  {bar}  {RD}{t['c']}{R}")

    coins = stats.get('top_coins', [])
    if coins:
        cs = '   '.join(f"{YL}{c['coin']}{R}:{WH}{c['c']}{R}" for c in coins)
        print(f"\n  {GY}Crypto wallets:{R}  {cs}")
    print()

# ─────────────────────────────────────────────────────────────────────────────
#  CRAWL
# ─────────────────────────────────────────────────────────────────────────────

def crawl_discovered():
    pending = get_pending_discovered(limit=100)
    if not pending:
        pok('No pending links to crawl.')
        return
    section('CRAWL DISCOVERED')
    pwarn(f"{len(pending)} discovered links pending")
    choice = prompt(f"How many to scan? {GY}[Enter=all / number]{R}")
    if choice.isdigit():
        pending = pending[:int(choice)]
    urls = [r['url'] for r in pending]
    ids  = [r['id']  for r in pending]
    run_scan(urls)
    for lid in ids:
        mark_discovered_scanned(lid)
    pok(f"Marked {len(ids)} as scanned.")

# ─────────────────────────────────────────────────────────────────────────────
#  SCHEDULER
# ─────────────────────────────────────────────────────────────────────────────

def scheduler_menu():
    sc = scheduler_status()
    section('SCHEDULER')

    if not sc['available']:
        perr('APScheduler not installed.')
        print(f"  {GY}Run: pip install apscheduler sqlalchemy{R}\n")
        return

    running = sc.get('running', False)
    state   = f"{GR}{B}[RUNNING]{R}" if running else f"{RD}[STOPPED]{R}"
    print(f"\n  Status: {state}   {GY}Jobs:{R} {WH}{sc['job_count']}{R}")

    print(f"\n  {GY}Intervals:{R}")
    for level, hours in sc['intervals'].items():
        color = RISK_C.get(level, GY)
        tag   = RISK_TAG.get(level, '[???]')
        print(f"    {color}{tag}{R}  every {WH}{hours}h{R}")

    jobs = list_jobs()
    if jobs:
        print(f"\n  {GY}Upcoming rescans:{R}")
        for j in jobs[:8]:
            nxt  = (j['next_run'] or '?')[:16]
            name = j['name'][:50]
            print(f"    {GY}>{R}  {WH}{name}{R}  {CY}{nxt}{R}")

    print()
    thinhr()
    print(f"  {GR}[S]{R} Start   {RD}[P]{R} Stop   {GY}[0]{R} Back")
    opt = prompt().upper()

    if opt == 'S':
        if start_scheduler(): pok('Scheduler started.')
        else: print(f"  {GY}Already running.{R}\n")
    elif opt == 'P':
        from collector.scheduler import stop_scheduler
        stop_scheduler()
        pwarn('Scheduler stopped.')

# ─────────────────────────────────────────────────────────────────────────────
#  EXPORT
# ─────────────────────────────────────────────────────────────────────────────

def export_flow():
    from collector.exporter import export_json, export_csv, export_html_report
    shops = export_all_json()
    stats = get_stats()

    section('EXPORT')
    print(f"  {GY}{len(shops)} sites in database{R}\n")
    print(f"  {GR}[1]{R}  JSON   {GY}structured, wallets + threat intel{R}")
    print(f"  {GR}[2]{R}  CSV    {GY}flat table, Excel compatible{R}")
    print(f"  {GR}[3]{R}  HTML   {GY}forensic report for LEA / CERT{R}")
    print(f"  {CY}[4]{R}  All formats")
    print(f"  {GY}[0]{R}  Cancel")

    opt   = prompt()
    paths = []
    if opt in ('1','4'): paths.append(export_json(shops))
    if opt in ('2','4'): paths.append(export_csv(shops))
    if opt in ('3','4'): paths.append(export_html_report(shops, stats))

    if paths:
        print()
        for p in paths:
            pok(f"{WH}{p}{R}")
    print()

# ─────────────────────────────────────────────────────────────────────────────
#  DB MANAGEMENT
# ─────────────────────────────────────────────────────────────────────────────

def delete_flow():
    def print_table(rows):
        if not rows:
            print(f"\n  {GY}No results.{R}\n"); return
        print(f"\n  {GY}{'ID':>4}  {'RISK':<8}  {'DOMAIN':<28}  TITLE{R}")
        print(f"  {GY}{'-'*4}  {'-'*8}  {'-'*28}  {'-'*24}{R}")
        for r in rows:
            rl  = r['risk_level'] or '?'
            rc  = RISK_C.get(rl, GY)
            tag = RISK_TAG.get(rl, '[???]')
            dom = (r['domain'] or '-')[:28]
            ttl = (r['title']  or '-')[:26]
            print(f"  {GY}{int(r['id']):>4}{R}  "
                  f"{rc}{tag}{R}  "
                  f"{WH}{dom:<28}{R}  "
                  f"{GY}{ttl}{R}")
        print()

    def parse_ids(s):
        out = set()
        for chunk in s.replace(',', ' ').split():
            if '-' in chunk:
                a, b = chunk.split('-', 1)
                if a.isdigit() and b.isdigit():
                    [out.add(x) for x in range(int(a), int(b)+1)]
            elif chunk.isdigit():
                out.add(int(chunk))
        return sorted(out)

    while True:
        section('DATABASE MANAGEMENT')
        print(f"\n  {GR}[1]{R}  List last 25"
              f"   {GR}[2]{R}  Search"
              f"   {YL}[3]{R}  Delete by ID"
              f"   {GY}[0]{R}  Back\n")
        opt = prompt()
        if opt == '0':
            return
        elif opt == '1':
            print_table(list_shops(25)); pause()
        elif opt == '2':
            q = prompt('Search (url / domain / title):')
            print_table(list_shops(25, q=q)); pause()
        elif opt == '3':
            print_table(list_shops(25))
            sids = prompt('IDs to delete (e.g. 1,3-7):')
            ids  = parse_ids(sids)
            if not ids:
                print(f"\n  {GY}Cancelled.{R}\n"); continue
            pwarn(f"About to delete {len(ids)} record(s).")
            confirm = prompt("Type DELETE to confirm:")
            if confirm != 'DELETE':
                print(f"\n  {GY}Cancelled.{R}\n"); continue
            deleted = sum(1 for sid in ids if delete_shop_by_id(sid))
            pok(f"Deleted: {WH}{deleted}{R}")

# ─────────────────────────────────────────────────────────────────────────────
#  BROWSER
# ─────────────────────────────────────────────────────────────────────────────

def open_browser(host='127.0.0.1', port=8000):
    import subprocess
    url = f"http://{host}:{port}"
    if not os.environ.get('DISPLAY') and not os.environ.get('WAYLAND_DISPLAY'):
        print(f"\n  {GY}No display. Open manually:{R}  {WH}{url}{R}\n")
        return
    try:
        subprocess.Popen(['xdg-open', url],
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        pok(f"Opening {WH}{url}{R}")
    except Exception:
        print(f"\n  {GY}Open manually:{R}  {WH}{url}{R}\n")

# ─────────────────────────────────────────────────────────────────────────────
#  MAIN LOOP
# ─────────────────────────────────────────────────────────────────────────────

def main_menu():
    env_path = os.path.join(os.path.dirname(__file__), '..', '.env')
    if os.path.isfile(env_path):
        try:
            from dotenv import load_dotenv
            load_dotenv(env_path)
        except ImportError:
            pass

    init_db()
    start_scheduler()
    host, port = '127.0.0.1', 8000

    while True:
        banner()
        stats = get_stats()
        status_panel(stats)
        main_menu_draw(stats)

        choice = prompt()

        if choice == '1':
            urls = read_urls_multiline()
            run_scan(urls)
            pause()
        elif choice == '2':
            urls = read_urls_from_file()
            if urls: run_scan(urls)
            pause()
        elif choice == '3':
            crawl_discovered()
            pause()
        elif choice == '4':
            start_dashboard(host, port)
            open_browser(host, port)
            pause()
        elif choice == '5':
            show_stats()
            pause()
        elif choice == '6':
            export_flow()
            pause()
        elif choice == '7':
            scheduler_menu()
            pause()
        elif choice == '8':
            delete_flow()
        elif choice == '0':
            banner()
            print(f"\n  {GY}Session terminated. Stay sharp.{R}\n")
            try:
                from collector.scheduler import stop_scheduler
                stop_scheduler()
            except Exception:
                pass
            break
        else:
            perr('Invalid option.')
            sleep(0.4)
