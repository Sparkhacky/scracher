from pathlib import Path
from urllib.parse import urlparse
from datetime import datetime, timezone
from playwright.sync_api import sync_playwright

ROOT = Path(__file__).resolve().parents[1]
SHOT_DIR = ROOT / "dashboard" / "static" / "screenshots"

TOR_PROXY = "socks5://127.0.0.1:9050"  # Playwright usa socks5 (no socks5h aquí)

def _safe_name(s: str) -> str:
    return "".join(ch if ch.isalnum() or ch in ("-", "_", ".") else "_" for ch in s)

def take_screenshot(url: str, timeout_ms: int = 90000) -> tuple[str, int | None, int | None]:
    SHOT_DIR.mkdir(parents=True, exist_ok=True)

    parsed = urlparse(url)
    domain = parsed.netloc or "site"
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    fname = f"{_safe_name(domain)}_{stamp}.png"

    abs_path = SHOT_DIR / fname
    rel_path = f"screenshots/{fname}"

    width = height = None

    with sync_playwright() as p:
        browser = p.chromium.launch(
            headless=True,
            proxy={"server": TOR_PROXY},
            args=[
                "--disable-dev-shm-usage",
                "--no-sandbox",
            ],
        )
        context = browser.new_context(ignore_https_errors=True, viewport={"width": 1365, "height": 768})
        page = context.new_page()

        page.goto(url, wait_until="domcontentloaded", timeout=timeout_ms)
        page.wait_for_timeout(2500)  # onion = lento

        page.screenshot(path=str(abs_path), full_page=True)
        width = page.viewport_size["width"]
        height = page.viewport_size["height"]

        context.close()
        browser.close()

    return rel_path, width, height
