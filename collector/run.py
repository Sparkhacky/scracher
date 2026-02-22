from collector.db import init_db, upsert_shop, replace_tech, add_screenshot, list_shops, delete_shop_by_id
import re
from collector.db import init_db, upsert_shop, replace_tech, add_screenshot
from collector.scrape import scrape_one
from collector.dashboard_launcher import start_dashboard

GREEN = "\033[92m"
RESET = "\033[0m"

def print_banner():
    art = r"""

              SCRACHER - ONION SEARCHER SCRAPPING
"""
    print(GREEN + art + RESET)

def normalize_url(u: str) -> str:
    u = u.strip()
    if not u:
        return u
    if not re.match(r"^https?://", u, flags=re.I):
        u = "https://" + u
    return u

def read_urls_multiline() -> list[str]:
    print("\nPega una o varias URLs (una por línea). Enter vacío para terminar:\n")
    urls = []
    while True:
        line = input().strip()
        if not line:
            break
        urls.append(normalize_url(line))
    # dedup conservando orden
    seen = set()
    out = []
    for u in urls:
        if u and u not in seen:
            out.append(u)
            seen.add(u)
    return out

def run_scan(urls: list[str]):
    from time import perf_counter
    from datetime import datetime

    # Colores (si no los quieres, ponlos a "")
    C_OK = "\033[92m"
    C_WARN = "\033[93m"
    C_ERR = "\033[91m"
    C_DIM = "\033[90m"
    C_TITLE = "\033[96m"
    C_RESET = "\033[0m"

    def hr():
        print(C_DIM + "─" * 72 + C_RESET)

    def fmt_s(t: float) -> str:
        # formato segundos bonito
        if t < 1:
            return f"{int(t*1000)}ms"
        if t < 60:
            return f"{t:.1f}s"
        m = int(t // 60)
        s = int(t % 60)
        return f"{m}m{s:02d}s"

    def short(s: str | None, n: int) -> str:
        if not s:
            return "-"
        s = " ".join(str(s).split())
        return (s[:n-1] + "…") if len(s) > n else s

    if not urls:
        print(f"\n{C_WARN}[!]{C_RESET} No se proporcionaron URLs.\n")
        return

    init_db()

    start_all = perf_counter()
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    hr()
    print(f"{C_TITLE}ESCANEO .onion{C_RESET}  {C_DIM}{ts}{C_RESET}")
    print(f"{C_DIM}Objetivos:{C_RESET} {len(urls)}   {C_DIM}Salida:{C_RESET} data/scrs.db  + screenshots/")
    hr()

    # Resumen
    ok = 0
    fail = 0
    results = []  # (status, domain, title, time, url, err)

    for i, u in enumerate(urls, start=1):
        u_display = short(u, 64)
        print(f"{C_DIM}[{i:>3}/{len(urls):<3}]{C_RESET} {u_display}")
        t0 = perf_counter()

        try:
            data = scrape_one(u)
            t1 = perf_counter()
            elapsed = t1 - t0

            shop_id = upsert_shop(
                url=data["url"],
                domain=data.get("domain"),
                title=data.get("title"),
                status="ok",
                notes=None,
            )

            replace_tech(shop_id, data.get("tech", []))

            sc = data.get("screenshot") or {}
            if sc.get("path"):
                add_screenshot(shop_id, sc["path"], sc.get("width"), sc.get("height"))

            ok += 1

            domain = data.get("domain") or "-"
            title = data.get("title")
            tech_count = len(data.get("tech") or [])
            shot = "yes" if sc.get("path") else "no"

            print(
                f"  {C_OK}✓ OK{C_RESET}  "
                f"{C_DIM}t={fmt_s(elapsed)}{C_RESET}  "
                f"{C_DIM}tech={tech_count}{C_RESET}  "
                f"{C_DIM}screenshot={shot}{C_RESET}  "
                f"{C_DIM}title:{C_RESET} {short(title, 44)}"
            )

            results.append(("ok", domain, title, elapsed, data["url"], None))

        except Exception as e:
            t1 = perf_counter()
            elapsed = t1 - t0
            fail += 1

            # Guardar error en DB (upsert)
            upsert_shop(url=u, domain=None, title=None, status="error", notes=str(e))

            print(f"  {C_ERR}✗ ERROR{C_RESET} {C_DIM}t={fmt_s(elapsed)}{C_RESET}  {C_DIM}{short(str(e), 70)}{C_RESET}")
            results.append(("error", "-", None, elapsed, u, str(e)))

        print()  # línea en blanco entre objetivos

    total = perf_counter() - start_all
    hr()
    print(f"{C_TITLE}RESUMEN{C_RESET}")
    print(f"{C_OK}OK:{C_RESET} {ok}   {C_ERR}ERROR:{C_RESET} {fail}   {C_DIM}Total:{C_RESET} {fmt_s(total)}")
    hr()

    # Top errores (si hay)
    if fail:
        print(f"{C_WARN}Errores (últimos 5):{C_RESET}")
        shown = 0
        for st, dom, title, elapsed, url, err in reversed(results):
            if st == "error":
                print(f"  {C_ERR}•{C_RESET} {short(url, 52)}  {C_DIM}{short(err, 90)}{C_RESET}")
                shown += 1
                if shown >= 5:
                    break
        hr()

    print(f"{C_DIM}Siguiente:{C_RESET} abre el dashboard para visualizar: http://127.0.0.1:8000\n")

def delete_flow():
    # Colores (puedes ponerlos a "" si no los quieres)
    C_OK = "\033[92m"
    C_WARN = "\033[93m"
    C_ERR = "\033[91m"
    C_DIM = "\033[90m"
    C_TITLE = "\033[96m"
    C_RESET = "\033[0m"

    def hr():
        print(C_DIM + "─" * 72 + C_RESET)

    def print_rows(rows):
        if not rows:
            print(f"{C_DIM}No hay resultados.{C_RESET}")
            return
        print(f"{C_DIM}{'ID':>4}  {'ST':<5}  {'DOMINIO':<26}  {'TÍTULO':<28}{C_RESET}")
        print(C_DIM + "-" * 72 + C_RESET)
        for r in rows:
            rid = int(r["id"])
            st = (r["status"] or "-")[:5]
            dom = (r["domain"] or "-")[:26]
            title = (r["title"] or "-")
            title = (title[:28] + "…") if len(title) > 29 else title
            st_col = C_OK if st == "ok" else (C_WARN if st == "warn" else C_ERR if st == "error" else C_DIM)
            print(f"{rid:>4}  {st_col}{st:<5}{C_RESET}  {dom:<26}  {title:<28}")

    def parse_ids(s: str) -> list[int]:
        """
        Acepta:
          - "12"
          - "12,13,20"
          - "12 13 20"
          - "12-20"
          - mezcla: "1-3, 8, 10-12"
        """
        s = s.strip()
        if not s:
            return []
        parts = []
        for chunk in s.replace(",", " ").split():
            parts.append(chunk)

        out = set()
        for p in parts:
            if "-" in p:
                a, b = p.split("-", 1)
                if a.isdigit() and b.isdigit():
                    a, b = int(a), int(b)
                    if a <= b:
                        for x in range(a, b + 1):
                            out.add(x)
            else:
                if p.isdigit():
                    out.add(int(p))
        return sorted(out)

    while True:
        hr()
        print(f"{C_TITLE}GESTIÓN DE DB — BORRADO{C_RESET}")
        print(f"{C_DIM}Tip: busca por dominio/url/título y borra por ID (uno o varios).{C_RESET}")
        hr()
        print(f"{C_OK}[1]{C_RESET} Buscar y listar (últimos 25)")
        print(f"{C_OK}[2]{C_RESET} Mostrar últimos 25 (sin filtro)")
        print(f"{C_WARN}[3]{C_RESET} Borrar por ID(s)")
        print(f"{C_ERR}[0]{C_RESET} Volver")
        hr()

        opt = input("Opción: ").strip()

        if opt == "0":
            print()
            return

        elif opt == "1":
            q = input("Buscar (url/dominio/título): ").strip()
            rows = list_shops(limit=25, q=q)
            print()
            print_rows(rows)
            print()
            input(C_DIM + "Enter para continuar..." + C_RESET)

        elif opt == "2":
            rows = list_shops(limit=25, q="")
            print()
            print_rows(rows)
            print()
            input(C_DIM + "Enter para continuar..." + C_RESET)

        elif opt == "3":
            # Previsualiza para ayudar a elegir
            rows = list_shops(limit=25, q="")
            print()
            print(f"{C_DIM}Últimos 25 (referencia rápida):{C_RESET}")
            print_rows(rows)
            print()
            sids = input("IDs a borrar (ej: 12,15-18,22) o vacío para cancelar: ").strip()
            ids = parse_ids(sids)

            if not ids:
                print(f"\n{C_DIM}Cancelado.{C_RESET}\n")
                input(C_DIM + "Enter para continuar..." + C_RESET)
                continue

            print()
            hr()
            print(f"{C_WARN}Vas a borrar {len(ids)} registro(s) de shops{C_RESET} (y su tech + screenshots en DB).")
            print(f"{C_DIM}IDs:{C_RESET} {', '.join(map(str, ids))}")
            print(f"{C_ERR}Esta acción no se puede deshacer.{C_RESET}")
            hr()

            confirm = input("Escribe EXACTAMENTE 'DELETE' para confirmar: ").strip()
            if confirm != "DELETE":
                print(f"\n{C_DIM}Cancelado (no se confirmó).{C_RESET}\n")
                input(C_DIM + "Enter para continuar..." + C_RESET)
                continue

            deleted = 0
            not_found = 0
            for sid in ids:
                n = delete_shop_by_id(int(sid))
                if n:
                    deleted += 1
                else:
                    not_found += 1

            print(f"\n{C_OK}[✓]{C_RESET} Borrados: {deleted}")
            if not_found:
                print(f"{C_WARN}[!]{C_RESET} No encontrados: {not_found}")
            print()
            input(C_DIM + "Enter para continuar..." + C_RESET)

        else:
            print(f"\n{C_ERR}[!] Opción inválida.{C_RESET}\n")
            input(C_DIM + "Enter para continuar..." + C_RESET)

def open_dashboard_in_browser(host="127.0.0.1", port=8000):
    import subprocess
    import os

    url = f"http://{host}:{port}"

    # Si no hay sesión gráfica, no intentes abrir navegador
    if not os.environ.get("DISPLAY") and not os.environ.get("WAYLAND_DISPLAY"):
        print(f"[i] No hay entorno gráfico. Abre manualmente: {url}")
        return

    try:
        subprocess.Popen(
            ["xdg-open", url],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    except Exception:
        print(f"[i] No pude abrir el navegador automáticamente. Abre: {url}")

def main_menu():
    print_banner()
    init_db()

    host = "127.0.0.1"
    port = 8000
    dash_proc = None

    # Colores ANSI (si no los quieres, ponlos a "")
    C_TITLE = "\033[96m"
    C_OK = "\033[92m"
    C_WARN = "\033[93m"
    C_ERR = "\033[91m"
    C_DIM = "\033[90m"
    C_RESET = "\033[0m"

    def hr():
        print(C_DIM + "─" * 72 + C_RESET)

    def header():
        hr()
        print(f"{C_TITLE}SCRACHER{C_RESET}  {C_DIM}(.onion collector + dashboard local){C_RESET}")
        print(f"{C_DIM}Dashboard:{C_RESET} http://{host}:{port}   {C_DIM}DB:{C_RESET} data/scrs.db")
        hr()

    def menu_options():
        print(f"{C_OK}[1]{C_RESET} Escanear URLs (.onion)  {C_DIM}(pegar por consola, una por línea){C_RESET}")
        print(f"{C_OK}[2]{C_RESET} Abrir dashboard local   {C_DIM}(inicia y abre en navegador){C_RESET}")
        print(f"{C_OK}[3]{C_RESET} Escanear + dashboard    {C_DIM}(flujo completo){C_RESET}")
        print(f"{C_WARN}[4]{C_RESET} Gestionar DB (borrar)   {C_DIM}(elimina urls/tech/capturas en DB){C_RESET}")
        print(f"{C_ERR}[0]{C_RESET} Salir")
        hr()

    while True:
        header()
        menu_options()
        choice = input("Selecciona una opción: ").strip()

        if choice == "1":
            print(C_DIM + "\nModo escaneo: pega URLs .onion (una por línea). Enter vacío para terminar.\n" + C_RESET)
            urls = read_urls_multiline()
            run_scan(urls)
            input(C_DIM + "Pulsa Enter para volver al menú..." + C_RESET)

        elif choice == "2":
            dash_proc = start_dashboard(host, port)
            print(f"\n{C_OK}[✓]{C_RESET} Dashboard disponible en: http://{host}:{port}\n")
            open_dashboard_in_browser(host, port)
            input(C_DIM + "Pulsa Enter para volver al menú..." + C_RESET)

        elif choice == "3":
            print(C_DIM + "\nModo escaneo + dashboard: pega URLs .onion (una por línea). Enter vacío para terminar.\n" + C_RESET)
            urls = read_urls_multiline()
            run_scan(urls)
            dash_proc = start_dashboard(host, port)
            print(f"\n{C_OK}[✓]{C_RESET} Dashboard disponible en: http://{host}:{port}\n")
            open_dashboard_in_browser(host, port)
            input(C_DIM + "Pulsa Enter para volver al menú..." + C_RESET)

        elif choice == "4":
            delete_flow()
            input(C_DIM + "Pulsa Enter para volver al menú..." + C_RESET)

        elif choice == "0":
            hr()
            print(f"{C_DIM}Saliendo...{C_RESET}")
            hr()
            break

        else:
            print(f"\n{C_ERR}[!] Opción inválida.{C_RESET} Usa 0,1,2,3,4.\n")
            input(C_DIM + "Pulsa Enter para volver al menú..." + C_RESET)
