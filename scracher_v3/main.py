"""
SCRACHER v3 — Lanzador
El dashboard en http://127.0.0.1:8000 contiene toda la funcionalidad.
"""
import os, sys, socket, subprocess, webbrowser
from pathlib import Path
from time import sleep

ROOT = Path(__file__).resolve().parent

R  = "\033[0m";  CY = "\033[96m"; GR = "\033[92m"
GY = "\033[90m"; RD = "\033[91m"; B  = "\033[1m"

def port_open(host, port):
    with socket.socket() as s:
        s.settimeout(0.3)
        return s.connect_ex((host, port)) == 0

def banner():
    os.system("clear")
    print(f"""
{CY}{B}  ██████  ██████ ██████   █████  ██████ ██   ██ ███████ ██████
  ██      ██     ██   ██ ██   ██ ██     ██   ██ ██      ██   ██
  ███████ ██     ██████  ███████ ██     ███████ █████   ██████
       ██ ██     ██   ██ ██   ██ ██     ██   ██ ██      ██   ██
  ██████  ██████ ██   ██ ██   ██ ██████ ██   ██ ███████ ██   ██{R}

  {GY}.onion Collector  ·  Threat Intelligence  ·  Crypto Tracer  ·  v3.0{R}
""")

def main():
    # Cargar .env
    env = ROOT / ".env"
    if env.exists():
        try:
            from dotenv import load_dotenv
            load_dotenv(env)
        except ImportError:
            pass

    HOST, PORT = "127.0.0.1", 8000
    banner()

    # Inicializar DB
    sys.path.insert(0, str(ROOT))
    try:
        from collector.db import init_db
        init_db()
        print(f"  {GR}✓{R}  Base de datos lista")
    except Exception as e:
        print(f"  {RD}✗{R}  DB error: {e}")

    # Arrancar Tor (si no está corriendo)
    if not port_open("127.0.0.1", 9050):
        print(f"  {GY}⚡{R}  Iniciando Tor...")
        subprocess.Popen(["tor"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        sleep(2)
    else:
        print(f"  {GR}✓{R}  Tor activo en :9050")

    # Arrancar scheduler en background
    try:
        from collector.scheduler import start_scheduler
        if start_scheduler():
            print(f"  {GR}✓{R}  Scheduler de re-escaneo activo")
    except Exception:
        pass

    # Arrancar dashboard
    if port_open(HOST, PORT):
        print(f"  {GY}→{R}  Dashboard ya corriendo en http://{HOST}:{PORT}")
    else:
        print(f"  {GY}⚡{R}  Iniciando dashboard...")
        proc = subprocess.Popen(
            [sys.executable, "-m", "uvicorn", "dashboard.app:app",
             "--host", HOST, "--port", str(PORT)],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, cwd=str(ROOT)
        )
        for _ in range(40):
            if port_open(HOST, PORT): break
            sleep(0.25)
        if port_open(HOST, PORT):
            print(f"  {GR}✓{R}  {B}Dashboard listo → http://{HOST}:{PORT}{R}")
        else:
            print(f"  {RD}✗{R}  No se pudo iniciar el dashboard")
            return

    # Abrir browser
    url = f"http://{HOST}:{PORT}"
    try:
        webbrowser.open(url)
        print(f"  {GR}✓{R}  Abriendo browser...")
    except Exception:
        pass

    print(f"""
  {GY}{'─'*50}{R}
  {CY}Todo se gestiona desde el browser:{R}
  {B}  http://{HOST}:{PORT}{R}

  {GY}Ctrl+C para detener{R}
  {GY}{'─'*50}{R}
""")

    try:
        while True:
            sleep(1)
    except KeyboardInterrupt:
        print(f"\n  {GY}Deteniendo...{R}")
        try:
            from collector.scheduler import stop_scheduler
            stop_scheduler()
        except Exception:
            pass
        print(f"  {GR}✓{R}  Hasta luego.\n")

if __name__ == "__main__":
    main()
