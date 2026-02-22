# SCRACHER (.onion) — Collector + Local Dashboard

SCRACHER es una herramienta en **Python** para recopilar información de **servicios .onion** a través de **Tor (SOCKS5)**, guardar resultados en **SQLite** y visualizarlo todo en un **dashboard local** (capturas + tecnologías detectadas).

> Uso responsable: utiliza esta herramienta solo para auditorías, investigación y análisis con autorización y cumpliendo leyes/políticas aplicables. No está diseñada para actividades ilícitas.

---

## Features
- ✅ Menú interactivo en consola (Linux)
- ✅ Soporte **.onion** via Tor (SOCKS5)
- ✅ Screenshot automático por objetivo (Playwright)
- ✅ Detección básica de tecnologías (headers + HTML heuristics)
- ✅ Persistencia en SQLite
- ✅ Dashboard local (FastAPI + templates)

---

## Requisitos
- Linux (recomendado)
- Python 3.10+
- Tor instalado y ejecutándose (proxy SOCKS)
- Dependencias del sistema para Playwright (varía por distro)

---

## Instalación rápida

```bash
git clone <TU_REPO>
cd scracher

python3 -m venv .venv
source .venv/bin/activate
pip install -U pip
pip install -r requirements.txt

playwright install
```

## Instalar y arrancar Tor (Debian/Ubuntu)

```bash
sudo apt update
sudo apt install -y tor
sudo systemctl enable --now tor
```

Verifica que el SOCKS está activo (normalmente 9050):
```bash
ss -lntp | grep 9050
```

## Uso

Ejecuta el programa:
```bash
source .venv/bin/activate
python3 main.py
```

En el menú:

[1] Escanear: pega una o más URLs .onion (una por línea) y Enter vacío para terminar.

[2] Abrir dashboard: inicia el dashboard y abre el navegador automáticamente (si hay GUI).

[3] Escanear + dashboard

[4] Gestión DB (borrar): elimina URLs por ID(s) de forma segura.

El dashboard queda en:

http://127.0.0.1:8000

## Configuración de Tor

El scraper usa SOCKS5 para acceder a .onion.

Tor system: 127.0.0.1:9050 (común)

Tor Browser: 127.0.0.1:9150

Si usas Tor Browser, cambia el puerto en el código o integra .env.

## Datos y rutas

DB (SQLite): data/scrs.db

Screenshots: dashboard/static/screenshots/

## Troubleshooting
1) .onion no responde / “Name or service not known”

Asegúrate de usar SOCKS con resolución remota (socks5h) en requests y que Tor esté activo.

2) Playwright falla en VM por librerías del sistema

En Ubuntu/Debian prueba:
```bash
sudo apt-get update
sudo apt-get install -y libnss3 libnspr4 libatk1.0-0 libatk-bridge2.0-0 libcups2 \
  libdrm2 libxkbcommon0 libxcomposite1 libxdamage1 libxfixes3 libxrandr2 libgbm1 \
  libpango-1.0-0 libcairo2 libasound2
```
