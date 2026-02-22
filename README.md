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
