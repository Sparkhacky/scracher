# SCRACHER v3 — .onion Threat Intelligence Collector

Herramienta de OSINT e inteligencia de amenazas para el análisis sistemático de servicios `.onion` a través de la red Tor. Diseñada para equipos de ciberseguridad, CERT, investigadores y analistas de inteligencia que necesitan monitorizar infraestructura en la dark web de forma automatizada y reproducible.

> ⚠️ **Uso exclusivamente legal y autorizado.** El uso de esta herramienta contra sistemas sin autorización expresa es ilegal. Está concebida para entornos de investigación, auditoría interna, inteligencia de amenazas y apoyo a fuerzas del orden.

---

## Qué hace SCRACHER

Dado un listado de URLs `.onion`, SCRACHER las visita a través de Tor, captura una screenshot, extrae el contenido y lo analiza en múltiples capas:

- **Detección de tecnologías** con versión exacta (servidor, CMS, frameworks, lenguajes)
- **Análisis de amenazas** mediante 70+ keywords en 8 categorías con severidad ponderada
- **Risk scoring** de 0 a 1 con clasificación automática en 5 niveles
- **Extracción de wallets** crypto (BTC, XMR, ETH, LTC) con enlace directo a block explorers
- **Correlación externa** via VirusTotal y URLhaus
- **OCR** sobre screenshots para indexar texto en imágenes
- **Descubrimiento de links** `.onion` adicionales para crawl en cascada
- **Alertas automáticas** por Slack y email según umbral de riesgo configurable
- **Re-escaneo periódico** programado por nivel de riesgo

Todo se gestiona desde un **dashboard local** en el navegador. El terminal es solo un lanzador.

---

## Novedades v3

| Funcionalidad | v2 | v3 |
|---|---|---|
| Escaneo .onion + screenshot + tech | ✅ | ✅ |
| Risk scoring + keywords + tags | ✅ | ✅ |
| Dashboard FastAPI | ✅ | ✅ mejorado |
| Exportación JSON / CSV / HTML | ✅ | ✅ |
| **Versión de cada tecnología detectada** | ❌ | ✅ |
| **Extracción de wallets crypto** | ❌ | ✅ |
| **Correlación VirusTotal + URLhaus** | ❌ | ✅ |
| **OCR en screenshots** | ❌ | ✅ |
| **Alertas Slack + email** | ❌ | ✅ |
| **Re-escaneo automático por riesgo** | ❌ | ✅ |
| **Escaneo en tiempo real desde el dashboard** | ❌ | ✅ |
| **Gestión de DB desde el dashboard** | ❌ | ✅ |
| **Exportación con descarga directa** | ❌ | ✅ |
| **Crawl de links descubiertos desde dashboard** | ❌ | ✅ |

---

## Arquitectura

```
scracher/
├── main.py                         # Lanzador: arranca Tor, DB, scheduler y dashboard
├── requirements.txt
├── .env.example
├── collector/
│   ├── scrape.py                   # Fetcher principal — orquesta todos los módulos
│   ├── tech_detect.py              # 40+ firmas, extrae versión exacta de cada tech
│   ├── content_analyze.py          # 70+ keywords, 8 categorías, risk scoring 0-1
│   ├── crypto_extract.py           # Wallets BTC / XMR / ETH / LTC
│   ├── threat_intel.py             # VirusTotal API v3 + URLhaus
│   ├── ocr_extract.py              # Tesseract OCR sobre screenshots
│   ├── alerts.py                   # Notificaciones Slack + SMTP
│   ├── scheduler.py                # APScheduler — re-escaneo por nivel de riesgo
│   ├── link_extract.py             # Descubrimiento de links .onion
│   ├── exporter.py                 # JSON / CSV / HTML forense
│   ├── capture.py                  # Screenshot via Playwright + Tor
│   ├── db.py                       # SQLite schema v3 + funciones de acceso
│   └── dashboard_launcher.py
└── dashboard/
    ├── app.py                      # FastAPI — toda la funcionalidad operativa
    └── templates/
        ├── layout.html             # Navbar + stats globales
        ├── index.html              # Grid de sitios con filtros
        ├── scan.html               # Escaneo en tiempo real (SSE)
        ├── shop.html               # Detalle: tech+versión, keywords, wallets, OCR
        ├── wallets.html            # Vista de wallets con block explorers
        ├── discovered.html         # Links .onion descubiertos
        ├── manage.html             # Gestión de DB (eliminar, buscar, filtrar)
        └── export.html             # Exportación y descarga de informes
```

---

## Instalación

### Requisitos del sistema

```bash
sudo apt update && sudo apt install -y \
  tor \
  tesseract-ocr tesseract-ocr-spa tesseract-ocr-rus \
  libnss3 libnspr4 libatk1.0-0 libatk-bridge2.0-0 libcups2 \
  libdrm2 libxkbcommon0 libxcomposite1 libxdamage1 libxfixes3 \
  libxrandr2 libgbm1 libpango-1.0-0 libcairo2 libasound2
```

### Instalación del proyecto

```bash
git clone https://github.com/TU_USUARIO/scracher.git
cd scracher

python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
playwright install chromium

mkdir -p data dashboard/static/screenshots
cp .env.example .env
```

### Configuración

Edita `.env` con tus credenciales:

```env
TOR_SOCKS=socks5h://127.0.0.1:9050

# VirusTotal (gratuito — 4 req/min)
VT_API_KEY=

# Alertas Slack
SLACK_WEBHOOK_URL=

# Alertas email
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=
SMTP_PASS=
SMTP_FROM=
SMTP_TO=

# Umbrales y configuración
ALERT_MIN_LEVEL=high           # critical / high / medium
ENABLE_OCR=true
ENABLE_THREAT_INTEL=true
OCR_LANGS=eng+spa+rus

# Intervalos de re-escaneo (horas)
RESCAN_CRITICAL_H=6
RESCAN_HIGH_H=12
RESCAN_MEDIUM_H=24
RESCAN_LOW_H=48
```

Las API keys de VirusTotal y Slack son opcionales. La herramienta funciona sin ellas.

---

## Uso

```bash
source .venv/bin/activate
sudo systemctl start tor
python3 main.py
```

El lanzador arranca el dashboard automáticamente y abre el navegador en `http://127.0.0.1:8000`. A partir de ahí, todo se gestiona desde el browser.

### Flujo de investigación recomendado

```
1. Dashboard → Escanear → pegar lista de .onion → iniciar
2. Revisar resultados en tiempo real según van llegando
3. Dashboard → Sitios → filtrar por CRITICAL / HIGH
4. Entrar en cada sitio: tech+versión, keywords, wallets, OCR
5. Dashboard → Links → crawlear los .onion descubiertos
6. Dashboard → Exportar → HTML forense para entrega a LEA / CERT
```

---

## Categorías de amenaza

| Categoría | Severidad | Ejemplos |
|---|---|---|
| exploitation | CRITICAL | CSAM, trafficking, underage |
| violence | CRITICAL | hitman, murder for hire, assassination |
| weapons (WMD) | CRITICAL | ricin, sarin, dirty bomb, explosives |
| drugs | HIGH | cocaine, heroin, fentanyl, meth |
| weapons | HIGH | firearms, glock, silencer, assault rifle |
| fraud | HIGH | carding, fullz, money laundering, bank logs |
| cybercrime | HIGH | ransomware, botnet, zero-day, exploit kit |
| counterfeit | MEDIUM | fake id, fake passport, forged documents |
| opsec | LOW | monero, pgp, anonymous, darknet |

---

## Detección de tecnologías y versiones

SCRACHER extrae la versión exacta de cada tecnología detectada consultando múltiples fuentes en orden de fiabilidad: headers HTTP, meta generator, atributos `data-*`, nombres de fichero en scripts/CSS y variables JavaScript embebidas.

Ejemplos de lo que extrae automáticamente:

- `Nginx 1.24.0` — header `Server`
- `PHP 8.2.11` — header `X-Powered-By`
- `WordPress 6.4.2` — `<meta name="generator">`
- `jQuery 3.7.1` — nombre del fichero JS
- `React 18.2.0` — parámetro `?v=` en src del script
- `Angular 16.2.0` — atributo `ng-version` en el DOM
- `reCAPTCHA v3` — patrón de integración en el HTML

---

## API REST

```
GET  /api/stats            → estadísticas globales
GET  /api/export           → export completo en JSON
GET  /api/wallets          → wallets extraídas (filtrables por coin)
GET  /api/threats/top      → top keywords de amenaza
GET  /api/scan/status      → estado del escaneo en curso
POST /scan/start           → iniciar escaneo (body: {urls, threat_intel})
POST /scan/crawl           → crawlear links descubiertos
POST /api/delete           → eliminar sitios por ID
POST /api/export/{fmt}     → generar export (json/csv/html/all)
```

---

## Troubleshooting

**`.onion no responde`** — verifica que Tor esté activo:
```bash
ss -lntp | grep 9050
sudo systemctl start tor
```

**`Playwright falla en VM headless`** — instala las dependencias del sistema listadas arriba. El escaneo continúa sin screenshot si Playwright no puede capturar.

**`Doble proxy / warnings de torsocks`** — ejecuta directamente con `python3 main.py`, sin anteponer `torsocks`. El cliente ya usa `socks5h://` internamente.

**`APScheduler: job not serializable`** — borra `data/scheduler.db` para limpiar jobs de versiones anteriores:
```bash
rm data/scheduler.db
```

**`Error 500 en dashboard`** — si la DB es de una versión anterior, ejecuta la migración:
```bash
sqlite3 data/scrs.db "
  ALTER TABLE shops ADD COLUMN external_risk TEXT DEFAULT 'unknown';
  CREATE TABLE IF NOT EXISTS wallets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    shop_id INTEGER NOT NULL, coin TEXT, address TEXT, addr_type TEXT
  );
  CREATE TABLE IF NOT EXISTS alert_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    shop_id INTEGER, channel TEXT, risk_level TEXT,
    sent INTEGER DEFAULT 0, reason TEXT, sent_at TEXT
  );
"
```

---

## Contexto y comparativa

SCRACHER no compite con plataformas comerciales como Recorded Future o DarkOwl. Cubre el espacio entre los scripts sueltos y las herramientas enterprise: es reproducible, extensible, no requiere suscripción y puedes auditarla entera.

| Herramienta | Categoría |
|---|---|
| OnionScan | Reconocimiento pasivo de .onion |
| SpiderFoot | OSINT automatizado |
| Maltego + Tor plugins | Análisis de grafos |
| **SCRACHER v3** | Threat intelligence + crypto tracing + alerting |

---

## Licencia

MIT — úsala, modifícala y compártela. Con cabeza.
