# SCRACHER v3

Plataforma de inteligencia en la dark web para recolección pasiva, análisis y monitorización de servicios .onion. Diseñada para flujos de trabajo de threat intelligence.

---

## Qué hace

SCRACHER rastrea sitios .onion a través de Tor, extrae datos estructurados y los presenta en un dashboard web local. Cada sitio se analiza en busca de stack tecnológico, direcciones de wallets de criptomonedas, palabras clave, dominios enlazados e indicadores de amenaza. Las capturas de pantalla se toman automáticamente usando un Firefox headless enrutado por SOCKS5.

El escáner funciona de forma asíncrona, transmite el progreso en tiempo real mediante SSE y re-escanea los sitios en intervalos configurables según su nivel de riesgo.

---

## Stack

- **Backend**: FastAPI + Uvicorn
- **Base de datos**: SQLite (vía `collector/db.py`)
- **Templates**: Jinja2
- **Capturas**: Playwright (Firefox) sobre Tor SOCKS5
- **OCR**: Tesseract
- **Threat Intel**: API de VirusTotal
- **Alertas**: Slack Webhooks, SMTP
- **Proxy**: Tor (`socks5h://127.0.0.1:9050`)

---

## Estructura del proyecto

```
scracherV3/
├── collector/
│   ├── alerts.py           # Envío de alertas Slack / email
│   ├── capture.py          # Capturas de pantalla (Playwright + Firefox)
│   ├── content_analyze.py  # Extracción de contenido y palabras clave
│   ├── crypto_extract.py   # Detección de wallets de criptomonedas
│   ├── db.py               # Esquema SQLite y consultas
│   ├── exporter.py         # Exportación JSON / CSV / HTML
│   ├── link_extract.py     # Recolección de enlaces descubiertos
│   ├── ocr_extract.py      # OCR con Tesseract sobre capturas
│   ├── run.py              # Orquestación del escaneo
│   ├── scheduler.py        # Planificación de re-escaneos
│   ├── scrape.py           # Núcleo de scraping HTTP + Tor
│   ├── tech_detect.py      # Fingerprinting del stack tecnológico
│   └── threat_intel.py     # Consultas a VirusTotal
├── dashboard/
│   ├── app.py              # Rutas FastAPI
│   ├── static/
│   │   └── screenshots/    # Capturas guardadas de los sitios
│   └── templates/
│       ├── layout.html
│       ├── index.html      # Listado de sitios y estadísticas
│       ├── shop.html       # Detalle de un sitio individual
│       ├── scan.html       # Vista de escaneo en tiempo real (SSE)
│       ├── discovered.html # Dominios enlazados descubiertos
│       ├── manage.html     # Gestión de la base de datos
│       ├── export.html     # Opciones de exportación
│       └── wallets.html    # Índice de wallets de criptomonedas
├── main.py                 # Punto de entrada CLI
├── requirements.txt
└── .env.example
```

---

## Instalación

**Requisitos**: Python 3.11+, Tor activo en el puerto 9050, Tesseract (opcional para OCR)

```bash
git clone https://github.com/Sparkhacky/scracher.git
cd scracher

pip install -r requirements.txt
playwright install firefox

cp .env.example .env
# Edita .env con tus claves API y configuración de alertas
```

Asegúrate de que Tor está activo antes de ejecutar:

```bash
sudo systemctl start tor
```

---

## Uso

**Iniciar el dashboard:**

```bash
cd dashboard
python3 -m uvicorn app:app --host 127.0.0.1 --port 8000
```

Abre `http://127.0.0.1:8000` en el navegador.

**Ejecutar un escaneo desde CLI:**

```bash
python3 main.py
```

---

## Configuración

Copia `.env.example` a `.env` y rellena los valores:

| Variable | Descripción |
|---|---|
| `TOR_SOCKS` | Dirección del proxy Tor (por defecto: `socks5h://127.0.0.1:9050`) |
| `VT_API_KEY` | Clave API de VirusTotal (tier gratuito: 4 req/min) |
| `SLACK_WEBHOOK_URL` | URL del Incoming Webhook de Slack |
| `SMTP_*` | Credenciales SMTP para alertas por email |
| `ALERT_MIN_LEVEL` | Nivel mínimo de riesgo para disparar alertas (`critical` / `high` / `medium`) |
| `ENABLE_OCR` | Activar OCR con Tesseract sobre las capturas |
| `ENABLE_THREAT_INTEL` | Activar consultas a VirusTotal |
| `RESCAN_*_H` | Intervalos de re-escaneo en horas por nivel de riesgo |

---

## Capturas de pantalla

SCRACHER usa **Playwright con Firefox** (no Chromium) para capturar sitios .onion. Firefox enruta correctamente la resolución DNS a través del proxy SOCKS5, lo cual es imprescindible para las direcciones `.onion`. Chromium resuelve el DNS localmente y falla de forma silenciosa.

Las capturas se guardan en `dashboard/static/screenshots/` y son servidas directamente por FastAPI.

---

## Notas

- Todo el escaneo es pasivo — sin explotación activa ni envío de formularios
- Diseñado para ejecutarse en local o en un servidor privado; no está pensado para exposición pública
- Las consultas a VirusTotal tienen límite de velocidad en el tier gratuito; esperar delays en escaneos masivos
- El OCR requiere `tesseract-ocr` y paquetes de idioma: `sudo apt install tesseract-ocr tesseract-ocr-eng tesseract-ocr-spa`

---

## Licencia

Ver `LICENSE`.
