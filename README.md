# SCRACHER v2 — .onion Threat Intelligence Collector

Herramienta de **OSINT e inteligencia de amenazas** para auditoría, investigación y análisis de **servicios .onion** a través de la red Tor.

> ⚠️ **Uso exclusivamente legal y autorizado.** Diseñada para CERT, equipos de ciberseguridad, investigadores y fuerzas del orden. No está diseñada para actividades ilícitas.

---

## Qué hay de nuevo en v2

| Funcionalidad                     | v1 | v2 |
|-----------------------------------|----|----|
| Escaneo .onion via Tor            | ✅ | ✅ |
| Screenshot automático             | ✅ | ✅ |
| Detección de tecnologías          | ✅ | ✅ (+40 firmas) |
| Dashboard local FastAPI           | ✅ | ✅ (mejorado) |
| **Análisis de amenazas (keywords)** | ❌ | ✅ |
| **Risk scoring 0-1**              | ❌ | ✅ |
| **Clasificación por nivel** (critical/high/medium/low/clean) | ❌ | ✅ |
| **Tags automáticos** (drugs/fraud/cybercrime...) | ❌ | ✅ |
| **Descubrimiento automático de links .onion** | ❌ | ✅ |
| **Crawl de links descubiertos**   | ❌ | ✅ |
| **Content hash** (detectar cambios) | ❌ | ✅ |
| **Detección de idioma**           | ❌ | ✅ |
| **Importar URLs desde fichero**   | ❌ | ✅ |
| **Exportación JSON / CSV / HTML** | ❌ | ✅ |
| **Informe forense HTML**          | ❌ | ✅ |
| **Estadísticas en tiempo real**   | ❌ | ✅ |
| **API REST** (/api/stats, /api/export, /api/threats/top) | ❌ | ✅ |
| Dashboard: filtro por riesgo      | ❌ | ✅ |
| Dashboard: vista de keywords      | ❌ | ✅ |
| Dashboard: links descubiertos     | ❌ | ✅ |
| Reintentos HTTP automáticos       | ❌ | ✅ |
| WAL mode + FK en SQLite           | ❌ | ✅ |

---

## Arquitectura

```
scracher/
├── main.py
├── requirements.txt
├── collector/
│   ├── run.py              # CLI menu (v2)
│   ├── scrape.py           # Fetcher con retry + hash
│   ├── tech_detect.py      # Detector de tecnologías (40+ firmas)
│   ├── content_analyze.py  # ★ NUEVO: análisis de amenazas + risk scoring
│   ├── link_extract.py     # ★ NUEVO: extractor de links .onion
│   ├── exporter.py         # ★ NUEVO: JSON / CSV / HTML report
│   ├── capture.py          # Screenshot via Playwright + Tor
│   ├── dashboard_launcher.py
│   └── db.py               # SQLite schema v2 (ampliado)
├── dashboard/
│   ├── app.py              # FastAPI (mejorado)
│   └── templates/
│       ├── layout.html     # Stats bar + nav
│       ├── index.html      # Grid con risk badges + filtro de riesgo
│       ├── shop.html       # Detalle: keywords + links + tech + historial
│       └── discovered.html # ★ NUEVA: tabla de links descubiertos
└── data/
    ├── scrs.db             # SQLite (auto-creada)
    └── exports/            # JSON / CSV / HTML exportados
```

---

## Base de datos v2

**Nueva tabla `threat_keywords`**: keywords peligrosas detectadas, categorizadas y con severidad.

**Nueva tabla `tags`**: etiquetas de categoría (drugs, fraud, cybercrime...).

**Nueva tabla `discovered_links`**: links .onion encontrados durante escaneos, con estado pendiente/escaneado.

**Nuevas columnas en `shops`**: `risk_score`, `risk_level`, `content_hash`, `scan_count`, `last_scanned`, `language`.

---

## Categorías de amenaza detectadas

| Categoría       | Severidad   | Ejemplos                                      |
|-----------------|-------------|-----------------------------------------------|
| exploitation    | CRITICAL    | CSAM, underage, trafficking                   |
| violence        | CRITICAL    | hitman, murder for hire, assassination        |
| weapons (WMD)   | CRITICAL    | ricin, sarin, explosives, dirty bomb          |
| drugs           | HIGH        | cocaine, heroin, fentanyl, mdma, meth         |
| weapons         | HIGH        | firearms, glock, silencer, assault rifle      |
| fraud           | HIGH        | carding, fullz, money laundering, bank logs   |
| cybercrime      | HIGH        | ransomware, botnet, zero-day, exploit kit     |
| counterfeit     | MEDIUM      | fake id, fake passport, forged documents      |
| drugs (soft)    | MEDIUM      | cannabis, weed                                |
| opsec           | LOW         | monero, pgp, anonymous, darknet               |

---

## Instalación

```bash
git clone <REPO>
cd scracher

python3 -m venv .venv
source .venv/bin/activate
pip install -U pip
pip install -r requirements.txt
playwright install
```

### Instalar Tor (Debian/Ubuntu)

```bash
sudo apt update && sudo apt install -y tor
sudo systemctl enable --now tor
ss -lntp | grep 9050   # verificar
```

---

## Uso

```bash
source .venv/bin/activate
python3 main.py
```

### Menú v2

```
[1] Escanear URLs .onion       → entrada manual
[2] Escanear desde fichero     → una URL por línea (ideal para lotes grandes)
[3] Crawl links descubiertos   → escanea automáticamente los .onion encontrados
[4] Dashboard local            → http://127.0.0.1:8000
[5] Estadísticas rápidas       → resumen de riesgo en consola
[6] Exportar                   → JSON / CSV / HTML informe forense
[7] Gestionar DB               → borrar por ID, buscar, rangos
[0] Salir
```

### Flujo recomendado para investigación

```
1. [2] Cargar lista de .onion sospechosos desde fichero
2. Revisar resultados: [5] estadísticas
3. [3] Crawl automático de links descubiertos
4. [4] Dashboard → filtrar por CRITICAL/HIGH → revisar keywords
5. [6] Exportar informe HTML para entrega a LEA/CERT
```

---

## API REST

El dashboard expone endpoints JSON para integración con otras herramientas:

```
GET /api/stats                  → estadísticas globales
GET /api/export                 → export completo (JSON)
GET /api/threats/top            → top keywords de amenaza
```

---

## Exportación / Informes

- **JSON**: datos completos con tech, keywords, tags, links — para análisis SIEM/programático
- **CSV**: tabla plana para Excel/LibreOffice
- **HTML**: informe forense legible, con tabla de amenazas y estadísticas — apto para entrega a autoridades

Exportados en `data/exports/`.

---

## Troubleshooting

**`.onion no responde`**: verifica que Tor esté activo (`ss -lntp | grep 9050`) y que la URL sea correcta.

**`Playwright falla`** (VM/headless):
```bash
sudo apt-get install -y libnss3 libnspr4 libatk1.0-0 libatk-bridge2.0-0 libcups2 \
  libdrm2 libxkbcommon0 libxcomposite1 libxdamage1 libxfixes3 libxrandr2 libgbm1 \
  libpango-1.0-0 libcairo2 libasound2
```

**Screenshots sin DISPLAY**: el scraper continúa funcionando (requests+análisis). Solo falla la captura visual.

**Tor Browser (puerto 9150)**: cambia `TOR_SOCKS` en `scrape.py` y `TOR_PROXY` en `capture.py`.
