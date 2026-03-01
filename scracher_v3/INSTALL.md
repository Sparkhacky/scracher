# SCRACHER v3 — Guía de instalación en Linux VM

## 1. Dependencias del sistema

```bash
sudo apt update

# Base
sudo apt install -y python3 python3-pip python3-venv git tor

# OCR (opcional pero recomendado)
sudo apt install -y tesseract-ocr tesseract-ocr-spa tesseract-ocr-rus tesseract-ocr-eng

# Playwright (Chromium headless)
sudo apt install -y libnss3 libnspr4 libatk1.0-0 libatk-bridge2.0-0 libcups2 \
  libdrm2 libxkbcommon0 libxcomposite1 libxdamage1 libxfixes3 libxrandr2 \
  libgbm1 libpango-1.0-0 libcairo2 libasound2
```

## 2. Tor

```bash
sudo systemctl enable --now tor
ss -lntp | grep 9050   # debe mostrar el puerto activo
```

## 3. Entorno Python

```bash
cd scracher_v3
python3 -m venv .venv
source .venv/bin/activate

pip install -U pip
pip install -r requirements.txt

# OCR (opcional)
pip install pytesseract Pillow

# Playwright
playwright install chromium
```

## 4. Configuración

```bash
cp .env.example .env
nano .env
# Rellena: VT_API_KEY, SLACK_WEBHOOK_URL, SMTP_*, etc.
```

## 5. Ejecutar

```bash
source .venv/bin/activate
python3 main.py
```

## APIs y claves

| Servicio      | Coste       | URL                                          |
|---------------|-------------|----------------------------------------------|
| VirusTotal    | Gratuito    | https://www.virustotal.com/gui/sign-in       |
| URLhaus       | Gratuito    | No requiere clave                            |
| Slack Webhook | Gratuito    | https://api.slack.com/messaging/webhooks     |
| Gmail SMTP    | Gratuito    | Genera "App Password" en tu cuenta Google    |

## Verificar OCR

```bash
python3 -c "from collector.ocr_extract import ocr_check_status; import json; print(json.dumps(ocr_check_status(), indent=2))"
```

## Scheduler

El scheduler de re-escaneo se inicia automáticamente al lanzar `main.py`.
Los jobs persisten en `data/scheduler.db` entre reinicios.
Intervalos configurables en `.env` (RESCAN_*_H).
