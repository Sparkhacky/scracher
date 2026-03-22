"""
SCRACHER v3 — OCR Extractor
Aplica Tesseract OCR a screenshots para extraer texto visible.
Requiere: sudo apt install tesseract-ocr tesseract-ocr-spa tesseract-ocr-rus
         pip install pytesseract Pillow
"""

import os
from pathlib import Path

ROOT     = Path(__file__).resolve().parents[1]
SHOT_DIR = ROOT / "dashboard" / "static" / "screenshots"

# Intentar importar dependencias OCR (opcionales)
try:
    from PIL import Image
    import pytesseract
    OCR_AVAILABLE = True
except ImportError:
    OCR_AVAILABLE = False

# Idiomas Tesseract disponibles (instalar según necesidad)
# eng+spa+rus cubre la mayoría de dark web
OCR_LANGS = os.getenv("OCR_LANGS", "eng+spa+rus")


def ocr_screenshot(rel_path: str) -> dict:
    """
    Extrae texto de un screenshot via Tesseract OCR.
    rel_path: ruta relativa como 'screenshots/domain_20240101.png'
    Devuelve dict con text, confidence, available.
    """
    if not OCR_AVAILABLE:
        return {
            "available": False,
            "error": "pytesseract/Pillow no instalado. "
                     "Ejecuta: pip install pytesseract Pillow && "
                     "sudo apt install tesseract-ocr",
            "text": "",
        }

    abs_path = SHOT_DIR / Path(rel_path).name
    if not abs_path.exists():
        return {"available": True, "error": f"Fichero no encontrado: {abs_path}", "text": ""}

    try:
        img = Image.open(abs_path)

        # Preprocesar para mejorar OCR: convertir a escala de grises
        img_gray = img.convert("L")

        # Extraer texto
        text = pytesseract.image_to_string(
            img_gray,
            lang=_available_langs(),
            config="--psm 3",  # página completa, orientación automática
        )

        # Extraer datos de confianza
        data = pytesseract.image_to_data(
            img_gray,
            lang=_available_langs(),
            output_type=pytesseract.Output.DICT,
        )
        confidences = [int(c) for c in data.get("conf", []) if str(c).isdigit() and int(c) > 0]
        avg_conf = sum(confidences) / len(confidences) if confidences else 0

        text_clean = text.strip()

        return {
            "available":    True,
            "text":         text_clean,
            "char_count":   len(text_clean),
            "word_count":   len(text_clean.split()),
            "confidence":   round(avg_conf, 1),
            "lang_used":    _available_langs(),
        }

    except Exception as e:
        return {"available": True, "error": str(e), "text": ""}


def _available_langs() -> str:
    """Verifica qué idiomas Tesseract tiene instalados y filtra."""
    if not OCR_AVAILABLE:
        return "eng"
    try:
        installed = pytesseract.get_languages()
        wanted = OCR_LANGS.split("+")
        available = [l for l in wanted if l in installed]
        return "+".join(available) if available else "eng"
    except Exception:
        return "eng"


def ocr_check_status() -> dict:
    """Comprueba si OCR está disponible y qué idiomas hay instalados."""
    if not OCR_AVAILABLE:
        return {"available": False, "libs": "pytesseract/Pillow no instalados"}
    try:
        langs = pytesseract.get_languages()
        version = pytesseract.get_tesseract_version()
        return {
            "available": True,
            "version":   str(version),
            "languages": langs,
        }
    except Exception as e:
        return {"available": False, "error": str(e)}
