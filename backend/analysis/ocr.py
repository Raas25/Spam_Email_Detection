"""
Optional OCR for text inside images.

Engines, in order of preference:
  1. RapidOCR (pip install -r requirements-ocr.txt), runs on CPU
     with ONNX Runtime; models are downloaded on first use.
  2. Tesseract via pytesseract, if the tesseract binary is installed.

If neither is available, OCR is reported as unavailable; nothing
is faked.
"""

import os
import threading


MAX_OCR_CHARS = 5000

# Set SPAM_CHECKER_DISABLE_OCR=1 to turn OCR off (e.g. in tests)
DISABLED = os.environ.get("SPAM_CHECKER_DISABLE_OCR") == "1"

_engine = None
_engine_name = None
_engine_error = None
_lock = threading.Lock()


def _load_engine():
    global _engine, _engine_name, _engine_error

    if _engine is not None or _engine_error is not None:
        return

    if DISABLED:
        _engine_error = "OCR is disabled (SPAM_CHECKER_DISABLE_OCR=1)."
        return

    try:
        import logging

        from rapidocr import RapidOCR

        logging.getLogger("RapidOCR").setLevel(logging.WARNING)

        _engine = RapidOCR()
        _engine_name = "RapidOCR"
        return
    except Exception as error:  # noqa: BLE001 - any import/init failure
        rapid_error = error

    try:
        import pytesseract

        pytesseract.get_tesseract_version()
        _engine = pytesseract
        _engine_name = "Tesseract"
        return
    except Exception as error:  # noqa: BLE001
        tesseract_error = error

    _engine_error = (
        "No OCR engine installed. Install backend/requirements-ocr.txt "
        f"(RapidOCR: {type(rapid_error).__name__}) or Tesseract "
        f"({type(tesseract_error).__name__})."
    )


def status():
    """Return (available, engine_name_or_error) without running OCR."""

    with _lock:
        _load_engine()

    if _engine is not None:
        return True, _engine_name

    return False, _engine_error


def extract_text(img):
    """
    Run OCR on a loaded OpenCV image.
    Returns the recognised text (possibly empty), or None if OCR
    is unavailable.
    """

    with _lock:
        _load_engine()

        if _engine is None:
            return None

        if _engine_name == "RapidOCR":
            result = _engine(img)
            lines = list(result.txts or []) if result is not None else []
            text = "\n".join(lines)
        else:
            import cv2

            rgb = cv2.cvtColor(img, cv2.COLOR_BGR2RGB)
            text = _engine.image_to_string(rgb, timeout=15)

    return text.strip()[:MAX_OCR_CHARS]
