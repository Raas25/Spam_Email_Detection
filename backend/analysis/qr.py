"""
QR code decoding with OpenCV.
"""

import re

import cv2
import numpy as np

from .text_model import contains_any_word, CREDENTIAL_WORDS, URL_PATTERN
from .urls import get_url_indicators


# Largest image side processed; bigger images are downscaled first
# to bound processing time.
MAX_IMAGE_SIDE = 2500

qr_detector = cv2.QRCodeDetector()

# Finds codes the default detector misses when an
# image contains several QR codes
qr_detector_aruco = cv2.QRCodeDetectorAruco()


def load_image(img_bytes):
    """Decode image bytes with OpenCV (no other parser is used)."""

    img = cv2.imdecode(
        np.frombuffer(img_bytes, dtype=np.uint8),
        cv2.IMREAD_COLOR
    )

    if img is None:
        return None

    height, width = img.shape[:2]
    scale = MAX_IMAGE_SIDE / max(height, width)

    if scale < 1:
        img = cv2.resize(img, None, fx=scale, fy=scale, interpolation=cv2.INTER_AREA)

    return img


def detect_qr_texts(img):
    texts = []

    for detector in (qr_detector, qr_detector_aruco):
        try:
            found, decoded, _, _ = detector.detectAndDecodeMulti(img)
            if found:
                texts.extend(decoded)
        except cv2.error:
            pass

    if not any(texts):
        try:
            data, _, _ = qr_detector.detectAndDecode(img)
            texts.append(data)
        except cv2.error:
            pass

    return [text for text in texts if text]


def decode_qr_image(img):
    """
    Decode every QR code in an already-loaded image.
    Retries on grayscale and on a 2x upscale for small codes.
    """

    gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)

    attempts = [img, gray]

    if max(gray.shape[:2]) <= MAX_IMAGE_SIDE // 2:
        attempts.append(cv2.resize(
            gray,
            None,
            fx=2,
            fy=2,
            interpolation=cv2.INTER_CUBIC
        ))

    for attempt in attempts:
        texts = detect_qr_texts(attempt)
        if texts:
            # Unique, order preserved
            return list(dict.fromkeys(texts))

    return []


def decode_qr_codes(img_bytes):
    """
    Decode every QR code in image bytes.
    Returns None if the bytes are not a readable image.
    """

    img = load_image(img_bytes)

    if img is None:
        return None

    return decode_qr_image(img)


def get_qr_type(text):
    lower = text.strip().lower()

    if re.match(URL_PATTERN, lower):
        return "url"
    if lower.startswith("mailto:"):
        return "email"
    if lower.startswith("tel:"):
        return "phone"
    if lower.startswith(("sms:", "smsto:")):
        return "sms"
    if lower.startswith("wifi:"):
        return "wifi"
    return "text"


def analyze_qr_payload(text):
    qr_type = get_qr_type(text)

    indicators = []

    if qr_type == "url":
        indicators = get_url_indicators(text.strip())
    elif contains_any_word(text.lower(), CREDENTIAL_WORDS):
        indicators.append("Possible credential or personal-information request")

    return {
        "content": text,
        "type": qr_type,
        "indicators": indicators
    }
