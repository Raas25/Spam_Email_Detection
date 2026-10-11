"""
Shared helpers: findings, evidence sanitizing, limits and decoding.
"""

import base64
import binascii
import re
import time
import unicodedata


# ---------------------------------------------------------
# Limits
# ---------------------------------------------------------

MAX_EMAIL_CHARS = 100_000
MAX_LINKS = 200
MAX_IMAGES = 10
MAX_ATTACHMENTS = 10
MAX_IMAGE_BYTES = 5 * 1024 * 1024
MAX_ATTACHMENT_BYTES = 5 * 1024 * 1024
MAX_HEADER_CHARS = 256 * 1024
MAX_EVIDENCE_CHARS = 300

# Whole /analyze request budget (seconds). Steps that would start
# after the deadline are skipped and reported as partial coverage.
ANALYSIS_TIME_BUDGET = 45.0


# ---------------------------------------------------------
# Severity and findings
# ---------------------------------------------------------

SEVERITY_POINTS = {
    "info": 0,
    "low": 5,
    "medium": 12,
    "high": 25,
    "critical": 40
}

SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]


# Invisible / direction-changing characters used to disguise text,
# e.g. "invoice‮fdp.exe" displays as "invoiceexe.pdf"
BIDI_CONTROL_CHARS = re.compile(
    "[​-‏‪-‮⁦-⁩﻿]"
)


def has_bidi_controls(text):
    return bool(BIDI_CONTROL_CHARS.search(text or ""))


def sanitize_evidence(text, limit=MAX_EVIDENCE_CHARS):
    """
    Make untrusted text safe to display as evidence:
    remove control and direction-changing characters,
    collapse whitespace and truncate.
    """

    text = "" if text is None else str(text)
    text = BIDI_CONTROL_CHARS.sub("", text)
    text = "".join(
        ch if unicodedata.category(ch)[0] != "C" else " "
        for ch in text
    )
    text = re.sub(r"\s+", " ", text).strip()

    if len(text) > limit:
        text = text[:limit - 1] + "…"

    return text


def finding(
    finding_id,
    category,
    severity,
    title,
    detail="",
    evidence=None
):
    """
    Build an explainable finding.
    finding_id groups repeated findings for scoring.
    """

    return {
        "id": finding_id,
        "category": category,
        "severity": severity,
        "title": title,
        "detail": detail,
        "evidence": sanitize_evidence(evidence) if evidence else None,
        "points": SEVERITY_POINTS[severity]
    }


def coverage(component, status, detail=""):
    """
    status: analyzed | partial | unavailable | not_applicable | skipped
    """

    return {
        "component": component,
        "status": status,
        "detail": detail
    }


# ---------------------------------------------------------
# Decoding
# ---------------------------------------------------------

def decode_base64_data(data):
    """
    Decode a base64 string (optionally a data: URL)
    into raw bytes. Returns None if invalid.
    """

    if not data:
        return None

    if "," in data and data.strip().startswith("data:"):
        data = data.split(",", 1)[1]

    try:
        return base64.b64decode(data, validate=True)
    except (binascii.Error, ValueError):
        return None


class Deadline:
    """Simple processing-time budget."""

    def __init__(self, seconds):
        self.end = time.monotonic() + seconds

    def expired(self):
        return time.monotonic() >= self.end

    def remaining(self):
        return max(0.0, self.end - time.monotonic())
