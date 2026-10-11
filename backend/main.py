from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from typing import List, Optional
import os

from analysis import ocr
from analysis.common import (
    decode_base64_data,
    MAX_ATTACHMENTS,
    MAX_EMAIL_CHARS,
    MAX_IMAGE_BYTES,
    MAX_IMAGES,
    MAX_LINKS,
)
from analysis.engine import analyze_email, ENGINE_VERSION
from analysis.qr import analyze_qr_payload, decode_qr_codes
from analysis.text_model import metadata, predict_text


# ---------------------------------------------------------
# Configuration
# ---------------------------------------------------------

MAX_QR_IMAGES = 10
MAX_QR_IMAGE_BYTES = MAX_IMAGE_BYTES

# Largest accepted request body (images and attachments are base64)
MAX_REQUEST_BYTES = 80 * 1024 * 1024

# Web page served locally (any port) and Gmail (content script).
# The extension's service worker is not subject to CORS.
ALLOWED_ORIGIN_REGEX = r"https?://(localhost|127\.0\.0\.1)(:\d+)?"
ALLOWED_ORIGINS = ["https://mail.google.com"]


# ---------------------------------------------------------
# FastAPI application
# ---------------------------------------------------------

app = FastAPI(
    title="Spam Email Checker API",
    description="AI-powered spam and phishing email detection API",
    version=ENGINE_VERSION
)


# ---------------------------------------------------------
# CORS
# ---------------------------------------------------------

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_origin_regex=ALLOWED_ORIGIN_REGEX,
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type"],
)


# ---------------------------------------------------------
# Request size limit
# ---------------------------------------------------------

@app.middleware("http")
async def limit_request_size(request: Request, call_next):
    length = request.headers.get("content-length")

    if length and length.isdigit() and int(length) > MAX_REQUEST_BYTES:
        return JSONResponse(
            status_code=413,
            content={"detail": "Request is too large."}
        )

    return await call_next(request)


# ---------------------------------------------------------
# Request schema
# ---------------------------------------------------------

class EmailRequest(BaseModel):
    subject: str = ""
    body: str = ""


class QRImage(BaseModel):
    id: str = ""
    data: str


class QRScanRequest(BaseModel):
    images: List[QRImage]


class Sender(BaseModel):
    name: str = Field("", max_length=500)
    email: str = Field("", max_length=320)


class MessageContent(BaseModel):
    subject: str = Field("", max_length=2000)
    body_text: str = ""
    hidden_text: str = ""
    sender: Optional[Sender] = None
    date: str = Field("", max_length=200)


class Link(BaseModel):
    text: str = Field("", max_length=1000)
    href: str = Field("", max_length=4096)


class ImageItem(BaseModel):
    id: str = Field("", max_length=200)
    data: Optional[str] = None
    fetch_error: Optional[str] = Field(None, max_length=500)


class AttachmentItem(BaseModel):
    id: str = Field("", max_length=200)
    name: str = Field("", max_length=500)
    mime: str = Field("", max_length=200)
    size_text: str = Field("", max_length=50)
    data: Optional[str] = None
    fetch_error: Optional[str] = Field(None, max_length=500)


class Extraction(BaseModel):
    source: str = Field("", max_length=50)
    warnings: List[str] = Field(default_factory=list, max_length=20)


class AnalyzeOptions(BaseModel):
    scan_images: bool = True
    ocr: bool = True


class AnalyzeRequest(BaseModel):
    message: MessageContent
    links: List[Link] = Field(default_factory=list)
    images: List[ImageItem] = Field(default_factory=list)
    attachments: List[AttachmentItem] = Field(default_factory=list)
    headers_raw: Optional[str] = None
    headers_error: Optional[str] = Field(None, max_length=500)
    extraction: Extraction = Field(default_factory=Extraction)
    options: AnalyzeOptions = Field(default_factory=AnalyzeOptions)


# ---------------------------------------------------------
# Health check
# ---------------------------------------------------------

@app.get("/")
def root():
    return {
        "status": "online",
        "service": "Spam Email Checker API",
        "version": ENGINE_VERSION
    }


@app.get("/capabilities")
def capabilities():
    ocr_available, ocr_info = ocr.status()

    return {
        "version": ENGINE_VERSION,
        "ocr": {"available": ocr_available, "detail": ocr_info},
        "qr": {"available": True, "detail": "OpenCV"},
        "reputation": {
            "available": bool(os.environ.get("SAFE_BROWSING_API_KEY")),
            "detail": "Google Safe Browsing" if os.environ.get("SAFE_BROWSING_API_KEY")
            else "Not configured (SAFE_BROWSING_API_KEY)"
        },
        "limits": {
            "max_email_chars": MAX_EMAIL_CHARS,
            "max_links": MAX_LINKS,
            "max_images": MAX_IMAGES,
            "max_attachments": MAX_ATTACHMENTS,
            "max_file_bytes": MAX_IMAGE_BYTES
        }
    }


# ---------------------------------------------------------
# Model information
# ---------------------------------------------------------

@app.get("/model-info")
def model_info():
    return {
        "dataset": metadata.get("dataset", "CEAS_08"),
        "features": metadata.get(
            "features",
            "Word + Character TF-IDF"
        ),
        "classifier": metadata.get(
            "classifier",
            "Logistic Regression"
        ),
        "metrics": metadata.get("metrics", {}),
        "labels": metadata.get(
            "label_mapping",
            {
                0: "NOT SPAM",
                1: "SPAM"
            }
        )
    }


# ---------------------------------------------------------
# Spam prediction
# ---------------------------------------------------------

@app.post("/predict")
def predict_email(request: EmailRequest):

    subject = request.subject.strip()
    body = request.body.strip()

    if not subject and not body:
        raise HTTPException(
            status_code=400,
            detail="Please provide an email subject or body."
        )

    if len(subject) + len(body) > MAX_EMAIL_CHARS:
        raise HTTPException(
            status_code=400,
            detail=f"Email is too long. Maximum is {MAX_EMAIL_CHARS:,} characters."
        )

    return predict_text(subject, body)


# ---------------------------------------------------------
# QR code scanning
# ---------------------------------------------------------

@app.post("/scan-qr")
def scan_qr(request: QRScanRequest):

    if len(request.images) > MAX_QR_IMAGES:
        raise HTTPException(
            status_code=400,
            detail=f"Too many images. Maximum is {MAX_QR_IMAGES}."
        )

    qr_codes = []
    images_scanned = 0

    for image in request.images:

        img_bytes = decode_base64_data(image.data)

        if not img_bytes:
            continue

        if len(img_bytes) > MAX_QR_IMAGE_BYTES:
            raise HTTPException(
                status_code=400,
                detail="Image is too large. Maximum is 5 MB."
            )

        texts = decode_qr_codes(img_bytes)

        # Not a readable image
        if texts is None:
            continue

        images_scanned += 1

        for text in texts:
            qr_codes.append({
                "image_id": image.id,
                **analyze_qr_payload(text)
            })

    return {
        "qr_codes": qr_codes,
        "images_scanned": images_scanned
    }


# ---------------------------------------------------------
# Full email analysis
# ---------------------------------------------------------

@app.post("/analyze")
def analyze(request: AnalyzeRequest):

    message = request.message

    if len(message.subject) + len(message.body_text) > MAX_EMAIL_CHARS:
        raise HTTPException(
            status_code=400,
            detail=f"Email is too long. Maximum is {MAX_EMAIL_CHARS:,} characters."
        )

    if len(request.images) > MAX_IMAGES or len(request.attachments) > MAX_ATTACHMENTS:
        raise HTTPException(
            status_code=400,
            detail=f"Too many images or attachments (max {MAX_IMAGES} and {MAX_ATTACHMENTS})."
        )

    if len(request.links) > MAX_LINKS:
        request.links = request.links[:MAX_LINKS]
        request.extraction.warnings.append(f"Only the first {MAX_LINKS} links were analyzed.")

    has_content = (
        message.subject.strip()
        or message.body_text.strip()
        or request.images
        or request.attachments
        or request.links
    )

    if not has_content:
        raise HTTPException(
            status_code=400,
            detail="The email has no content to analyze."
        )

    return analyze_email(request.model_dump())
