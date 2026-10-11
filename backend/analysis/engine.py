"""
Analysis engine: runs every analyzer on an extracted email and
combines the results into a score, verdict, findings, coverage and
recommendations.
"""

import time

from . import ocr
from .attachments import analyze_attachments
from .common import (
    ANALYSIS_TIME_BUDGET,
    coverage,
    Deadline,
    decode_base64_data,
    finding,
    MAX_EMAIL_CHARS,
    MAX_IMAGE_BYTES,
    MAX_IMAGES,
    sanitize_evidence,
)
from .content_checks import content_findings, keyword_findings
from .headers import analyze_headers
from .qr import decode_qr_image, get_qr_type, load_image
from .reputation import check_urls
from .scoring import (
    compute_score,
    get_classification,
    get_recommendations,
    get_summary,
    get_verdict,
    sort_findings,
)
from .sender import analyze_sender
from .text_model import predict_text
from .urls import analyze_links, analyze_url, extract_urls_from_text, unwrap_redirect


ENGINE_VERSION = "2.0.0"

# Body text shorter than this is treated as an image-only email
MIN_BODY_CHARS = 40


def _analyze_images(images, use_ocr, deadline):
    """
    images: [(id, bytes_or_None, error_or_None)]
    Returns (qr_payloads, ocr_texts, reports, counts).
    """

    qr_payloads = []
    ocr_texts = []
    reports = []
    counts = {"total": len(images), "analyzed": 0, "failed": 0, "ocr": 0, "ocr_skipped_time": 0}

    ocr_available = use_ocr and ocr.status()[0]

    for image_id, data, error in images:
        report = {"id": image_id, "status": "analyzed", "qr_codes": 0, "ocr_chars": 0, "note": ""}

        if data is None:
            report["status"] = "unavailable"
            report["note"] = sanitize_evidence(error or "Image data was not available.", 160)
            counts["failed"] += 1
            reports.append(report)
            continue

        if len(data) > MAX_IMAGE_BYTES:
            report["status"] = "skipped"
            report["note"] = "Larger than the 5 MB limit."
            counts["failed"] += 1
            reports.append(report)
            continue

        if deadline.expired():
            report["status"] = "skipped"
            report["note"] = "Analysis time limit reached."
            counts["failed"] += 1
            reports.append(report)
            continue

        img = load_image(data)

        if img is None:
            report["status"] = "unsupported"
            report["note"] = "Not a readable image format."
            counts["failed"] += 1
            reports.append(report)
            continue

        counts["analyzed"] += 1

        for text in decode_qr_image(img):
            qr_payloads.append((image_id, text))
            report["qr_codes"] += 1

        if ocr_available:
            if deadline.remaining() > 8:
                text = ocr.extract_text(img) or ""
                report["ocr_chars"] = len(text)
                counts["ocr"] += 1
                if text:
                    ocr_texts.append(text)
            else:
                counts["ocr_skipped_time"] += 1

        reports.append(report)

    return qr_payloads, ocr_texts, reports, counts


def _qr_findings(qr_payloads):
    findings = []
    codes = []

    for image_id, text in qr_payloads:
        qr_type = get_qr_type(text)

        codes.append({
            "image_id": sanitize_evidence(image_id, 80),
            "type": qr_type,
            "content": sanitize_evidence(text, 500)
        })

        if qr_type == "url":
            findings.append(finding(
                "qr.link", "qr", "medium",
                "QR code links to a website",
                "QR codes hide the link from email security checks and are a common "
                "phishing technique ('quishing').",
                text
            ))
            findings.extend(analyze_url(text.strip(), "qr"))
        else:
            findings.append(finding(
                f"qr.{qr_type}", "qr", "info",
                f"QR code contains {qr_type} data",
                "",
                text
            ))

    return findings, codes


def analyze_email(payload):
    """
    payload: dict matching the /analyze request (see main.py).
    """

    started = time.monotonic()
    deadline = Deadline(ANALYSIS_TIME_BUDGET)

    message = payload.get("message") or {}
    options = payload.get("options") or {}
    extraction = payload.get("extraction") or {}

    subject = (message.get("subject") or "")[:2000]
    body = (message.get("body_text") or "")[:MAX_EMAIL_CHARS]
    hidden_text = (message.get("hidden_text") or "")[:20000]

    findings = []
    coverage_entries = []
    warnings = [sanitize_evidence(w, 300) for w in (extraction.get("warnings") or [])[:10]]

    # ---------- Attachments (first, so image attachments join image analysis)
    attachments = payload.get("attachments") or []
    attachment_findings, attachment_reports, attachment_images = analyze_attachments(attachments, deadline)
    findings.extend(attachment_findings)

    if not attachments:
        coverage_entries.append(coverage("attachments", "not_applicable", "No attachments found."))
    else:
        inspected = sum(1 for r in attachment_reports if r["inspected"] == "content")
        status = "analyzed" if inspected == len(attachment_reports) else "partial"
        coverage_entries.append(coverage(
            "attachments",
            status,
            f"{len(attachment_reports)} attachment(s): names and types checked for all, "
            f"contents inspected for {inspected}."
        ))

    # ---------- Images: QR codes and OCR
    image_inputs = []

    for image in (payload.get("images") or [])[:MAX_IMAGES]:
        image_inputs.append((
            image.get("id") or "image",
            decode_base64_data(image.get("data")),
            image.get("fetch_error")
        ))

    for image_id, data in attachment_images:
        image_inputs.append((f"attachment: {image_id}", data, None))

    use_ocr = bool(options.get("ocr", True))
    scan_images = bool(options.get("scan_images", True))

    if not scan_images:
        image_inputs = []

    qr_payloads, ocr_texts, image_reports, image_counts = _analyze_images(image_inputs, use_ocr, deadline)

    if not scan_images:
        coverage_entries.append(coverage("images", "skipped", "Image scanning is turned off in settings."))
    elif not image_inputs:
        coverage_entries.append(coverage("images", "not_applicable", "No images found."))
    else:
        status = "analyzed" if image_counts["failed"] == 0 else ("partial" if image_counts["analyzed"] else "unavailable")
        coverage_entries.append(coverage(
            "images",
            status,
            f"{image_counts['analyzed']} of {image_counts['total']} image(s) analyzed for QR codes."
        ))

    qr_findings, qr_codes = _qr_findings(qr_payloads)
    findings.extend(qr_findings)

    if image_counts["analyzed"]:
        coverage_entries.append(coverage(
            "qr",
            "analyzed",
            f"{len(qr_codes)} QR code(s) found in {image_counts['analyzed']} image(s)."
        ))
    else:
        coverage_entries.append(coverage("qr", "not_applicable", "No images could be scanned for QR codes."))

    ocr_ok, ocr_info = ocr.status() if use_ocr and image_counts["analyzed"] else (False, None)

    if not image_counts["analyzed"]:
        coverage_entries.append(coverage("ocr", "not_applicable", "No images to read text from."))
    elif not use_ocr:
        coverage_entries.append(coverage("ocr", "skipped", "OCR is turned off in settings."))
    elif not ocr_ok:
        coverage_entries.append(coverage("ocr", "unavailable", ocr_info or "No OCR engine available."))
    elif image_counts["ocr_skipped_time"]:
        coverage_entries.append(coverage(
            "ocr",
            "partial",
            f"Text read from {image_counts['ocr']} image(s) with {ocr_info}; "
            f"{image_counts['ocr_skipped_time']} skipped (time limit)."
        ))
    else:
        coverage_entries.append(coverage(
            "ocr",
            "analyzed",
            f"Text read from {image_counts['ocr']} image(s) with {ocr_info}."
        ))

    ocr_text = "\n".join(ocr_texts)[:20000]

    # ---------- Text model
    text_source = "body"
    model_body = body

    if ocr_text:
        model_body = f"{body}\n{ocr_text}".strip()
        text_source = "body+ocr" if len(body.strip()) >= MIN_BODY_CHARS else "ocr"

    model_result = None

    if subject.strip() or model_body.strip():
        model_result = predict_text(subject, model_body)
        model_result["text_source"] = text_source

        spam_probability = model_result["spam_probability"]

        if model_result["prediction"] == "SPAM":
            severity = "high" if spam_probability >= 0.9 else "medium" if spam_probability >= 0.75 else "low"
            findings.append(finding(
                "text.model_spam", "model", severity,
                f"Spam model: {round(spam_probability * 100)}% spam probability",
                "Based on the words used (see top words). Points are added by probability.",
                None
            ))
            findings[-1]["points"] = 0  # counted via model points in scoring

        findings.extend(keyword_findings(model_result["indicators"]))

        detail = "Subject and body text classified."
        if text_source == "ocr":
            detail = "Little body text: the text read from images (OCR) was classified."
        elif text_source == "body+ocr":
            detail = "Subject, body and text read from images classified."

        coverage_entries.append(coverage("text_model", "analyzed", detail))

        if len(body.strip()) < MIN_BODY_CHARS and not ocr_text:
            warnings.append(
                "The email has almost no readable text; the text model had little to work with."
            )
    else:
        coverage_entries.append(coverage(
            "text_model",
            "not_applicable",
            "No subject, body text or image text to classify."
        ))

    findings.extend(content_findings(subject, body, hidden_text))

    # ---------- Sender
    sender_findings, sender_coverage, sender_summary = analyze_sender(message.get("sender"))
    findings.extend(sender_findings)
    coverage_entries.append(sender_coverage)

    # ---------- Links (anchors + URLs in body and OCR text)
    links = payload.get("links") or []
    link_findings, link_summary = analyze_links(links, f"{body}\n{ocr_text}")
    findings.extend(link_findings)

    if link_summary["total"]:
        coverage_entries.append(coverage(
            "links",
            "partial" if link_summary["truncated"] else "analyzed",
            f"{link_summary['total']} link(s) to {len(link_summary['unique_domains'])} domain(s) "
            "inspected (not opened)."
        ))
    else:
        coverage_entries.append(coverage("links", "not_applicable", "No links found."))

    # ---------- Authentication headers
    header_findings, header_coverage, auth_summary = analyze_headers(
        payload.get("headers_raw"),
        payload.get("headers_error")
    )
    findings.extend(header_findings)
    coverage_entries.append(header_coverage)

    # ---------- Reputation
    urls = [unwrap_redirect(link.get("href") or "") for link in links]
    urls += extract_urls_from_text(f"{body}\n{ocr_text}")
    urls += [text for _, text in qr_payloads if get_qr_type(text) == "url"]

    if deadline.expired():
        coverage_entries.append(coverage("reputation", "skipped", "Analysis time limit reached."))
    else:
        reputation_findings, reputation_coverage = check_urls(urls)
        findings.extend(reputation_findings)
        coverage_entries.append(reputation_coverage)

    # ---------- Scoring
    findings = sort_findings(findings)
    score, breakdown = compute_score(
        findings,
        model_result["spam_probability"] if model_result and model_result["prediction"] == "SPAM" else None
    )
    verdict = get_verdict(score, findings)
    classification = get_classification(verdict, findings, model_result)

    for entry in coverage_entries:
        if entry["status"] in ("partial", "unavailable") and entry["component"] != "reputation":
            warnings.append(f"{entry['component'].replace('_', ' ').capitalize()}: {entry['detail']}")

    return {
        "engine_version": ENGINE_VERSION,
        "score": score,
        "score_breakdown": breakdown,
        "verdict": verdict,
        "classification": classification,
        "summary": get_summary(verdict, classification, score, findings),
        "findings": findings,
        "recommendations": get_recommendations(verdict, classification, findings, coverage_entries),
        "coverage": coverage_entries,
        "warnings": list(dict.fromkeys(warnings)),
        "partial_analysis": any(
            entry["status"] in ("partial", "unavailable") and entry["component"] != "reputation"
            for entry in coverage_entries
        ),
        "model": model_result,
        "sender": sender_summary,
        "authentication": auth_summary,
        "links": link_summary,
        "qr_codes": qr_codes,
        "images": image_reports,
        "attachments": attachment_reports,
        "elapsed_ms": round((time.monotonic() - started) * 1000)
    }
