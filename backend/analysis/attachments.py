"""
Attachment inspection.

Every attachment is checked by name and type. When its bytes are
provided (and within the size limit), supported formats are also
inspected statically: PDF, Office (OOXML and legacy OLE), ZIP, HTML
and images. Files are only parsed as data: nothing is executed,
rendered, extracted to disk or opened in another program.
"""

import io
import re
import zipfile

from bs4 import BeautifulSoup

from .common import (
    decode_base64_data,
    finding,
    has_bidi_controls,
    MAX_ATTACHMENT_BYTES,
    MAX_ATTACHMENTS,
    sanitize_evidence,
)
from .urls import analyze_url, EXECUTABLE_EXTENSIONS


MACRO_OFFICE_EXTENSIONS = {"docm", "dotm", "xlsm", "xltm", "xlam", "xlsb", "pptm", "potm", "ppam", "sldm"}
OFFICE_EXTENSIONS = {"docx", "dotx", "xlsx", "xltx", "pptx", "potx"} | MACRO_OFFICE_EXTENSIONS
LEGACY_OFFICE_EXTENSIONS = {"doc", "dot", "xls", "xlt", "ppt", "pot"}
ARCHIVE_EXTENSIONS = {"zip", "rar", "7z", "gz", "tgz", "tar", "bz2", "xz", "ace", "cab", "arj", "lzh"}
HTML_EXTENSIONS = {"html", "htm", "shtml", "xhtml", "mht", "mhtml"}
IMAGE_EXTENSIONS = {"png", "jpg", "jpeg", "gif", "bmp", "webp"}
SCRIPTABLE_DOCUMENTS = {"svg", "one", "chm", "xll"}
DOCUMENT_EXTENSIONS = {"pdf", "txt", "csv", "rtf", "odt", "ods", "odp"} | OFFICE_EXTENSIONS | LEGACY_OFFICE_EXTENSIONS

MAX_ZIP_ENTRIES = 1000
MAX_ZIP_MEMBER_READ = 1024 * 1024
ZIP_BOMB_RATIO = 100
ZIP_BOMB_TOTAL = 200 * 1024 * 1024
MAX_HTML_BYTES = 2 * 1024 * 1024
MAX_URLS_PER_ATTACHMENT = 20

PDF_ACTIVE_KEYS = {
    b"/JavaScript": "JavaScript",
    b"/JS": "JavaScript",
    b"/Launch": "a Launch action (runs programs)",
    b"/OpenAction": "an automatic action when opened",
    b"/AA": "automatic actions",
    b"/EmbeddedFile": "embedded files",
    b"/RichMedia": "embedded rich media",
    b"/XFA": "an XFA form",
}


# ---------------------------------------------------------
# Type detection
# ---------------------------------------------------------

def get_extensions(name):
    """All extensions, lowercased: "a.pdf.exe" -> ["pdf", "exe"]."""

    clean = re.sub(r"[​-‏‪-‮⁦-⁩﻿]", "", name or "")
    parts = clean.lower().strip().strip(".").split(".")

    return [part.strip() for part in parts[1:] if part.strip()]


def sniff_type(data):
    head = data[:16]

    if head.startswith(b"MZ"):
        return "executable"
    if head.startswith(b"\x7fELF"):
        return "executable"
    if head.startswith(b"%PDF"):
        return "pdf"
    if head.startswith(b"PK\x03\x04") or head.startswith(b"PK\x05\x06"):
        return "zip"
    if head.startswith(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"):
        return "ole"
    if head.startswith(b"Rar!") or head.startswith(b"7z\xbc\xaf\x27\x1c"):
        return "archive"
    if head.startswith((b"\x89PNG", b"\xff\xd8\xff", b"GIF87a", b"GIF89a", b"BM")) or (
        head[:4] == b"RIFF" and head[8:12] == b"WEBP"
    ):
        return "image"

    text_start = data[:1024].lstrip().lower()

    if text_start.startswith((b"<!doctype html", b"<html", b"<head", b"<body", b"<script", b"<form")):
        return "html"

    if text_start.startswith(b"<svg") or (text_start.startswith(b"<?xml") and b"<svg" in data[:4096].lower()):
        return "svg"

    return "unknown"


# ---------------------------------------------------------
# Content inspectors
# ---------------------------------------------------------

def _url_findings(urls, name):
    findings = []

    for url in list(dict.fromkeys(urls))[:MAX_URLS_PER_ATTACHMENT]:
        for item in analyze_url(url, "attachments"):
            item["detail"] = f"In attachment {sanitize_evidence(name, 80)}. {item['detail']}".strip()
            findings.append(item)

    return findings


def inspect_pdf(data, name):
    findings = []
    notes = []

    present = sorted({label for key, label in PDF_ACTIVE_KEYS.items()
                      if re.search(re.escape(key) + rb"(?![A-Za-z])", data)})

    if "JavaScript" in present or "a Launch action (runs programs)" in present:
        findings.append(finding(
            "attachments.pdf_active_content", "attachments", "high",
            "PDF contains active content",
            f"{sanitize_evidence(name, 80)} contains {', '.join(present)}.",
            name
        ))
    elif present:
        findings.append(finding(
            "attachments.pdf_auto_actions", "attachments", "medium",
            "PDF contains automatic actions or embedded content",
            f"{sanitize_evidence(name, 80)} contains {', '.join(present)}.",
            name
        ))

    uris = [
        match.decode("latin-1", "replace")
        for match in re.findall(rb"/URI\s*\(([^)]{1,2000})\)", data)
    ]

    findings.extend(_url_findings(uris, name))

    if re.search(rb"/ObjStm|/FlateDecode", data):
        notes.append("Compressed parts of the PDF were not decompressed; only uncompressed objects were scanned.")

    if uris:
        notes.append(f"{len(uris)} link(s) found in the PDF.")

    return findings, notes


def inspect_zip(data, name, extensions):
    findings = []
    notes = []

    try:
        archive = zipfile.ZipFile(io.BytesIO(data))
        entries = archive.infolist()
    except (zipfile.BadZipFile, ValueError, OSError):
        return findings, ["The archive could not be read."]

    names = [entry.filename for entry in entries[:MAX_ZIP_ENTRIES]]
    is_ooxml = "[Content_Types].xml" in names

    if len(entries) > MAX_ZIP_ENTRIES:
        notes.append(f"Only the first {MAX_ZIP_ENTRIES} of {len(entries)} entries were listed.")

    total_uncompressed = sum(entry.file_size for entry in entries)
    total_compressed = sum(entry.compress_size for entry in entries) or 1

    if total_uncompressed > ZIP_BOMB_TOTAL and total_uncompressed / total_compressed > ZIP_BOMB_RATIO:
        findings.append(finding(
            "attachments.zip_bomb", "attachments", "high",
            "Archive expands to an extremely large size (possible compression bomb)",
            f"{sanitize_evidence(name, 80)} expands to {total_uncompressed // (1024 * 1024)} MB.",
            name
        ))
        return findings, notes

    if is_ooxml:
        return inspect_ooxml(archive, names, name, extensions)

    if any(entry.flag_bits & 0x1 for entry in entries):
        findings.append(finding(
            "attachments.encrypted_archive", "attachments", "high",
            "Password-protected archive",
            "Its contents cannot be scanned; attackers use passwords to hide malware from scanners.",
            name
        ))

    for entry_name in names:
        entry_extensions = get_extensions(entry_name.rsplit("/", 1)[-1])
        last = entry_extensions[-1] if entry_extensions else ""

        if last in EXECUTABLE_EXTENSIONS:
            findings.append(finding(
                "attachments.archive_executable", "attachments", "critical",
                f"Archive contains a .{last} file that can run programs",
                f"Inside {sanitize_evidence(name, 80)}.",
                entry_name
            ))
        elif last in MACRO_OFFICE_EXTENSIONS:
            findings.append(finding(
                "attachments.archive_macro_document", "attachments", "high",
                "Archive contains a macro-enabled Office document",
                f"Inside {sanitize_evidence(name, 80)}.",
                entry_name
            ))
        elif last in HTML_EXTENSIONS:
            findings.append(finding(
                "attachments.archive_html", "attachments", "medium",
                "Archive contains an HTML file",
                "HTML files in archives are often fake login pages.",
                entry_name
            ))
        elif last in ARCHIVE_EXTENSIONS:
            notes.append("Contains a nested archive, which was not opened.")

    notes.append(f"{min(len(entries), MAX_ZIP_ENTRIES)} archive entries listed (not extracted).")

    return findings, list(dict.fromkeys(notes))


def inspect_ooxml(archive, names, name, extensions):
    findings = []
    notes = []

    if any(entry.lower().endswith("vbaproject.bin") for entry in names):
        findings.append(finding(
            "attachments.office_macros", "attachments", "high",
            "Office document contains macros",
            f"{sanitize_evidence(name, 80)} includes VBA macro code. Do not enable editing or content.",
            name
        ))

    urls = []

    for entry_name in names:
        if not entry_name.endswith(".rels"):
            continue

        info = archive.getinfo(entry_name)

        if info.file_size > MAX_ZIP_MEMBER_READ:
            continue

        content = archive.read(info).decode("utf-8", "replace")

        for relationship in re.findall(r"<Relationship\b[^>]*>", content):
            if 'TargetMode="External"' not in relationship:
                continue

            target = re.search(r'Target="([^"]{1,2000})"', relationship)
            rel_type = re.search(r'Type="([^"]+)"', relationship)
            target = target.group(1) if target else ""
            rel_type = rel_type.group(1).rsplit("/", 1)[-1] if rel_type else ""

            if rel_type in ("attachedTemplate", "oleObject", "frame", "subDocument"):
                findings.append(finding(
                    "attachments.office_remote_template", "attachments", "high",
                    "Office document loads content from the internet when opened",
                    f"External {rel_type} reference, a known malware technique.",
                    target
                ))
            elif target.lower().startswith(("http://", "https://")):
                urls.append(target)

    findings.extend(_url_findings(urls, name))
    notes.append("Office document structure inspected (macros and external references).")

    if urls:
        notes.append(f"{len(urls)} external link(s) found in the document.")

    return findings, notes


def inspect_ole(data, name):
    findings = []

    if b"_VBA_PROJECT" in data or b"V\x00B\x00A\x00" in data:
        findings.append(finding(
            "attachments.office_macros", "attachments", "high",
            "Office document contains macros",
            f"{sanitize_evidence(name, 80)} includes VBA macro code. Do not enable editing or content.",
            name
        ))

    return findings, ["Legacy Office file scanned for macro markers."]


def inspect_html(data, name):
    findings = []

    soup = BeautifulSoup(data[:MAX_HTML_BYTES], "html.parser")

    if soup.find("input", attrs={"type": re.compile("^password$", re.I)}):
        findings.append(finding(
            "attachments.html_password_form", "attachments", "critical",
            "HTML attachment asks for a password",
            "Attached web pages with login forms are a common credential-phishing technique.",
            name
        ))
    elif soup.find("form"):
        findings.append(finding(
            "attachments.html_form", "attachments", "high",
            "HTML attachment contains a form",
            "Information typed into it may be sent to the attacker.",
            name
        ))

    if soup.find("script"):
        findings.append(finding(
            "attachments.html_script", "attachments", "medium",
            "HTML attachment contains scripts",
            "Scripts were not run.",
            name
        ))

    refresh = soup.find("meta", attrs={"http-equiv": re.compile("^refresh$", re.I)})
    if refresh or re.search(rb"(window|document)\.location|location\.(href|replace)", data[:MAX_HTML_BYTES]):
        findings.append(finding(
            "attachments.html_redirect", "attachments", "high",
            "HTML attachment redirects to a website when opened",
            "",
            name
        ))

    urls = []

    for tag in soup.find_all(["a", "form", "iframe"], limit=200):
        target = tag.get("href") or tag.get("action") or tag.get("src") or ""
        if target.lower().startswith(("http://", "https://")):
            urls.append(target)

    findings.extend(_url_findings(urls, name))

    return findings, ["HTML parsed as text (scripts not run)."]


# ---------------------------------------------------------
# Main entry point
# ---------------------------------------------------------

def metadata_findings(name, extensions, mime):
    findings = []
    last = extensions[-1] if extensions else ""

    if has_bidi_controls(name):
        findings.append(finding(
            "attachments.bidi_filename", "attachments", "critical",
            "File name uses hidden characters to disguise its type",
            "Right-to-left override characters make e.g. 'exe' look like 'pdf'.",
            repr(name)[1:-1]
        ))

    if last in EXECUTABLE_EXTENSIONS:
        disguised = len(extensions) >= 2 and extensions[-2] in DOCUMENT_EXTENSIONS | IMAGE_EXTENSIONS

        findings.append(finding(
            "attachments.executable", "attachments", "critical",
            ("Executable disguised as a document" if disguised
             else f"Attachment is a .{last} file that can run programs"),
            "Do not open it.",
            name
        ))
    elif last in MACRO_OFFICE_EXTENSIONS:
        findings.append(finding(
            "attachments.macro_extension", "attachments", "high",
            "Macro-enabled Office document",
            "Macros can install malware. Do not enable content.",
            name
        ))
    elif last in HTML_EXTENSIONS:
        findings.append(finding(
            "attachments.html_file", "attachments", "high",
            "HTML file attached",
            "Attached web pages are often fake login pages that work offline.",
            name
        ))
    elif last in SCRIPTABLE_DOCUMENTS:
        findings.append(finding(
            "attachments.scriptable_document", "attachments", "high",
            f"Attachment type .{last} can contain scripts or code",
            "",
            name
        ))
    elif last in ARCHIVE_EXTENSIONS:
        findings.append(finding(
            "attachments.archive", "attachments", "low",
            "Compressed archive attached",
            "Archives can hide dangerous files.",
            name
        ))

    return findings


def analyze_attachments(attachments, deadline=None):
    """
    attachments: [{"id", "name", "mime", "size_text", "data"?, "fetch_error"?}]
    Returns (findings, reports, images) where images are
    [(id, bytes)] of image attachments for QR/OCR analysis.
    """

    findings = []
    reports = []
    images = []

    for attachment in (attachments or [])[:MAX_ATTACHMENTS]:
        name = attachment.get("name") or "(unnamed attachment)"
        mime = (attachment.get("mime") or "").lower()
        extensions = get_extensions(name)
        last = extensions[-1] if extensions else ""

        report = {
            "id": attachment.get("id"),
            "name": sanitize_evidence(name, 120),
            "size": sanitize_evidence(attachment.get("size_text") or "", 20),
            "inspected": "metadata",
            "detected_type": None,
            "notes": []
        }

        item_findings = metadata_findings(name, extensions, mime)

        data = decode_base64_data(attachment.get("data"))

        if attachment.get("data") and data is None:
            report["notes"].append("The attachment data was not valid base64.")

        if data is None and attachment.get("fetch_error"):
            report["notes"].append(
                "Contents not inspected: " + sanitize_evidence(attachment["fetch_error"], 160)
            )
        elif data is not None and len(data) > MAX_ATTACHMENT_BYTES:
            report["notes"].append("Contents not inspected: larger than the 5 MB limit.")
            data = None
        elif deadline is not None and deadline.expired():
            report["notes"].append("Contents not inspected: analysis time limit reached.")
            data = None

        if data is not None:
            detected = sniff_type(data)
            report["detected_type"] = detected
            report["inspected"] = "content"

            if detected == "executable" and last not in EXECUTABLE_EXTENSIONS:
                item_findings.append(finding(
                    "attachments.disguised_executable", "attachments", "critical",
                    "Attachment is a program disguised as another file type",
                    f"Its name ends in .{last or '?'} but the file is an executable.",
                    name
                ))

            try:
                if detected == "pdf":
                    extra, notes = inspect_pdf(data, name)
                elif detected == "zip":
                    extra, notes = inspect_zip(data, name, extensions)
                elif detected == "ole":
                    extra, notes = inspect_ole(data, name)
                elif detected in ("html", "svg") or last in HTML_EXTENSIONS:
                    extra, notes = inspect_html(data, name)
                elif detected == "image":
                    images.append((attachment.get("id") or name, data))
                    extra, notes = [], ["Image sent to QR and OCR analysis."]
                elif detected == "archive":
                    extra, notes = [], ["RAR/7z archives are not supported; contents were not listed."]
                    report["inspected"] = "unsupported"
                else:
                    extra, notes = [], ["No content inspector for this file type; only its name and type were checked."]
                    report["inspected"] = "unsupported"
            except Exception as error:  # noqa: BLE001 - malformed files must not crash analysis
                extra = []
                notes = [f"The file could not be parsed ({type(error).__name__})."]
                report["inspected"] = "failed"

            item_findings.extend(extra)
            report["notes"].extend(notes)

        report["findings"] = len(item_findings)
        findings.extend(item_findings)
        reports.append(report)

    return findings, reports, images
