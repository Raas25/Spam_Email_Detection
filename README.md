# Spam & Phishing Email Detector

A Chrome extension for Gmail, backed by a local FastAPI analysis engine. The engine checks text (machine-learning model plus rules), the sender, links, images (QR codes and OCR), attachments and SPF/DKIM/DMARC headers, and explains its risk score.

**To get started, follow [How to Run.md](How%20to%20Run.md).**

---

## Project structure

```
ai_mini/
├── README.md
├── How to Run.md                Step-by-step setup and usage
├── backend/                     FastAPI analysis backend
│   ├── main.py                  API: /analyze, /predict, /scan-qr, /capabilities, /model-info
│   ├── analysis/                Analysis engine
│   │   ├── engine.py            Runs all analyzers, builds the result
│   │   ├── scoring.py           Score, verdict, classification, recommendations
│   │   ├── text_model.py        Spam model, keyword indicators, top words
│   │   ├── content_checks.py    Hidden text, instructions aimed at scanners
│   │   ├── sender.py            Display-name spoofing, look-alike sender domains
│   │   ├── urls.py / domains.py Link analysis, brands, look-alike domains
│   │   ├── qr.py / ocr.py       QR decoding (OpenCV), OCR (RapidOCR / Tesseract)
│   │   ├── attachments.py       Name/type checks; PDF, Office, ZIP, HTML inspection
│   │   ├── headers.py           SPF / DKIM / DMARC / Reply-To from raw headers
│   │   ├── reputation.py        Optional Google Safe Browsing lookups
│   │   └── common.py            Findings, limits, evidence sanitizing
│   ├── model/spam_model.joblib  Trained spam model (TF-IDF + Logistic Regression)
│   ├── requirements.txt         Runtime dependencies (pinned)
│   └── requirements-ocr.txt     Optional OCR engine
└── spam_extension/              Chrome extension (Manifest V3, plain JavaScript)
    ├── manifest.json
    ├── background.js            Service worker: scan pipeline
    ├── content/gmail-extract.js Reads the open Gmail message
    ├── content/content.js       "Check Spam" button, overlay, navigation tracking
    ├── popup/                   Toolbar popup (summary)
    ├── sidepanel/               Side panel (full report)
    ├── options/                 Settings page
    ├── lib/                     Settings, rendering, helpers
    ├── styles/ui.css
    └── icons/
```

---

## Spam & Phishing Email Detector

### How it works

```
Gmail tab                          Extension service worker                 Local backend (FastAPI)
─────────                          ────────────────────────                 ───────────────────────
gmail-extract.js reads the   ──►   downloads the email's images,      ──►   /analyze runs every analyzer
open message: sender,              attachments (≤ 5 MB) and                 and returns score, verdict,
subject, body, hidden text,        "Show original" headers using            findings, coverage and
links, images, attachments         your Gmail session                       recommendations
                                                                     ◄──
popup / side panel / page    ◄──   stores the result per tab
overlay show the result
```

1. You open an email in Gmail.
2. You start a scan with the **🔍 Check Spam** button on the page, the toolbar **popup**, or the **side panel** (or automatically, if enabled in Settings).
3. The content script extracts the **most recent expanded message** in the visible conversation. Hidden, previously viewed emails that Gmail keeps in the page are ignored.
4. The service worker downloads what the page doesn't contain as text, then sends everything to the backend.
5. The backend analyzes it and returns an explainable result, shown in the overlay, popup and side panel.

### What is analyzed

| Area | How | Notes |
|---|---|---|
| **Text model** | TF-IDF + Logistic Regression trained on CEAS_08; top words explain the result | For image-only emails, text read by OCR is classified |
| **Keyword rules** | Urgency, prize/money words, password requests (whole words only) | |
| **Hidden text** | Text styled invisible; instructions aimed at "AI scanners" | The engine uses no language model, so such text cannot change its behaviour, but its presence is reported |
| **Sender** | Brand in display name vs. sending domain, look-alike domains (`paypa1`, `rnicrosoft`), punycode, another address hidden in the name, organisation names on free webmail | Based on what Gmail shows; not proof of identity |
| **Links** | Link text vs. real destination, look-alike/brand domains, raw IPs, `@` tricks, shorteners, risky TLDs, `javascript:`/`data:` links, executable downloads, Google/Outlook redirect unwrapping | Links are parsed, never opened |
| **Images** | QR codes decoded with OpenCV; QR links get the same link checks | "Quishing" (QR phishing) is flagged |
| **OCR** | Text inside images (RapidOCR, or Tesseract if installed) | Optional; reported as unavailable if not installed |
| **Attachments** | Every file: dangerous/double extensions, right-to-left override names, macro formats, HTML/SVG/OneNote. With contents (≤ 5 MB): disguised executables, PDF JavaScript/actions/links, Office macros and remote templates, ZIP contents/encryption/zip bombs, HTML login forms/redirects, image QR/OCR | Static parsing only; nothing is opened or executed. RAR/7z contents are not listed |
| **SPF / DKIM / DMARC** | From the message's "Show original" headers (fetched automatically, or pasted in the side panel); Reply-To mismatch | Only reported when headers are available; otherwise shown as "not checked" |
| **Reputation** | Google Safe Browsing, if the backend has an API key | Off by default; never claims a link is "clean" |

### Scoring

Each finding has a severity: **info 0, low 5, medium 12, high 25, critical 40 points**.

- Repeated findings of the same kind count once.
- Each category is capped (for example, links at 60), so one noisy area can't dominate.
- The text model adds 15, 22 or 30 points at 50%, 75% or 90% spam probability.
- **Score** = the sum, capped at 100.
- **Verdict:**
  - **Dangerous:** a score of 50 or more, or any critical finding.
  - **Suspicious:** a score of 20 or more.
  - **Safe:** anything lower.
- **Classification:**
  - **malware:** a dangerous attachment or download.
  - **phishing:** deceptive links, impersonation, credential requests, QR links or authentication failures.
  - **spam:** the model predicts spam with none of the above.
  - **legitimate:** the verdict is Safe.

Every result also lists **analysis coverage**: for each area, whether it was checked, partly checked, unavailable, skipped or not applicable, and why. Anything not fully checked appears as a **partial-analysis warning**.

### Requirements

- Python 3.11 or newer (the pinned versions were tested on Python 3.14)
- Google Chrome 116 or newer

### 1. Start the backend

```bash
cd backend
```
```bash
python -m venv venv
```
```bash
venv\Scripts\activate
```
(On macOS or Linux, use `source venv/bin/activate` instead.)
```bash
pip install -r requirements.txt
```
Optional, to read text inside images (the OCR models are downloaded on first use):
```bash
pip install -r requirements-ocr.txt
```
```bash
uvicorn main:app --port 8000
```

The API runs at `http://127.0.0.1:8000`; check `http://127.0.0.1:8000/capabilities` to see whether OCR and reputation are available.

> The model was saved with scikit-learn 1.6.1, which has no builds for Python 3.14. `requirements.txt` pins 1.9.1, which loads the model correctly but prints an `InconsistentVersionWarning` at startup.

### 2. Load the extension in Chrome

1. Open `chrome://extensions` and turn on **Developer mode**.
2. Click **Load unpacked** and select the `spam_extension` folder.
3. Pin the extension (puzzle icon → pin) for easy access to the popup.
4. Reload any Gmail tab that was already open.

After changing the extension's files, click the reload icon on `chrome://extensions` and reload Gmail.

### 3. Scan an email

- **Popup** (toolbar icon): backend status, **Scan this email**, a summary with the top findings, and **Full report**.
- **Side panel**: the full report, with the verdict, score, recommended actions, findings grouped by area with evidence, text-model words, sender and authentication details, QR codes, images, attachments and coverage. If headers couldn't be read automatically, you can paste them from Gmail's ⋮ → **Show original** to check SPF/DKIM/DMARC.
- **In Gmail**: the **🔍 Check Spam** button shows progress and a compact result. Results are cleared when you open another email, and the popup and side panel mark old results as belonging to a different email.

### Settings

Open them from the popup or side panel (**Settings**), or from `chrome://extensions` → Details → Extension options.

| Setting | Default | |
|---|---|---|
| Backend URL | `http://127.0.0.1:8000` | A non-local backend must use HTTPS, needs a host permission (Chrome asks), and requires an explicit consent checkbox because email content will leave your computer |
| Scan images for QR codes | on | |
| Read text inside images (OCR) | on | Needs an OCR engine on the backend |
| Inspect attachment contents | on | When off, attachments are judged by name and type only |
| Read message headers | on | Fetches Gmail's "Show original" page for this message |
| Show the "Check Spam" button | on | |
| Scan automatically | off | |

### Backend configuration

| Variable | Effect |
|---|---|
| `SAFE_BROWSING_API_KEY` | Enables Google Safe Browsing link checks. The key stays on the backend. Link URLs (not email text) are then sent to Google. |
| `SPAM_CHECKER_DISABLE_OCR=1` | Turns OCR off even if installed |

### Security and privacy

- **Email content is untrusted.**
  - All UI (overlay, popup, side panel) is built with `textContent`, never `innerHTML`.
  - Links and evidence are shown as text, never as clickable links.
  - Evidence is cleaned of control and right-to-left override characters and shortened.
- **Nothing from an email is executed, opened or followed.**
  - Links are only parsed.
  - Attachments are only parsed in memory with size limits, and never saved or run.
  - HTML attachments are parsed with BeautifulSoup without running scripts.
- **Limits:**
  - 100,000 characters of text and 200 links.
  - 10 images and 10 attachments, 5 MB each.
  - 256 KB of headers and an 80 MB request.
  - A 45-second analysis budget, a 1,000-entry ZIP listing and zip-bomb detection.
  - Images are downscaled before decoding.
- **Network:**
  - Only Gmail and Gmail-image URLs are fetched with your cookies; other URLs extracted from an email are refused.
  - The service worker only accepts messages from this extension.
- **No external AI services are used.** Email content goes only to the configured backend, by default on your own computer. A remote backend requires explicit consent in Settings.
- **No API keys in the extension.** The optional Safe Browsing key is a backend environment variable.
- **SPF/DKIM/DMARC and reputation are never claimed** without evidence: without headers or a configured service they are shown as "not checked" or "unavailable".

### API reference

#### `GET /`
Health check.

#### `GET /capabilities`
Engine version, whether OCR and reputation checks are available, and the limits.

#### `GET /model-info`
Dataset, features, classifier and metrics of the text model.

#### `POST /analyze`

The full analysis used by the extension. Only `message` is required.

```json
{
  "message": {
    "subject": "Your account will be suspended",
    "body_text": "Verify your account password immediately…",
    "hidden_text": "",
    "sender": { "name": "PayPal Security", "email": "security@paypa1-alerts.com" }
  },
  "links": [{ "text": "www.paypal.com", "href": "http://paypa1-secure.example.net/login" }],
  "images": [{ "id": "image-1", "data": "<base64>" }, { "id": "image-2", "fetch_error": "HTTP 403" }],
  "attachments": [{ "id": "a1", "name": "invoice.zip", "size_text": "3 KB", "data": "<base64 or null>" }],
  "headers_raw": "Authentication-Results: mx.google.com; spf=fail …",
  "headers_error": null,
  "extraction": { "source": "gmail", "warnings": [] },
  "options": { "scan_images": true, "ocr": true }
}
```

Response (abridged):

```json
{
  "score": 100,
  "verdict": "dangerous",
  "classification": "malware",
  "summary": "Dangerous (100/100): possible malware delivery. Main reasons: …",
  "findings": [
    {
      "id": "links.lookalike_domain",
      "category": "links",
      "severity": "critical",
      "title": "Look-alike domain imitating paypal",
      "detail": "paypa1-secure.example.net is spelled to resemble paypal …",
      "evidence": "paypa1-secure.example.net",
      "points": 40
    }
  ],
  "recommendations": ["Do not click links, scan QR codes, or open attachments in this email.", "…"],
  "coverage": [
    { "component": "ocr", "status": "analyzed", "detail": "Text read from 1 image(s) with RapidOCR." },
    { "component": "authentication", "status": "unavailable", "detail": "Message headers were not available …" }
  ],
  "warnings": ["Authentication: Message headers were not available, so SPF, DKIM and DMARC were not checked."],
  "partial_analysis": true,
  "model": { "prediction": "SPAM", "spam_probability": 0.94, "top_terms": [], "text_source": "body+ocr" },
  "sender": { "name": "PayPal Security", "email": "security@paypa1-alerts.com", "domain": "paypa1-alerts.com" },
  "authentication": { "spf": "not checked", "dkim": "not checked", "dmarc": "not checked" },
  "links": { "total": 1, "unique_domains": ["example.net"], "truncated": false },
  "qr_codes": [{ "image_id": "image-1", "type": "url", "content": "http://192.168.1.5/login" }],
  "images": [{ "id": "image-1", "status": "analyzed", "qr_codes": 1, "ocr_chars": 2, "note": "" }],
  "attachments": [{ "name": "invoice.zip", "inspected": "content", "findings": 2, "notes": ["…"] }],
  "score_breakdown": { "attachments": 45, "links": 60, "model": 30 },
  "elapsed_ms": 677
}
```

#### `POST /predict`

Text model only (kept for compatibility).

Request:
```json
{
  "subject": "You won a prize!",
  "body": "Claim your cash now at http://example.com"
}
```

Response:
```json
{
  "prediction": "SPAM",
  "spam_probability": 0.9845,
  "not_spam_probability": 0.0155,
  "confidence": 0.9845,
  "indicators": ["Prize or financial-related language", "Contains a URL"],
  "top_terms": [
    { "term": "[link]", "weight": 0.1738 },
    { "term": "cash", "weight": 0.0759 },
    { "term": "won", "weight": 0.0257 },
    { "term": "prize", "weight": 0.0051 },
    { "term": "claim", "weight": -0.0008 }
  ]
}
```

`top_terms` lists up to 5 words pushing towards spam (positive `weight`) and up to 5 pushing towards not spam (negative `weight`). `[link]` and `[number]` stand for any URL or number.

#### `POST /scan-qr`

QR decoding only (kept for compatibility). Up to 10 images, 5 MB each.

```json
{ "images": [{ "id": "image-1", "data": "iVBORw0KGgo..." }] }
```

Returns `qr_codes` (`image_id`, `content`, `type`, `indicators`) and `images_scanned`.

### Limitations and known gaps

- **Not yet verified in a real Gmail account.** During development the extension was tested against simulated Gmail pages, and the scan pipeline end to end against the real backend. Gmail's class names (`h2.hP`, `.adn`, `.a3s`, `span.gD`, `.aZo`, `download_url`) are not a public API and may change; fallbacks exist and are reported as extraction warnings.
- **Automatic "Show original" header fetching** depends on finding Gmail's account key (`ik`) in the page. If it isn't found, SPF/DKIM/DMARC are reported as not checked, and you can paste the headers in the side panel.
- **Attachment downloads** use Gmail's download links. Some attachments (for example, ones Gmail blocks as dangerous) can't be downloaded; they are still checked by name and type and marked "name/type only".
- **Images Gmail hides** behind "Display images below" are not scanned until you show them.
- **PDF inspection** reads uncompressed objects only; compressed object streams are noted but not decompressed. RAR/7z contents are not listed.
- **The text model** was trained on 2008 emails (CEAS_08). Some learned weights are surprising (for example, "password" pushes towards *not* spam), so the other analyzers matter for modern phishing.
- **Reputation checks** need a Google Safe Browsing API key on the backend.

---

## Tech stack

- **Backend:** Python, FastAPI, Uvicorn, scikit-learn, OpenCV, BeautifulSoup, RapidOCR (optional)
- **Extension:** Chrome Manifest V3, plain JavaScript (ES modules)
