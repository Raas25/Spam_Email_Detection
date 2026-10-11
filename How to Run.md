# How to Run

Step-by-step instructions for running the Spam & Phishing Email Detector: the analysis backend and the Chrome extension for Gmail.

Commands are shown for **Windows** (PowerShell or Command Prompt). Where macOS/Linux differs, the alternative is given below the command.

---

## 1. Prerequisites

| Tool | Version | Needed for |
|---|---|---|
| Python | 3.11 or newer (tested with 3.14) | The analysis backend |
| Google Chrome | 116 or newer | The extension |

Check your Python version:

```bash
python --version
```

---

## 2. Set up the backend (first time only)

Open a terminal in the project folder (the one containing `backend`, `spam_extension` and `README.md`).

```bash
cd backend
python -m venv venv
venv\Scripts\activate
```

macOS/Linux: `source venv/bin/activate`

Install the dependencies:

```bash
pip install -r requirements.txt
```

**Optional: text recognition in images (OCR).** Needed to analyze image-only emails. The OCR models (~15 MB) are downloaded automatically the first time OCR runs.

```bash
pip install -r requirements-ocr.txt
```

---

## 3. Start the backend

From the `backend` folder, with the virtual environment activated:

```bash
uvicorn main:app --port 8000
```

Wait until you see `Uvicorn running on http://127.0.0.1:8000`. Leave this terminal open while you use the extension.

To check that it works, open `http://127.0.0.1:8000/capabilities` in a browser. It shows the engine version and whether OCR is available.

> A warning such as `InconsistentVersionWarning: Trying to unpickle estimator…` at startup is expected and harmless. The model was saved with an older scikit-learn version.

**Next time**, you only need:

```bash
cd backend
venv\Scripts\activate
uvicorn main:app --port 8000
```

---

## 4. Load the extension in Chrome (first time only)

1. Open Chrome and go to `chrome://extensions`.
2. Turn on **Developer mode** (top-right switch).
3. Click **Load unpacked** and select the `spam_extension` folder inside the project.
4. Click the puzzle-piece icon in Chrome's toolbar and **pin** "Spam & Phishing Email Detector".
5. If Gmail was already open, **reload the Gmail tab**.

---

## 5. Scan an email

1. Make sure the backend is running (step 3).
2. Open [Gmail](https://mail.google.com) and **open an email** (not just the inbox list).
3. Start a scan in any of these ways:
   - Click the red **🔍 Check Spam** button in the bottom-right corner of Gmail.
   - Click the extension icon in the toolbar → **Scan this email**.
   - Click the extension icon → **Full report** to open the side panel, then **Scan this email**.
4. Read the result:
   - **Verdict and score**: Safe, Suspicious or Dangerous, from 0 to 100.
   - **Recommended actions**: what to do with the email.
   - **Why this verdict**: each finding with its evidence (shown in the side panel).
   - **Analysis coverage**: what was checked, and anything that couldn't be checked and why.

**Optional: check SPF/DKIM/DMARC manually.** If the report says the headers couldn't be read, open the email's ⋮ menu in Gmail → **Show original**, copy the headers, paste them into the side panel's "Check SPF / DKIM / DMARC with pasted headers" box, and click **Scan with these headers**.

**Settings** (extension icon → Settings) let you change the backend address, turn image/OCR/attachment/header checks on or off, hide the in-page button, or scan automatically when an email opens.

---

## 6. Optional configuration

Set these before starting the backend:

| Variable | Effect |
|---|---|
| `SAFE_BROWSING_API_KEY` | Enables Google Safe Browsing checks of the email's links. Only link addresses (not the email text) are sent to Google. |
| `SPAM_CHECKER_DISABLE_OCR=1` | Turns OCR off even if it is installed. |

Example (PowerShell):

```powershell
$env:SAFE_BROWSING_API_KEY = "your-key"
uvicorn main:app --port 8000
```

---

## 7. Troubleshooting

| Problem | Fix |
|---|---|
| "Cannot reach the analysis backend at http://127.0.0.1:8000" | Start the backend (step 3) and keep its terminal open. |
| No **Check Spam** button in Gmail | Open an email (the button only appears on an open email), reload the Gmail tab, and check that "Show the Check Spam button" is on in Settings. |
| "No open email found" | Open the email itself, not the inbox list. |
| "This tab is not Gmail" | Switch to a `mail.google.com` tab before scanning. |
| Images not scanned | Click **Display images below** in Gmail if shown, then scan again. |
| "OCR: not installed" | Run `pip install -r requirements-ocr.txt` in `backend` and restart the backend. |
| SPF / DKIM / DMARC "not checked" | Paste the headers from **Show original** into the side panel (see step 5). |
| `venv\Scripts\activate` is blocked in PowerShell | Run `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned` once, or use Command Prompt instead. |
| The extension stopped working after editing its files | Click the reload icon on `chrome://extensions`, then reload Gmail. |

---

## 8. Stopping

- **Backend:** press `Ctrl+C` in its terminal.
- **Extension:** turn it off or remove it on `chrome://extensions`.
