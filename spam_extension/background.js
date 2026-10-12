// Background service worker: runs the scan pipeline.
//
//   content script (extract) -> service worker (download images,
//   attachments, headers with the user's Gmail session) -> backend
//   /analyze -> result stored per tab -> popup / side panel / page.
//
// Email images and attachments are only downloaded into memory and
// sent to the configured analysis backend; they are never opened,
// saved to disk or executed. Only Gmail and Gmail-image URLs are
// fetched with the user's cookies.

import { getSettings, isLocalBackend, normalizeBackendUrl } from "./lib/settings.js";
import {
    arrayBufferToBase64,
    buildShowOriginalUrl,
    extractRawHeaders,
    friendlyFetchError,
    isAllowedGmailUrl,
    isAllowedImageUrl,
    LIMITS,
    verdictBadge
} from "./lib/scan-utils.js";


const CONTENT_SCRIPTS = ["content/gmail-extract.js", "content/content.js"];
const runningScans = new Map();


// ---------------------------------------------------------
// Per-tab scan state (chrome.storage.session)
// ---------------------------------------------------------

function stateKey(tabId) {
    return `scan:${tabId}`;
}

/** @returns {Promise<any>} */
async function getState(tabId) {

    /** @type {Record<string, any>} */
    const stored = await chrome.storage.session.get(stateKey(tabId));

    return stored[stateKey(tabId)] || { status: "idle" };
}

async function setState(tabId, state) {

    await chrome.storage.session.set({ [stateKey(tabId)]: state });

    // Keep the Gmail page overlay in sync (ignore tabs without our script)
    chrome.tabs.sendMessage(tabId, { type: "SCAN_STATE", state: pageState(state) }).catch(() => {});
}

// The page overlay only needs a subset of the result
function pageState(state) {

    return {
        status: state.status,
        progress: state.progress,
        error: state.error,
        messageKey: state.messageKey,
        result: state.result ? {
            verdict: state.result.verdict,
            score: state.result.score,
            summary: state.result.summary,
            findings: (state.result.findings || []).slice(0, 8),
            recommendations: state.result.recommendations,
            partial_analysis: state.result.partial_analysis,
            warnings: state.result.warnings
        } : null
    };
}

async function setProgress(tabId, base, progress) {
    await setState(tabId, { ...base, status: "running", progress });
}

async function updateBadge(tabId, verdict) {

    const badge = verdictBadge(verdict);

    await chrome.action.setBadgeText({ tabId, text: badge.text }).catch(() => {});
    await chrome.action.setBadgeBackgroundColor({ tabId, color: badge.color }).catch(() => {});
}


// ---------------------------------------------------------
// Downloads (with timeouts and size limits)
// ---------------------------------------------------------

async function fetchWithTimeout(url, options, timeoutMs) {

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);

    try {
        return await fetch(url, { ...options, signal: controller.signal });
    } finally {
        clearTimeout(timer);
    }
}

async function downloadAsBase64(url, what) {

    try {
        const response = await fetchWithTimeout(
            url,
            { credentials: "include", redirect: "follow", cache: "no-store" },
            LIMITS.fetchTimeoutMs
        );

        if (!response.ok) {
            return { error: `Could not download the ${what} (HTTP ${response.status}).` };
        }

        const length = Number(response.headers.get("content-length") || 0);

        if (length > LIMITS.maxFileBytes) {
            return { error: `The ${what} is larger than the 5 MB limit and was not downloaded.` };
        }

        const contentType = response.headers.get("content-type") || "";

        // Gmail answers with its sign-in or interstitial page when it
        // refuses a download; never treat that HTML as the file.
        if (what === "attachment" && /text\/html/i.test(contentType) && response.redirected) {
            return { error: "Gmail did not allow the attachment to be downloaded (it may be blocked or require a click)." };
        }

        const buffer = await response.arrayBuffer();

        if (buffer.byteLength > LIMITS.maxFileBytes) {
            return { error: `The ${what} is larger than the 5 MB limit and was not analyzed.` };
        }

        return { data: arrayBufferToBase64(buffer), bytes: buffer.byteLength };
    } catch (error) {
        return { error: friendlyFetchError(error, what) };
    }
}

async function collectImages(images) {

    return Promise.all(images.slice(0, LIMITS.maxImages).map(async (image) => {

        if (!isAllowedImageUrl(image.src)) {
            return { id: image.id, data: null, fetch_error: "Image is hosted outside Gmail and was not downloaded." };
        }

        const result = await downloadAsBase64(image.src, "image");

        return { id: image.id, data: result.data || null, fetch_error: result.error || null };
    }));
}

async function collectAttachments(attachments, download) {

    const results = [];

    // One at a time to bound memory use
    for (const attachment of attachments.slice(0, LIMITS.maxAttachments)) {

        const item = {
            id: attachment.id,
            name: attachment.name,
            mime: attachment.mime,
            size_text: attachment.size_text,
            data: null,
            fetch_error: null
        };

        if (!download) {
            item.fetch_error = "Attachment downloads are turned off in settings; only the name and type were checked.";
        } else if (!attachment.url) {
            item.fetch_error = "Gmail did not expose a download link for this attachment.";
        } else if (!isAllowedGmailUrl(attachment.url)) {
            item.fetch_error = "The attachment link is not a Gmail link and was not followed.";
        } else {
            const result = await downloadAsBase64(attachment.url, "attachment");
            item.data = result.data || null;
            item.fetch_error = result.error || null;
        }

        results.push(item);
    }

    return results;
}

async function collectHeaders(locator) {

    const url = buildShowOriginalUrl(locator);

    if (!url) {
        return {
            headers: null,
            error: "Could not locate this message's \"Show original\" page; SPF, DKIM and DMARC were not checked. "
                + "You can paste the headers in the side panel."
        };
    }

    try {
        const response = await fetchWithTimeout(url, { credentials: "include", cache: "no-store" }, LIMITS.fetchTimeoutMs);

        if (!response.ok) {
            return { headers: null, error: `Gmail's "Show original" page returned HTTP ${response.status}; SPF, DKIM and DMARC were not checked.` };
        }

        const html = (await response.text()).slice(0, 20 * 1024 * 1024);
        const headers = extractRawHeaders(html);

        if (!headers) {
            return { headers: null, error: "Gmail's \"Show original\" page did not contain the message headers; SPF, DKIM and DMARC were not checked." };
        }

        return { headers, error: null };
    } catch (error) {
        return { headers: null, error: friendlyFetchError(error, "message headers") + " SPF, DKIM and DMARC were not checked." };
    }
}


// ---------------------------------------------------------
// Talking to the Gmail tab and the backend
// ---------------------------------------------------------

async function extractFromTab(tabId) {

    try {
        return await chrome.tabs.sendMessage(tabId, { type: "EXTRACT_EMAIL" });
    } catch {
        // The tab was open before the extension was installed or reloaded:
        // inject the content scripts and try once more.
        await chrome.scripting.executeScript({ target: { tabId }, files: CONTENT_SCRIPTS });
        return chrome.tabs.sendMessage(tabId, { type: "EXTRACT_EMAIL" });
    }
}

async function callBackend(backendUrl, path, body, timeoutMs) {

    let response;

    try {
        response = await fetchWithTimeout(
            `${backendUrl}${path}`,
            body
                ? { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) }
                : { method: "GET" },
            timeoutMs
        );
    } catch (error) {
        if (error && error.name === "AbortError") {
            throw new Error(`The analysis backend at ${backendUrl} did not answer in time.`);
        }

        throw new Error(
            `Cannot reach the analysis backend at ${backendUrl}. Start it with "uvicorn main:app --port 8000" in the backend folder, or check the URL in Settings.`
        );
    }

    let data = null;

    try {
        data = await response.json();
    } catch {
        // handled below
    }

    if (!response.ok) {
        const detail = data && data.detail
            ? (typeof data.detail === "string" ? data.detail : "The request was rejected as invalid.")
            : `HTTP ${response.status}`;

        throw new Error(`The analysis backend returned an error: ${detail}`);
    }

    if (!data) {
        throw new Error("The analysis backend returned an invalid response.");
    }

    return data;
}

async function checkBackend(url) {

    const settings = await getSettings();
    const backendUrl = normalizeBackendUrl(url || settings.backendUrl);

    try {
        const capabilities = await callBackend(backendUrl, "/capabilities", null, 8000);
        return { ok: true, backendUrl, capabilities };
    } catch (error) {
        return { ok: false, backendUrl, error: error.message };
    }
}


// ---------------------------------------------------------
// Scan pipeline
// ---------------------------------------------------------

async function runScan(tabId, manualHeaders) {

    const settings = await getSettings();
    const backendUrl = normalizeBackendUrl(settings.backendUrl);
    const startedAt = Date.now();

    let base = { status: "running", startedAt, messageKey: null, subject: "" };

    try {
        const tab = await chrome.tabs.get(tabId);

        if (!tab.url || !tab.url.startsWith("https://mail.google.com/")) {
            throw new Error("This tab is not Gmail. Open an email at mail.google.com to scan it.");
        }

        if (!isLocalBackend(backendUrl) && !settings.remoteBackendConsent) {
            throw new Error(
                "The backend is not on this computer and you have not agreed to send email content to it. "
                + "Confirm this in Settings, or use a local backend."
            );
        }

        await setProgress(tabId, base, "Reading the open email…");

        const extracted = await extractFromTab(tabId);

        if (!extracted || !extracted.ok) {
            throw new Error((extracted && extracted.message) || "The email could not be read from the page.");
        }

        base = {
            ...base,
            messageKey: extracted.messageKey,
            subject: extracted.message.subject,
            sender: extracted.message.sender
        };

        const imageCount = settings.scanImages ? extracted.images.length : 0;
        await setProgress(
            tabId,
            base,
            `Downloading ${imageCount} image(s) and ${extracted.attachments.length} attachment(s)…`
        );

        const [images, attachments, headerResult] = await Promise.all([
            settings.scanImages ? collectImages(extracted.images) : Promise.resolve([]),
            collectAttachments(extracted.attachments, settings.fetchAttachments),
            manualHeaders
                ? Promise.resolve({ headers: String(manualHeaders).slice(0, LIMITS.maxHeaderChars), error: null })
                : settings.fetchHeaders
                    ? collectHeaders(extracted.locator)
                    : Promise.resolve({ headers: null, error: "Reading message headers is turned off in settings; SPF, DKIM and DMARC were not checked." })
        ]);

        const payload = {
            message: extracted.message,
            links: extracted.links,
            images,
            attachments,
            headers_raw: headerResult.headers,
            headers_error: headerResult.error,
            extraction: extracted.extraction,
            options: { scan_images: settings.scanImages, ocr: settings.ocr }
        };

        let size = JSON.stringify(payload).length;

        // Drop downloaded file contents (largest first) if the request is too big
        while (size > LIMITS.maxRequestBytes) {
            const largest = [...payload.images, ...payload.attachments]
                .filter((item) => item.data)
                .sort((a, b) => b.data.length - a.data.length)[0];

            if (!largest) {
                break;
            }

            largest.data = null;
            largest.fetch_error = "Skipped: the email's files together exceed the size limit.";
            size = JSON.stringify(payload).length;
        }

        await setProgress(tabId, base, "Analyzing text, links, images and attachments…");

        const result = await callBackend(backendUrl, "/analyze", payload, LIMITS.analyzeTimeoutMs);

        const current = await getState(tabId);

        await setState(tabId, {
            ...base,
            status: "done",
            progress: "",
            finishedAt: Date.now(),
            currentKey: current.currentKey ?? extracted.messageKey,
            extraction: {
                links: extracted.links.length,
                images: extracted.images.length,
                attachments: extracted.attachments.length,
                headers: headerResult.headers ? (manualHeaders ? "pasted" : "fetched") : "unavailable"
            },
            result
        });

        await updateBadge(tabId, result.verdict);
    } catch (error) {
        await setState(tabId, {
            ...base,
            status: "error",
            progress: "",
            finishedAt: Date.now(),
            error: error.message || String(error)
        });

        await updateBadge(tabId, null);
    }
}

function startScan(tabId, manualHeaders) {

    if (runningScans.has(tabId)) {
        return runningScans.get(tabId);
    }

    const promise = runScan(tabId, manualHeaders).finally(() => runningScans.delete(tabId));
    runningScans.set(tabId, promise);

    return promise;
}


// ---------------------------------------------------------
// Message routing
// ---------------------------------------------------------

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {

    // Only accept messages from this extension's own pages and scripts
    if (sender.id !== chrome.runtime.id) {
        return false;
    }

    const tabId = message.tabId ?? (sender.tab && sender.tab.id);

    switch (message.type) {

        case "START_SCAN":
            if (typeof tabId !== "number") {
                sendResponse({ ok: false, error: "No tab to scan." });
                return false;
            }
            startScan(tabId, message.manualHeaders || null);
            sendResponse({ ok: true });
            return false;

        case "GET_STATE":
            getState(tabId).then(sendResponse);
            return true;

        case "EMAIL_CHANGED":
            if (typeof tabId === "number") {
                getState(tabId).then((state) => {
                    chrome.storage.session.set({ [stateKey(tabId)]: { ...state, currentKey: message.key } });

                    if (state.messageKey && state.messageKey !== message.key) {
                        updateBadge(tabId, null);
                    }
                });
            }
            return false;

        case "OPEN_SIDE_PANEL":
            if (typeof tabId !== "number") {
                sendResponse({ ok: false });
                return false;
            }
            chrome.sidePanel.open({ tabId })
                .then(() => sendResponse({ ok: true }))
                .catch((error) => sendResponse({ ok: false, error: error.message }));
            return true;

        case "CHECK_BACKEND":
            checkBackend(message.url).then(sendResponse);
            return true;

        default:
            return false;
    }
});

chrome.tabs.onRemoved.addListener((tabId) => {
    chrome.storage.session.remove(stateKey(tabId)).catch(() => {});
});
