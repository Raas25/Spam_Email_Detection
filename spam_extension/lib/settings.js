// Extension settings (chrome.storage.sync).

export const DEFAULT_SETTINGS = Object.freeze({
    // The local FastAPI backend that runs the analysis engine
    backendUrl: "http://127.0.0.1:8000",

    // Required before email content is sent to a non-local backend
    remoteBackendConsent: false,

    // Download the email's images and scan them for QR codes
    scanImages: true,

    // Read text inside images (needs an OCR engine on the backend)
    ocr: true,

    // Download attachments (up to 5 MB each) for content inspection
    fetchAttachments: true,

    // Read the message headers ("Show original") for SPF/DKIM/DMARC
    fetchHeaders: true,

    // Show the "Check Spam" button inside Gmail
    showPageButton: true,

    // Scan automatically whenever an email is opened
    autoScan: false
});


export function isLocalBackend(url) {

    try {
        const { protocol, hostname } = new URL(url);

        return (
            (protocol === "http:" || protocol === "https:") &&
            (hostname === "127.0.0.1" || hostname === "localhost" || hostname === "[::1]")
        );
    } catch {
        return false;
    }
}


// Returns an error message, or null when the URL is acceptable
export function validateBackendUrl(url) {

    let parsed;

    try {
        parsed = new URL(url);
    } catch {
        return "Enter a full URL, for example http://127.0.0.1:8000";
    }

    if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
        return "The backend URL must start with http:// or https://";
    }

    if (!isLocalBackend(url) && parsed.protocol !== "https:") {
        return "A remote backend must use https://";
    }

    if (parsed.username || parsed.password) {
        return "Do not put credentials in the backend URL.";
    }

    return null;
}


export function normalizeBackendUrl(url) {
    return String(url || "").trim().replace(/\/+$/, "");
}


export async function getSettings() {

    const stored = await chrome.storage.sync.get(DEFAULT_SETTINGS);

    return { ...DEFAULT_SETTINGS, ...stored };
}


export async function saveSettings(changes) {

    const settings = { ...(await getSettings()), ...changes };

    settings.backendUrl = normalizeBackendUrl(settings.backendUrl);

    // Consent is tied to a specific remote backend
    if (isLocalBackend(settings.backendUrl)) {
        settings.remoteBackendConsent = false;
    }

    await chrome.storage.sync.set(settings);

    return settings;
}
