// Pure helpers used by the service worker (no chrome.* calls),
// kept separate so they can be unit tested.

export const LIMITS = Object.freeze({
    maxImages: 10,
    maxAttachments: 10,
    maxFileBytes: 5 * 1024 * 1024,
    maxHeaderChars: 256 * 1024,
    maxRequestBytes: 70 * 1024 * 1024,
    fetchTimeoutMs: 15000,
    analyzeTimeoutMs: 90000
});


// Convert an ArrayBuffer to base64 in chunks
// (avoids call-stack limits on large files)
export function arrayBufferToBase64(buffer) {

    const bytes = new Uint8Array(buffer);
    const chunkSize = 0x8000;
    let binary = "";

    for (let i = 0; i < bytes.length; i += chunkSize) {
        binary += String.fromCharCode.apply(
            null,
            bytes.subarray(i, i + chunkSize)
        );
    }

    return btoa(binary);
}


// Only Gmail's own attachment URLs may be fetched with the
// user's cookies; anything else extracted from an email is refused.
export function isAllowedGmailUrl(url) {

    try {
        const parsed = new URL(url);

        return parsed.protocol === "https:" && parsed.hostname === "mail.google.com";
    } catch {
        return false;
    }
}


// Email images are served by Gmail's image proxy or inline as data:
export function isAllowedImageUrl(url) {

    if (typeof url !== "string") {
        return false;
    }

    if (/^data:image\/(png|jpe?g|gif|webp|bmp);base64,/i.test(url)) {
        return true;
    }

    try {
        const parsed = new URL(url);

        return (
            parsed.protocol === "https:" &&
            (parsed.hostname.endsWith(".googleusercontent.com") || parsed.hostname === "mail.google.com")
        );
    } catch {
        return false;
    }
}


// Build Gmail's "Show original" URL for a message
export function buildShowOriginalUrl(locator) {

    if (!locator || !locator.ik || !locator.messageId) {
        return null;
    }

    if (!/^[0-9a-f]{6,16}$/i.test(locator.ik)) {
        return null;
    }

    const account = /^\d{1,2}$/.test(String(locator.account ?? "0")) ? String(locator.account ?? "0") : "0";
    const params = new URLSearchParams({ ik: locator.ik, view: "om" });

    if (/^msg-[af]:\d{5,25}$/.test(locator.messageId)) {
        params.set("permmsgid", locator.messageId);
    } else if (/^[0-9a-f]{8,20}$/i.test(locator.messageId)) {
        params.set("th", locator.messageId);
    } else {
        return null;
    }

    return `https://mail.google.com/mail/u/${account}/?${params.toString()}`;
}


const ENTITIES = { lt: "<", gt: ">", amp: "&", quot: "\"", apos: "'", nbsp: " " };

export function decodeHtmlEntities(text) {

    return text.replace(/&(#x[0-9a-f]+|#\d+|[a-z]+);/gi, (match, code) => {

        if (code[0] === "#") {
            const value = code[1].toLowerCase() === "x"
                ? parseInt(code.slice(2), 16)
                : parseInt(code.slice(1), 10);

            return Number.isFinite(value) && value > 0 && value < 0x110000
                ? String.fromCodePoint(value)
                : "";
        }

        return ENTITIES[code.toLowerCase()] ?? match;
    });
}


// Extract the header section from the "Show original" page HTML.
// Returns null when the page does not contain a raw message.
export function extractRawHeaders(html) {

    if (typeof html !== "string") {
        return null;
    }

    const match = html.match(/<pre[^>]*(?:class|id)="raw_message_text"[^>]*>([\s\S]*?)<\/pre>/i);

    if (!match) {
        return null;
    }

    const raw = decodeHtmlEntities(match[1]).replace(/\r\n/g, "\n");
    const headers = raw.split(/\n\n/, 1)[0];

    if (!/^[A-Za-z-]+:/m.test(headers)) {
        return null;
    }

    return headers.slice(0, LIMITS.maxHeaderChars);
}


export function verdictBadge(verdict) {

    return {
        dangerous: { text: "!", color: "#d93025" },
        suspicious: { text: "?", color: "#e37400" },
        safe: { text: "✓", color: "#188038" }
    }[verdict] || { text: "", color: "#5f6368" };
}


export function friendlyFetchError(error, what) {

    if (error && error.name === "AbortError") {
        return `Timed out while downloading the ${what}.`;
    }

    return `Could not download the ${what} (${error && error.message ? error.message : "network error"}).`;
}
