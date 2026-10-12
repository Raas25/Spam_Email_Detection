// Helpers shared by the popup and the side panel.

export async function getActiveTab() {

    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });

    return tab || null;
}

export function isGmailTab(tab) {
    return Boolean(tab && tab.url && tab.url.startsWith("https://mail.google.com/"));
}


// Call render(state) now and whenever the tab's scan state changes.
// Returns a function that stops watching.
export function watchTabState(tabId, render) {

    const key = `scan:${tabId}`;

    const listener = (changes, area) => {
        if (area === "session" && changes[key]) {
            render(changes[key].newValue || { status: "idle" });
        }
    };

    chrome.storage.onChanged.addListener(listener);

    chrome.runtime.sendMessage({ type: "GET_STATE", tabId })
        .then((state) => render(state || { status: "idle" }))
        .catch(() => render({ status: "idle" }));

    return () => chrome.storage.onChanged.removeListener(listener);
}


export async function describeBackend(element) {

    const response = await chrome.runtime.sendMessage({ type: "CHECK_BACKEND" }).catch(() => null);

    if (!response || !response.ok) {
        element.className = "backend-status down";
        element.textContent = response ? response.error : "The extension's background worker did not respond.";
        return null;
    }

    const caps = response.capabilities || {};
    const ocr = caps.ocr && caps.ocr.available ? `OCR: ${caps.ocr.detail}` : "OCR: not installed";
    const reputation = caps.reputation && caps.reputation.available ? "reputation: on" : "reputation: off";

    element.className = "backend-status ok";
    element.textContent = `Backend online at ${response.backendUrl} · ${ocr} · ${reputation}`;

    return caps;
}
