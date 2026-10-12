import { renderMessage, renderState } from "../lib/render.js";
import { describeBackend, getActiveTab, isGmailTab, watchTabState } from "../lib/ui-common.js";


const content = document.getElementById("content");
const scanButton = /** @type {HTMLButtonElement} */ (document.getElementById("scanButton"));
const headersInput = /** @type {HTMLTextAreaElement} */ (document.getElementById("headersInput"));
const headersScanButton = /** @type {HTMLButtonElement} */ (document.getElementById("headersScanButton"));
const backendStatus = document.getElementById("backendStatus");

let tab = null;
let stopWatching = null;
let lastState = { status: "idle" };

function render(state) {

    lastState = state || { status: "idle" };

    if (!isGmailTab(tab)) {
        scanButton.disabled = true;
        headersScanButton.disabled = true;
        renderMessage(content, "info", "Not a Gmail tab", "Switch to a Gmail tab with an open email to scan it.");
        return;
    }

    const running = lastState.status === "running";

    scanButton.disabled = running;
    headersScanButton.disabled = running;
    scanButton.textContent = running ? "Scanning…" : lastState.status === "done" ? "Scan again" : "Scan this email";

    renderState(content, lastState, { compact: false });
}

// Follow the active tab of this window
async function followActiveTab() {

    tab = await getActiveTab();

    if (stopWatching) {
        stopWatching();
        stopWatching = null;
    }

    if (isGmailTab(tab)) {
        stopWatching = watchTabState(tab.id, render);
    } else {
        render({ status: "idle" });
    }
}

async function scan(manualHeaders) {

    if (!tab) {
        return;
    }

    scanButton.disabled = true;

    const response = await chrome.runtime.sendMessage({ type: "START_SCAN", tabId: tab.id, manualHeaders });

    if (!response || !response.ok) {
        renderMessage(content, "error", "Scan failed", (response && response.error) || "The scan could not start.");
        scanButton.disabled = false;
    }
}

scanButton.addEventListener("click", () => scan(null));

headersScanButton.addEventListener("click", () => {

    const headers = headersInput.value.trim();

    if (!/^[A-Za-z-]+:/m.test(headers)) {
        renderMessage(content, "error", "These don't look like email headers", "Paste the text from \"Show original\", starting with lines such as \"Delivered-To:\" or \"Authentication-Results:\".");
        return;
    }

    scan(headers);
});

document.getElementById("settingsButton").addEventListener("click", () => chrome.runtime.openOptionsPage());

chrome.tabs.onActivated.addListener(followActiveTab);
chrome.tabs.onUpdated.addListener((tabId, info) => {
    if (tab && tabId === tab.id && info.url) {
        followActiveTab();
    }
});

followActiveTab();
describeBackend(backendStatus);
