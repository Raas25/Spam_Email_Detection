import { renderMessage, renderState } from "../lib/render.js";
import { describeBackend, getActiveTab, isGmailTab, watchTabState } from "../lib/ui-common.js";


const content = document.getElementById("content");
const scanButton = /** @type {HTMLButtonElement} */ (document.getElementById("scanButton"));
const panelButton = /** @type {HTMLButtonElement} */ (document.getElementById("panelButton"));
const backendStatus = document.getElementById("backendStatus");

const tab = await getActiveTab();
const gmail = isGmailTab(tab);

function render(state) {

    if (!gmail) {
        renderMessage(content, "info", "Not a Gmail tab", "Open an email at mail.google.com, then click the extension icon to scan it.");
        return;
    }

    scanButton.disabled = state.status === "running";
    scanButton.textContent = state.status === "running" ? "Scanning…" : state.status === "done" ? "Scan again" : "Scan this email";

    renderState(content, state, { compact: true });
}

scanButton.addEventListener("click", async () => {

    scanButton.disabled = true;

    const response = await chrome.runtime.sendMessage({ type: "START_SCAN", tabId: tab.id });

    if (!response || !response.ok) {
        renderMessage(content, "error", "Scan failed", (response && response.error) || "The scan could not start.");
        scanButton.disabled = false;
    }
});

panelButton.addEventListener("click", async () => {

    try {
        await chrome.sidePanel.open({ tabId: tab.id });
        window.close();
    } catch (error) {
        renderMessage(content, "error", "Could not open the side panel", error.message);
    }
});

document.getElementById("settingsButton").addEventListener("click", () => chrome.runtime.openOptionsPage());

panelButton.disabled = !gmail;

if (gmail) {
    watchTabState(tab.id, render);
} else {
    render({ status: "idle" });
}

describeBackend(backendStatus);
