import {
    DEFAULT_SETTINGS,
    getSettings,
    isLocalBackend,
    normalizeBackendUrl,
    saveSettings,
    validateBackendUrl
} from "../lib/settings.js";


const form = document.getElementById("settingsForm");
const backendInput = /** @type {HTMLInputElement} */ (document.getElementById("backendUrl"));
const consentRow = document.getElementById("consentRow");
const consentInput = /** @type {HTMLInputElement} */ (document.getElementById("remoteBackendConsent"));
const saveStatus = document.getElementById("saveStatus");
const testStatus = document.getElementById("testStatus");

const CHECKBOXES = ["scanImages", "ocr", "fetchAttachments", "fetchHeaders", "showPageButton", "autoScan"];

/** @returns {HTMLInputElement} */
function checkbox(name) {
    return /** @type {HTMLInputElement} */ (document.getElementById(name));
}


function setStatus(element, kind, text) {
    element.className = `form-status ${kind}`;
    element.textContent = text;
}

function updateConsentVisibility() {

    const remote = !isLocalBackend(normalizeBackendUrl(backendInput.value));

    consentRow.hidden = !remote;
}

// Non-local backends need a host permission granted by the user
async function ensureBackendPermission(url) {

    if (isLocalBackend(url)) {
        return true;
    }

    const origin = `${new URL(url).origin}/*`;

    return chrome.permissions.request({ origins: [origin] });
}

async function load() {

    const settings = await getSettings();

    backendInput.value = settings.backendUrl;
    consentInput.checked = settings.remoteBackendConsent;

    for (const name of CHECKBOXES) {
        checkbox(name).checked = Boolean(settings[name]);
    }

    updateConsentVisibility();
}

backendInput.addEventListener("input", updateConsentVisibility);

document.getElementById("testButton").addEventListener("click", async () => {

    const url = normalizeBackendUrl(backendInput.value);
    const error = validateBackendUrl(url);

    if (error) {
        setStatus(testStatus, "error", error);
        return;
    }

    if (!(await ensureBackendPermission(url))) {
        setStatus(testStatus, "error", "Permission to contact this server was not granted.");
        return;
    }

    setStatus(testStatus, "", "Testing…");

    const response = await chrome.runtime.sendMessage({ type: "CHECK_BACKEND", url });

    if (response && response.ok) {
        const ocr = response.capabilities.ocr.available ? `OCR: ${response.capabilities.ocr.detail}` : "OCR not installed";
        setStatus(testStatus, "ok", `Connected (engine ${response.capabilities.version}, ${ocr}).`);
    } else {
        setStatus(testStatus, "error", response ? response.error : "No response.");
    }
});

form.addEventListener("submit", async (event) => {

    event.preventDefault();

    const url = normalizeBackendUrl(backendInput.value || DEFAULT_SETTINGS.backendUrl);
    const error = validateBackendUrl(url);

    if (error) {
        setStatus(saveStatus, "error", error);
        backendInput.focus();
        return;
    }

    const remote = !isLocalBackend(url);

    if (remote && !consentInput.checked) {
        setStatus(saveStatus, "error", "Confirm that email content may be sent to this remote server, or use a local backend.");
        consentInput.focus();
        return;
    }

    if (!(await ensureBackendPermission(url))) {
        setStatus(saveStatus, "error", "Permission to contact this server was not granted.");
        return;
    }

    const changes = { backendUrl: url, remoteBackendConsent: remote && consentInput.checked };

    for (const name of CHECKBOXES) {
        changes[name] = checkbox(name).checked;
    }

    await saveSettings(changes);
    setStatus(saveStatus, "ok", "Saved.");
});

load();
