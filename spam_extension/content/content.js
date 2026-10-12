// Gmail content script: "Check Spam" button, compact result overlay,
// navigation tracking and extraction on request.
// Requires gmail-extract.js (loaded first).

(function () {

    // Guard against double injection (manifest + scripting.executeScript)
    if (globalThis.__spamCheckerLoaded) {
        return;
    }
    globalThis.__spamCheckerLoaded = true;

    const Extract = globalThis.GmailExtract;

    const PAGE_DEFAULTS = { showPageButton: true, autoScan: false };

    let settings = { ...PAGE_DEFAULTS };
    let currentKey = null;
    let lastAutoScannedKey = null;
    let button = null;
    let checkTimer = null;


    // ---------------------------------------------------------
    // DOM helper: all text goes through textContent, so email
    // content and scan evidence can never inject HTML
    // ---------------------------------------------------------

    function el(tag, styles = {}, text = "") {

        const element = document.createElement(tag);

        Object.assign(element.style, styles);

        if (text) {
            element.textContent = text;
        }

        return element;
    }


    // After the extension is reloaded, this (old) script's
    // runtime is gone and sendMessage throws synchronously.
    function sendToWorker(message) {

        try {
            return chrome.runtime.sendMessage(message);
        } catch (error) {
            return Promise.reject(error);
        }
    }


    // ---------------------------------------------------------
    // Page button
    // ---------------------------------------------------------

    function createButton() {

        button = el("button", {
            position: "fixed",
            bottom: "20px",
            right: "20px",
            zIndex: "99999",
            padding: "12px 18px",
            background: "#d93025",
            color: "white",
            border: "none",
            borderRadius: "8px",
            cursor: "pointer",
            fontSize: "14px",
            fontWeight: "bold",
            boxShadow: "0 2px 8px rgba(0,0,0,0.25)",
            display: "none"
        }, "🔍 Check Spam");

        button.id = "spamCheckerButton";
        button.addEventListener("click", startScan);

        document.body.appendChild(button);
    }

    function setButtonBusy(busy, label) {

        if (!button) {
            return;
        }

        button.disabled = busy;
        button.style.opacity = busy ? "0.8" : "1";
        button.style.cursor = busy ? "progress" : "pointer";
        button.textContent = busy ? `⏳ ${label || "Checking..."}` : "🔍 Check Spam";
    }

    function updateButtonVisibility() {

        if (button) {
            button.style.display = settings.showPageButton && currentKey ? "block" : "none";
        }
    }

    function startScan() {

        setButtonBusy(true, "Starting...");

        sendToWorker({ type: "START_SCAN" }).then((response) => {
            if (!response || !response.ok) {
                setButtonBusy(false);
                showOverlay({ status: "error", error: (response && response.error) || "The scan could not start." });
            }
        }).catch((error) => {
            setButtonBusy(false);
            showOverlay({ status: "error", error: `The extension could not start the scan (${error.message}). Reload the page.` });
        });
    }


    // ---------------------------------------------------------
    // Compact result overlay
    // ---------------------------------------------------------

    const VERDICT_STYLES = {
        dangerous: { title: "⛔ DANGEROUS", color: "#a50e0e", background: "#fce8e6" },
        suspicious: { title: "⚠️ SUSPICIOUS", color: "#8a4b00", background: "#fef3e0" },
        safe: { title: "✅ LOOKS SAFE", color: "#0d652d", background: "#e6f4ea" }
    };

    function removeOverlay() {

        const old = document.getElementById("spamResultBox");

        if (old) {
            old.remove();
        }
    }

    function showOverlay(state) {

        removeOverlay();

        const box = el("div", {
            position: "fixed",
            top: "80px",
            right: "20px",
            width: "340px",
            maxHeight: "calc(100vh - 140px)",
            overflowY: "auto",
            background: "white",
            padding: "16px",
            borderRadius: "12px",
            boxShadow: "0 4px 20px rgba(0,0,0,0.25)",
            zIndex: "99999",
            fontFamily: "Arial, sans-serif",
            fontSize: "13px",
            color: "#222",
            lineHeight: "1.4"
        });

        box.id = "spamResultBox";
        box.setAttribute("role", "dialog");
        box.setAttribute("aria-label", "Spam check result");

        if (state.status === "error") {
            box.appendChild(el("div", { fontWeight: "bold", fontSize: "16px", marginBottom: "8px", color: "#a50e0e" }, "Scan failed"));
            box.appendChild(el("div", {}, String(state.error || "Unknown error.")));
        } else if (state.status === "running") {
            box.appendChild(el("div", { fontWeight: "bold", fontSize: "15px" }, "Scanning this email…"));
            box.appendChild(el("div", { color: "#555", marginTop: "6px" }, String(state.progress || "")));
        } else if (state.status === "done" && state.result) {
            renderResult(box, state.result);
        }

        const actions = el("div", { display: "flex", gap: "8px", marginTop: "12px", flexWrap: "wrap" });

        if (state.status === "done") {
            const details = el("button", {
                padding: "8px 12px", border: "none", borderRadius: "6px",
                background: "#1a73e8", color: "white", cursor: "pointer"
            }, "Full report");

            details.addEventListener("click", () => {
                sendToWorker({ type: "OPEN_SIDE_PANEL" }).then((response) => {
                    if (!response || !response.ok) {
                        details.textContent = "Open the extension icon → Full report";
                        details.disabled = true;
                    }
                }).catch(() => {});
            });

            actions.appendChild(details);
        }

        const close = el("button", {
            padding: "8px 12px", border: "none", borderRadius: "6px",
            background: "#eee", cursor: "pointer"
        }, "Close");

        close.addEventListener("click", removeOverlay);
        actions.appendChild(close);
        box.appendChild(actions);

        document.body.appendChild(box);
    }

    function renderResult(box, result) {

        const style = VERDICT_STYLES[result.verdict] || VERDICT_STYLES.suspicious;

        const banner = el("div", {
            background: style.background,
            color: style.color,
            borderRadius: "8px",
            padding: "10px 12px",
            marginBottom: "10px"
        });

        banner.appendChild(el("div", { fontSize: "17px", fontWeight: "bold" }, `${style.title} · ${result.score}/100`));
        banner.appendChild(el("div", { marginTop: "4px" }, String(result.summary || "")));
        box.appendChild(banner);

        const findings = (result.findings || []).filter((item) => item.severity !== "info").slice(0, 4);

        if (findings.length > 0) {
            box.appendChild(el("div", { fontWeight: "bold", margin: "6px 0 4px" }, "Why"));

            const list = el("ul", { paddingLeft: "18px", margin: "0" });

            findings.forEach((item) => {
                list.appendChild(el("li", { marginBottom: "3px" }, `${String(item.title)} (${String(item.severity)})`));
            });

            box.appendChild(list);
        }

        if (result.recommendations && result.recommendations.length > 0) {
            box.appendChild(el("div", { fontWeight: "bold", margin: "8px 0 4px" }, "What to do"));
            box.appendChild(el("div", {}, String(result.recommendations[0])));
        }

        if (result.partial_analysis) {
            box.appendChild(el(
                "div",
                { marginTop: "8px", padding: "6px 8px", background: "#f1f3f4", borderRadius: "6px", color: "#444" },
                `Partial analysis: ${(result.warnings || []).length} part(s) could not be fully checked. See the full report.`
            ));
        }
    }


    // ---------------------------------------------------------
    // Navigation tracking (Gmail is a single-page app)
    // ---------------------------------------------------------

    function checkOpenEmail() {

        let key = null;

        try {
            key = Extract.getOpenEmailKey(document);
        } catch (error) {
            console.warn("Spam checker: could not inspect the page", error);
        }

        if (key === currentKey) {
            return;
        }

        currentKey = key;
        removeOverlay();
        setButtonBusy(false);
        updateButtonVisibility();

        sendToWorker({ type: "EMAIL_CHANGED", key }).catch(() => {});

        maybeAutoScan();
    }

    function maybeAutoScan() {

        if (settings.autoScan && currentKey && currentKey !== lastAutoScannedKey) {
            lastAutoScannedKey = currentKey;
            startScan();
        }
    }

    function scheduleCheck() {

        clearTimeout(checkTimer);
        checkTimer = setTimeout(checkOpenEmail, 400);
    }


    // ---------------------------------------------------------
    // Messages from the service worker
    // ---------------------------------------------------------

    chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {

        if (sender.id !== chrome.runtime.id) {
            return false;
        }

        if (message.type === "EXTRACT_EMAIL") {
            try {
                sendResponse(Extract.extractOpenEmail(document, window.location));
            } catch (error) {
                sendResponse({ ok: false, reason: "extraction_failed", message: `Could not read the email (${error.message}).` });
            }
            return false;
        }

        if (message.type === "SCAN_STATE") {
            const state = message.state || {};

            // Ignore results for an email that is no longer open
            if (state.messageKey && currentKey && state.messageKey !== currentKey) {
                return false;
            }

            if (state.status === "running") {
                setButtonBusy(true, state.progress || "Checking...");
                showOverlay(state);
            } else {
                setButtonBusy(false);
                showOverlay(state);
            }
            return false;
        }

        if (message.type === "PING") {
            sendResponse({ ok: true });
            return false;
        }

        return false;
    });


    // ---------------------------------------------------------
    // Start
    // ---------------------------------------------------------

    chrome.storage.sync.get(PAGE_DEFAULTS).then((stored) => {
        settings = { ...PAGE_DEFAULTS, ...stored };
        updateButtonVisibility();

        // An email may already be open when Gmail loads
        maybeAutoScan();
    }).catch(() => {});

    chrome.storage.onChanged.addListener((changes, area) => {

        if (area !== "sync") {
            return;
        }

        for (const name of Object.keys(PAGE_DEFAULTS)) {
            if (changes[name]) {
                settings[name] = changes[name].newValue;
            }
        }

        updateButtonVisibility();
    });

    createButton();
    window.addEventListener("hashchange", scheduleCheck);
    window.addEventListener("popstate", scheduleCheck);
    new MutationObserver(scheduleCheck).observe(document.body, { childList: true, subtree: true });
    checkOpenEmail();
})();
