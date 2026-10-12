// Renders scan states and results for the popup and side panel.
//
// All values from the backend and the email are inserted with
// textContent only (never innerHTML), and links are shown as plain
// text, never as clickable anchors.

const VERDICT_LABELS = {
    dangerous: "Dangerous",
    suspicious: "Suspicious",
    safe: "Looks safe"
};

const CLASSIFICATION_LABELS = {
    malware: "Possible malware",
    phishing: "Likely phishing",
    spam: "Likely spam",
    suspicious: "Unusual signals",
    legitimate: "No strong warning signs"
};

const CATEGORY_LABELS = {
    model: "Text model",
    text: "Text",
    sender: "Sender",
    links: "Links",
    qr: "QR codes",
    images: "Images",
    attachments: "Attachments",
    authentication: "Authentication",
    reputation: "Reputation"
};

const COMPONENT_LABELS = {
    text_model: "Text model",
    sender: "Sender",
    links: "Links",
    images: "Images",
    qr: "QR codes",
    ocr: "Text in images (OCR)",
    attachments: "Attachments",
    authentication: "SPF / DKIM / DMARC",
    reputation: "Link reputation"
};

const STATUS_LABELS = {
    analyzed: "Checked",
    partial: "Partly checked",
    unavailable: "Not available",
    not_applicable: "Nothing to check",
    skipped: "Skipped"
};


// ---------------------------------------------------------
// DOM helper
// ---------------------------------------------------------

export function h(doc, tag, attributes = {}, ...children) {

    const element = doc.createElement(tag);

    for (const [name, value] of Object.entries(attributes)) {
        if (value === null || value === undefined || value === false) {
            continue;
        }
        if (name === "class") {
            element.className = value;
        } else {
            element.setAttribute(name, String(value));
        }
    }

    for (const child of children.flat(Infinity)) {
        if (child === null || child === undefined || child === false) {
            continue;
        }
        element.append(typeof child === "string" || typeof child === "number" ? String(child) : child);
    }

    return element;
}

function section(doc, title, ...children) {
    return h(doc, "section", { class: "section" }, h(doc, "h2", {}, title), ...children);
}


// ---------------------------------------------------------
// States
// ---------------------------------------------------------

export function renderMessage(container, kind, title, text) {

    const doc = container.ownerDocument;

    container.replaceChildren(
        h(doc, "div", { class: `message message-${kind}`, role: kind === "error" ? "alert" : "status" },
            h(doc, "strong", {}, title),
            text ? h(doc, "p", {}, text) : null
        )
    );
}

export function renderRunning(container, state) {

    const doc = container.ownerDocument;

    container.replaceChildren(
        h(doc, "div", { class: "message message-running", role: "status", "aria-live": "polite" },
            h(doc, "span", { class: "spinner", "aria-hidden": "true" }),
            h(doc, "div", {},
                h(doc, "strong", {}, "Scanning this email…"),
                h(doc, "p", {}, state.progress || "Working…")
            )
        )
    );
}

// Render any per-tab state. Returns true when a result was shown.
export function renderState(container, state, options = {}) {

    if (!state || state.status === "idle") {
        renderMessage(container, "info", "No scan yet", "Open an email in Gmail and choose \"Scan this email\".");
        return false;
    }

    if (state.status === "running") {
        renderRunning(container, state);
        return false;
    }

    if (state.status === "error") {
        renderMessage(container, "error", "Scan failed", state.error || "Unknown error.");
        return false;
    }

    if (state.status === "done" && state.result) {
        renderResult(container, state, options);
        return true;
    }

    renderMessage(container, "info", "No result", "");
    return false;
}


// ---------------------------------------------------------
// Result
// ---------------------------------------------------------

export function isStale(state) {
    return Boolean(state && state.messageKey && state.currentKey && state.messageKey !== state.currentKey);
}

function verdictHeader(doc, state) {

    const result = state.result;
    const verdict = result.verdict;

    return h(doc, "div", { class: `verdict verdict-${verdict}` },
        h(doc, "div", { class: "verdict-top" },
            h(doc, "span", { class: "verdict-label" }, VERDICT_LABELS[verdict] || verdict),
            h(doc, "span", { class: "verdict-score", title: "Risk score from 0 (no risk found) to 100" }, `${result.score}/100`)
        ),
        h(doc, "div", { class: "score-track", role: "meter", "aria-valuemin": 0, "aria-valuemax": 100, "aria-valuenow": result.score, "aria-label": "Risk score" },
            h(doc, "div", { class: "score-bar", style: `width:${Math.max(0, Math.min(100, Number(result.score) || 0))}%` })
        ),
        h(doc, "div", { class: "classification" }, CLASSIFICATION_LABELS[result.classification] || result.classification),
        h(doc, "p", { class: "summary" }, result.summary || ""),
        h(doc, "p", { class: "scanned-email" },
            "Email: ", h(doc, "span", {}, state.subject || "(no subject)"),
            state.sender && state.sender.email ? ` · from ${state.sender.email}` : ""
        )
    );
}

function warningsBlock(doc, result, stale) {

    const items = [];

    if (stale) {
        items.push("This result is for a different email than the one now open. Scan again to check the current email.");
    }

    if (result.partial_analysis) {
        items.push("Partial analysis: some content could not be checked (details below).");
    }

    items.push(...(result.warnings || []));

    if (items.length === 0) {
        return null;
    }

    return h(doc, "div", { class: "warnings", role: stale ? "alert" : null },
        h(doc, "ul", {}, items.map((item) => h(doc, "li", {}, item)))
    );
}

function findingItem(doc, item) {

    return h(doc, "li", { class: `finding severity-${item.severity}` },
        h(doc, "div", { class: "finding-head" },
            h(doc, "span", { class: `badge badge-${item.severity}` }, item.severity),
            h(doc, "span", { class: "finding-title" }, item.title)
        ),
        item.detail ? h(doc, "p", { class: "finding-detail" }, item.detail) : null,
        item.evidence ? h(doc, "code", { class: "evidence", title: "Evidence (shown as text only)" }, item.evidence) : null
    );
}

function findingsBlock(doc, findings, limit) {

    const shown = findings.filter((item) => item.severity !== "info");
    const info = findings.filter((item) => item.severity === "info");

    if (shown.length === 0 && info.length === 0) {
        return section(doc, "Findings", h(doc, "p", { class: "muted" }, "No warning signs were found."));
    }

    if (limit) {
        return section(doc, "Top findings",
            h(doc, "ul", { class: "findings" }, shown.slice(0, limit).map((item) => findingItem(doc, item))),
            shown.length > limit ? h(doc, "p", { class: "muted" }, `+ ${shown.length - limit} more in the full report`) : null,
            shown.length === 0 ? h(doc, "p", { class: "muted" }, "No warning signs were found.") : null
        );
    }

    const groups = new Map();

    for (const item of shown) {
        if (!groups.has(item.category)) {
            groups.set(item.category, []);
        }
        groups.get(item.category).push(item);
    }

    return section(doc, "Why this verdict",
        shown.length === 0 ? h(doc, "p", { class: "muted" }, "No warning signs were found.") : null,
        [...groups.entries()].map(([category, items]) => h(doc, "div", { class: "finding-group" },
            h(doc, "h3", {}, `${CATEGORY_LABELS[category] || category} (${items.length})`),
            h(doc, "ul", { class: "findings" }, items.map((item) => findingItem(doc, item)))
        )),
        info.length ? h(doc, "div", { class: "finding-group" },
            h(doc, "h3", {}, "Information"),
            h(doc, "ul", { class: "findings" }, info.map((item) => findingItem(doc, item)))
        ) : null
    );
}

function recommendationsBlock(doc, result, limit) {

    const items = (result.recommendations || []).slice(0, limit || undefined);

    return section(doc, "Recommended actions",
        h(doc, "ol", { class: "recommendations" }, items.map((item) => h(doc, "li", {}, item)))
    );
}

function coverageBlock(doc, result) {

    return section(doc, "Analysis coverage",
        h(doc, "table", { class: "coverage" },
            h(doc, "tbody", {}, (result.coverage || []).map((entry) => h(doc, "tr", { class: `coverage-${entry.status}` },
                h(doc, "th", { scope: "row" }, COMPONENT_LABELS[entry.component] || entry.component),
                h(doc, "td", {}, h(doc, "span", { class: `status status-${entry.status}` }, STATUS_LABELS[entry.status] || entry.status)),
                h(doc, "td", { class: "coverage-detail" }, entry.detail || "")
            )))
        )
    );
}

function modelBlock(doc, result) {

    const model = result.model;

    if (!model) {
        return null;
    }

    const spamTerms = (model.top_terms || []).filter((term) => term.weight > 0);
    const safeTerms = (model.top_terms || []).filter((term) => term.weight < 0);

    const chips = (terms, kind) => terms.length
        ? h(doc, "div", { class: "chips" }, terms.map((term) => h(doc, "span", { class: `chip chip-${kind}`, title: `weight ${term.weight}` }, term.term)))
        : h(doc, "span", { class: "muted" }, "none");

    return section(doc, "Text model",
        h(doc, "p", {},
            `${model.prediction} · ${Math.round((model.spam_probability || 0) * 100)}% spam probability`,
            model.text_source && model.text_source !== "body" ? ` (includes text read from images)` : ""
        ),
        h(doc, "p", { class: "muted" }, "Words that pushed towards spam:"), chips(spamTerms, "spam"),
        h(doc, "p", { class: "muted" }, "Words that pushed towards not spam:"), chips(safeTerms, "safe")
    );
}

function detailsBlock(doc, result) {

    const rows = [];
    const auth = result.authentication || {};

    if (result.sender) {
        rows.push(["Sender", `${result.sender.name || ""} <${result.sender.email}>`]);
    }

    rows.push(["SPF / DKIM / DMARC", `${auth.spf || "not checked"} / ${auth.dkim || "not checked"} / ${auth.dmarc || "not checked"}`]);

    if (auth.reply_to) {
        rows.push(["Reply-To", auth.reply_to]);
    }

    if (result.links) {
        rows.push(["Links", `${result.links.total} link(s); domains: ${(result.links.unique_domains || []).join(", ") || "none"}`]);
    }

    const blocks = [
        section(doc, "Details",
            h(doc, "dl", { class: "details" }, rows.map(([name, value]) => [h(doc, "dt", {}, name), h(doc, "dd", {}, value)]))
        )
    ];

    if ((result.qr_codes || []).length) {
        blocks.push(section(doc, "QR codes",
            h(doc, "ul", { class: "plain-list" }, result.qr_codes.map((code) => h(doc, "li", {},
                h(doc, "span", { class: "badge badge-info" }, code.type),
                " ",
                h(doc, "code", { class: "evidence" }, code.content)
            )))
        ));
    }

    if ((result.images || []).length) {
        blocks.push(section(doc, "Images",
            h(doc, "ul", { class: "plain-list" }, result.images.map((image) => h(doc, "li", {},
                `${image.id}: ${STATUS_LABELS[image.status] || image.status}`,
                image.status === "analyzed" ? ` · ${image.qr_codes} QR code(s) · ${image.ocr_chars} characters of text read` : "",
                image.note ? ` · ${image.note}` : ""
            )))
        ));
    }

    if ((result.attachments || []).length) {
        const labels = { content: "contents inspected", metadata: "name/type only", unsupported: "type not supported", failed: "could not be parsed" };

        blocks.push(section(doc, "Attachments",
            h(doc, "ul", { class: "plain-list" }, result.attachments.map((attachment) => h(doc, "li", {},
                h(doc, "strong", {}, attachment.name),
                attachment.size ? ` (${attachment.size})` : "",
                ` · ${labels[attachment.inspected] || attachment.inspected}`,
                attachment.findings ? ` · ${attachment.findings} finding(s)` : "",
                (attachment.notes || []).length ? h(doc, "div", { class: "muted" }, attachment.notes.join(" ")) : null
            )))
        ));
    }

    return blocks;
}

export function renderResult(container, state, options = {}) {

    const doc = container.ownerDocument;
    const result = state.result;
    const compact = Boolean(options.compact);

    const parts = [
        verdictHeader(doc, state),
        warningsBlock(doc, result, isStale(state)),
        recommendationsBlock(doc, result, compact ? 2 : 0),
        findingsBlock(doc, result.findings || [], compact ? 4 : 0)
    ];

    if (!compact) {
        parts.push(modelBlock(doc, result));
        parts.push(...detailsBlock(doc, result));
        parts.push(coverageBlock(doc, result));
        parts.push(h(doc, "p", { class: "muted footer-note" },
            `Engine ${result.engine_version || "?"} · analyzed in ${result.elapsed_ms ?? "?"} ms. `
            + "Results are an automated estimate, not a guarantee."
        ));
    }

    container.replaceChildren(...parts.filter(Boolean));
}
