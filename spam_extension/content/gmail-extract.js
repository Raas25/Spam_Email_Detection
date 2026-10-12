// Extracts the currently opened Gmail message from the page DOM.
//
// Loaded as a classic content script (before content.js) and in
// tests; exposes globalThis.GmailExtract. Email content is only
// read as text and attributes: nothing from the email is executed,
// inserted into the page or followed.
//
// Gmail's class names are not a public API. Each lookup has
// fallbacks, and any fallback used is reported as a warning.

(function () {

    const LIMITS = {
        maxBodyChars: 100000,
        maxHiddenChars: 20000,
        maxLinks: 200,
        maxLinkTextChars: 300,
        maxHrefChars: 4096,
        maxImages: 10,
        maxAttachments: 10,
        minImageSize: 60
    };

    const SELECTORS = {
        subject: ["h2.hP", "h2[data-thread-perm-id]", "[role='main'] h2"],
        message: ["div.adn", "div[data-message-id]"],
        body: [".a3s.aiL", ".a3s", ".ii.gt"],
        sender: ["span.gD[email]", ".gD[email]", "[email][name]", "[email]"],
        date: ["span.g3[title]", ".g3[title]"],
        attachmentArea: [".aQH"],
        attachmentChip: [".aZo", ".aQy"]
    };


    // ---------------------------------------------------------
    // Visibility
    // ---------------------------------------------------------

    function hasLayout(doc) {
        return !!doc.body && doc.body.getClientRects().length > 0;
    }

    function isHiddenByStyle(element) {

        const style = element.style;

        if (!style) {
            return false;
        }

        const fontSize = parseFloat(style.fontSize);

        return (
            style.display === "none" ||
            style.visibility === "hidden" ||
            style.opacity === "0" ||
            (Number.isFinite(fontSize) && fontSize <= 1 && /px|pt/.test(style.fontSize))
        );
    }

    // Gmail keeps previously viewed pages in the DOM but hidden,
    // so only visible elements count as the "open" email.
    function isVisible(element) {

        if (!element || !element.isConnected) {
            return false;
        }

        const doc = element.ownerDocument;

        if (hasLayout(doc)) {
            return element.getClientRects().length > 0;
        }

        // No layout engine (tests): check inline styles and the hidden attribute
        for (let node = element; node && node.nodeType === 1; node = node.parentElement) {
            if (node.hidden || isHiddenByStyle(node)) {
                return false;
            }
        }

        return true;
    }

    function firstVisible(root, selectors) {

        for (const selector of selectors) {
            for (const element of root.querySelectorAll(selector)) {
                if (isVisible(element)) {
                    return { element, selector, fallback: selector !== selectors[0] };
                }
            }
        }

        return null;
    }

    function allVisible(root, selectors) {

        for (const selector of selectors) {
            const found = Array.from(root.querySelectorAll(selector)).filter(isVisible);

            if (found.length > 0) {
                return { elements: found, selector, fallback: selector !== selectors[0] };
            }
        }

        return { elements: [], selector: null, fallback: false };
    }


    // ---------------------------------------------------------
    // Text helpers
    // ---------------------------------------------------------

    function readText(element) {

        if (!element) {
            return "";
        }

        // innerText follows rendering (skips hidden text);
        // textContent is used where no layout engine exists.
        const text = typeof element.innerText === "string" && hasLayout(element.ownerDocument)
            ? element.innerText
            : element.textContent;

        return (text || "").replace(/\u00a0/g, " ");
    }

    function clip(text, limit) {
        text = String(text || "");
        return text.length > limit ? text.slice(0, limit) : text;
    }

    function collectHiddenText(body) {

        const parts = [];
        let total = 0;

        for (const element of body.querySelectorAll("*")) {

            if (!isHiddenByStyle(element)) {
                continue;
            }

            // Count only the outermost hidden element
            const parent = element.parentElement;
            if (parent && parent !== body && parent.closest && hiddenAncestor(parent, body)) {
                continue;
            }

            const text = (element.textContent || "").replace(/\s+/g, " ").trim();

            if (text) {
                parts.push(text);
                total += text.length;
            }

            if (total >= LIMITS.maxHiddenChars) {
                break;
            }
        }

        return clip(parts.join("\n"), LIMITS.maxHiddenChars);
    }

    function hiddenAncestor(element, stop) {

        for (let node = element; node && node !== stop; node = node.parentElement) {
            if (isHiddenByStyle(node)) {
                return true;
            }
        }

        return false;
    }


    // ---------------------------------------------------------
    // Message location
    // ---------------------------------------------------------

    function findOpenMessage(doc) {

        const subject = firstVisible(doc, SELECTORS.subject);
        const messages = allVisible(doc, SELECTORS.message);
        const warnings = [];

        // Messages whose body is shown (expanded in the conversation)
        const expanded = messages.elements.filter((message) => firstVisible(message, SELECTORS.body));

        let container = null;
        let body = null;

        if (expanded.length > 0) {
            // The most recent expanded message is the one being read
            container = expanded[expanded.length - 1];
            body = firstVisible(container, SELECTORS.body);
        } else {
            // Fallback: any visible message body on the page
            body = firstVisible(doc, SELECTORS.body);
            if (body) {
                container = body.element.closest("div[data-message-id], div.adn") || body.element.parentElement;
                warnings.push("Gmail's message layout was not recognised; used a fallback to find the email body.");
            }
        }

        if (!body) {
            return null;
        }

        if (body.fallback) {
            warnings.push("The email body was found with a fallback selector; extraction may be incomplete.");
        }

        if (expanded.length > 1) {
            warnings.push(
                `This conversation has ${expanded.length} expanded messages; the most recent one was analyzed.`
            );
        }

        return {
            subjectElement: subject ? subject.element : null,
            container,
            body: body.element,
            messageCount: messages.elements.length,
            expandedCount: expanded.length,
            warnings
        };
    }


    // ---------------------------------------------------------
    // Parts of the message
    // ---------------------------------------------------------

    function extractSender(container) {

        const found = container ? firstVisible(container, SELECTORS.sender) : null;

        if (!found) {
            return { sender: null, warning: "The sender's name and address could not be found." };
        }

        const element = found.element;
        const email = (element.getAttribute("email") || "").trim();
        const name = (element.getAttribute("name") || readText(element)).trim();

        return {
            sender: { name: clip(name, 500), email: clip(email, 320) },
            warning: found.fallback ? "The sender was found with a fallback selector." : null
        };
    }

    function extractLinks(body) {

        const links = [];
        const anchors = body.querySelectorAll("a[href]");

        for (const anchor of anchors) {

            if (links.length >= LIMITS.maxLinks) {
                break;
            }

            const href = (anchor.getAttribute("href") || "").trim();

            if (!href || href.startsWith("#")) {
                continue;
            }

            links.push({
                text: clip(readText(anchor).replace(/\s+/g, " ").trim(), LIMITS.maxLinkTextChars),
                href: clip(href, LIMITS.maxHrefChars)
            });
        }

        return { links, truncated: anchors.length > LIMITS.maxLinks };
    }

    function imageSize(img, name) {

        const natural = name === "width" ? img.naturalWidth : img.naturalHeight;
        const attribute = parseInt(img.getAttribute(name) || "", 10);

        return natural || (Number.isFinite(attribute) ? attribute : 0);
    }

    function extractImages(body) {

        const images = [];
        const seen = new Set();

        for (const img of body.querySelectorAll("img")) {

            const src = (img.currentSrc || img.getAttribute("src") || "").trim();
            const width = imageSize(img, "width");
            const height = imageSize(img, "height");

            if (!src || src.startsWith("blob:") || seen.has(src)) {
                continue;
            }

            // Icons and tracking pixels (size known and small)
            if ((width && width < LIMITS.minImageSize) || (height && height < LIMITS.minImageSize)) {
                continue;
            }

            seen.add(src);

            images.push({
                id: `image-${images.length + 1}`,
                src: clip(src, 8 * 1024 * 1024),
                alt: clip(img.getAttribute("alt") || "", 200),
                width,
                height
            });

            if (images.length >= LIMITS.maxImages) {
                break;
            }
        }

        return images;
    }

    // Gmail attribute: download_url="mime/type:file name.pdf:https://mail.google.com/..."
    function parseDownloadUrl(value) {

        const match = /^([^:]+\/[^:]+):(.+?):(https:\/\/mail\.google\.com\/.+)$/.exec(value || "");

        return match ? { mime: match[1], name: match[2], url: match[3] } : null;
    }

    function extractAttachments(container) {

        const attachments = [];
        const warnings = [];

        if (!container) {
            return { attachments, warnings };
        }

        const byName = new Map();

        for (const element of container.querySelectorAll("[download_url]")) {
            const parsed = parseDownloadUrl(element.getAttribute("download_url"));
            if (parsed && !byName.has(parsed.name)) {
                byName.set(parsed.name, { name: parsed.name, mime: parsed.mime, url: parsed.url, size_text: "" });
            }
        }

        for (const selector of SELECTORS.attachmentChip) {
            for (const chip of container.querySelectorAll(selector)) {

                const nameElement = chip.querySelector(".aV3");
                const name = (nameElement ? readText(nameElement) : chip.getAttribute("aria-label") || "").trim();

                if (!name) {
                    continue;
                }

                const sizeElement = chip.querySelector(".SaH2Ve");
                const link = chip.querySelector("a[href*='mail.google.com'], a[href*='view=att'], a[href*='disp=']");
                const existing = byName.get(name) || { name, mime: "", url: "", size_text: "" };

                existing.size_text = existing.size_text || (sizeElement ? readText(sizeElement).trim() : "");
                existing.url = existing.url || (link ? link.href || link.getAttribute("href") : "");

                byName.set(name, existing);
            }
        }

        for (const item of byName.values()) {

            if (attachments.length >= LIMITS.maxAttachments) {
                warnings.push(`Only the first ${LIMITS.maxAttachments} attachments were analyzed.`);
                break;
            }

            attachments.push({
                id: `attachment-${attachments.length + 1}`,
                name: clip(item.name, 500),
                mime: clip(item.mime, 200),
                size_text: clip(item.size_text, 50),
                url: clip(item.url, 4096)
            });
        }

        const area = firstVisible(container, SELECTORS.attachmentArea);

        if (area && attachments.length === 0) {
            warnings.push("Attachments are shown but could not be read from the page.");
        }

        return { attachments, warnings };
    }


    // ---------------------------------------------------------
    // Locating the message for "Show original"
    // ---------------------------------------------------------

    function findAccountKey(doc) {

        // ik= appears in Gmail's own attachment/print URLs
        for (const element of doc.querySelectorAll("[download_url], a[href*='ik=']")) {
            const value = element.getAttribute("download_url") || element.getAttribute("href") || "";
            const match = /[?&]ik=([0-9a-f]{6,16})/i.exec(value);
            if (match) {
                return match[1];
            }
        }

        // Gmail's bootstrap data: GLOBALS=[..., ..., "<ik>", ...] (10th entry)
        for (const script of doc.querySelectorAll("script:not([src])")) {
            const text = script.textContent || "";
            const index = text.indexOf("GLOBALS=");
            if (index === -1) {
                continue;
            }
            const match = /GLOBALS=\[(?:[^,\]]*,){9}"([0-9a-f]{6,16})"/i.exec(text.slice(index, index + 4000));
            if (match) {
                return match[1];
            }
        }

        return null;
    }

    function getMessageLocator(container, doc, location) {

        const element = container && (container.matches("[data-message-id]")
            ? container
            : container.querySelector("[data-message-id]"));

        const messageId = element ? (element.getAttribute("data-message-id") || "").replace(/^#/, "") : "";
        const legacyElement = container && (container.matches("[data-legacy-message-id]")
            ? container
            : container.querySelector("[data-legacy-message-id]"));
        const legacyId = legacyElement ? legacyElement.getAttribute("data-legacy-message-id") || "" : "";
        const account = /\/mail\/u\/(\d+)/.exec(location ? location.pathname : "");

        return {
            messageId: messageId || legacyId || null,
            ik: findAccountKey(doc),
            account: account ? account[1] : "0"
        };
    }


    // ---------------------------------------------------------
    // Public API
    // ---------------------------------------------------------

    // Cheap identifier of the open email, used to notice navigation
    function getOpenEmailKey(doc) {

        const open = findOpenMessage(doc);

        if (!open) {
            return null;
        }

        const locator = getMessageLocator(open.container, doc, null);
        const subject = open.subjectElement ? readText(open.subjectElement).trim() : "";

        return locator.messageId
            ? `id:${locator.messageId}`
            : `text:${subject}|${open.expandedCount}|${readText(open.body).length}`;
    }

    function extractOpenEmail(doc, location) {

        location = location || doc.location;

        if (!location || location.hostname !== "mail.google.com") {
            return {
                ok: false,
                reason: "unsupported_page",
                message: "This page is not Gmail. Open an email at mail.google.com to scan it."
            };
        }

        const open = findOpenMessage(doc);

        if (!open) {
            return {
                ok: false,
                reason: "no_email_open",
                message: "No open email found. Open an email (not the inbox list) and try again."
            };
        }

        const warnings = open.warnings.slice();
        const subject = open.subjectElement ? readText(open.subjectElement).trim() : "";

        if (!open.subjectElement) {
            warnings.push("The subject could not be found.");
        }

        const senderResult = extractSender(open.container);
        if (senderResult.warning) {
            warnings.push(senderResult.warning);
        }

        const bodyText = readText(open.body);

        if (bodyText.length > LIMITS.maxBodyChars) {
            warnings.push(`The email body is very long; only the first ${LIMITS.maxBodyChars.toLocaleString("en-US")} characters were analyzed.`);
        }

        const linkResult = extractLinks(open.body);
        if (linkResult.truncated) {
            warnings.push(`Only the first ${LIMITS.maxLinks} links were analyzed.`);
        }

        const images = extractImages(open.body);
        const attachmentResult = extractAttachments(open.container);
        warnings.push(...attachmentResult.warnings);

        // Gmail may block external images until the user allows them
        const containerText = readText(open.container);
        if (/display images below|images are not displayed/i.test(containerText)) {
            warnings.push("Gmail is hiding some images in this email. Click \"Display images below\" and scan again to include them.");
        }

        const locator = getMessageLocator(open.container, doc, location);
        const subjectText = clip(subject, 2000);

        return {
            ok: true,
            source: "gmail",
            messageKey: locator.messageId
                ? `id:${locator.messageId}`
                : `text:${subjectText}|${open.expandedCount}|${bodyText.length}`,
            message: {
                subject: subjectText,
                body_text: clip(bodyText, LIMITS.maxBodyChars),
                hidden_text: collectHiddenText(open.body),
                sender: senderResult.sender,
                date: open.container ? clip((firstVisible(open.container, SELECTORS.date) || { element: null }).element?.getAttribute("title") || "", 200) : ""
            },
            links: linkResult.links,
            images,
            attachments: attachmentResult.attachments,
            locator,
            extraction: {
                source: "gmail",
                warnings,
                thread_messages: open.messageCount,
                expanded_messages: open.expandedCount
            }
        };
    }

    globalThis.GmailExtract = {
        LIMITS,
        extractOpenEmail,
        getOpenEmailKey,
        parseDownloadUrl,
        isVisible
    };
})();
