"""
Risk scoring: turns findings into a 0-100 score, a verdict,
a classification and recommended actions.

Scoring rules (documented so results can be explained):
  * Each finding has points by severity: info 0, low 5, medium 12,
    high 25, critical 40. Repeated findings with the same id count
    once (the highest).
  * Points are capped per category so one noisy area cannot
    dominate (CATEGORY_CAPS).
  * The text model adds points by spam probability (model_points).
  * Score = min(100, total).
  * Verdict: "dangerous" if score >= 50 or any critical finding,
    "suspicious" if score >= 20, otherwise "safe".
"""

from .common import SEVERITY_ORDER


DANGEROUS_THRESHOLD = 50
SUSPICIOUS_THRESHOLD = 20

CATEGORY_CAPS = {
    "text": 45,
    "sender": 50,
    "links": 60,
    "qr": 60,
    "images": 40,
    "attachments": 80,
    "authentication": 50,
    "reputation": 80,
}

PHISHING_IDS = {
    "links.deceptive_text", "links.lookalike_domain", "links.brand_in_domain",
    "links.ip_host", "links.at_sign", "links.punycode",
    "qr.link", "qr.lookalike_domain", "qr.brand_in_domain", "qr.ip_host",
    "qr.deceptive_text", "qr.punycode", "qr.at_sign",
    "sender.brand_impersonation", "sender.lookalike_domain",
    "sender.name_contains_other_address", "sender.punycode_domain",
    "attachments.html_password_form", "attachments.html_form", "attachments.html_file",
    "text.credentials", "text.hidden_instructions", "reputation.blocklisted",
    "auth.dmarc_fail",
}

MALWARE_IDS = {
    "attachments.executable", "attachments.disguised_executable",
    "attachments.archive_executable", "attachments.macro_extension",
    "attachments.office_macros", "attachments.office_remote_template",
    "attachments.pdf_active_content", "attachments.bidi_filename",
    "attachments.scriptable_document", "attachments.archive_macro_document",
    "links.executable_download", "qr.executable_download",
}


def model_points(spam_probability):
    if spam_probability is None:
        return 0
    if spam_probability >= 0.9:
        return 30
    if spam_probability >= 0.75:
        return 22
    if spam_probability >= 0.5:
        return 15
    return 0


def sort_findings(findings):
    return sorted(
        findings,
        key=lambda item: (SEVERITY_ORDER.index(item["severity"]), item["category"], item["id"])
    )


def compute_score(findings, spam_probability):
    best = {}

    for item in findings:
        current = best.get(item["id"])
        if current is None or item["points"] > current["points"]:
            best[item["id"]] = item

    per_category = {}

    for item in best.values():
        per_category[item["category"]] = per_category.get(item["category"], 0) + item["points"]

    breakdown = {
        category: min(points, CATEGORY_CAPS.get(category, 50))
        for category, points in per_category.items()
        if points > 0
    }

    text_model = model_points(spam_probability)

    if text_model:
        breakdown["model"] = text_model

    score = min(100, sum(breakdown.values()))

    return score, breakdown


def get_verdict(score, findings):
    if score >= DANGEROUS_THRESHOLD or any(item["severity"] == "critical" for item in findings):
        return "dangerous"

    if score >= SUSPICIOUS_THRESHOLD:
        return "suspicious"

    return "safe"


def get_classification(verdict, findings, model_result):
    significant = {
        item["id"] for item in findings
        if item["severity"] in ("medium", "high", "critical")
    }

    if significant & MALWARE_IDS:
        return "malware"

    if significant & PHISHING_IDS:
        if verdict != "safe":
            return "phishing"

    is_spam = bool(model_result) and model_result.get("prediction") == "SPAM"

    if verdict == "safe":
        return "legitimate"

    if is_spam:
        return "spam"

    return "suspicious"


def get_recommendations(verdict, classification, findings, coverage_entries):
    recommendations = []
    ids = {item["id"] for item in findings}
    categories = {item["category"] for item in findings if item["severity"] != "info"}

    if verdict == "dangerous":
        recommendations.append("Do not click links, scan QR codes, or open attachments in this email.")
        recommendations.append("Do not reply, and never enter passwords or payment details from this email.")
        recommendations.append("Report it in Gmail: open the ⋮ (More) menu on the message and choose \"Report phishing\".")
        recommendations.append("If you already clicked or entered details, change that password and contact your bank or IT team.")
    elif verdict == "suspicious":
        recommendations.append("Verify the request through a channel you already trust (official website or phone number), not via this email.")
        recommendations.append("Avoid clicking links or opening attachments until you have verified the sender.")

        if classification == "spam":
            recommendations.append("If it is unwanted, mark it as spam in Gmail.")
    else:
        recommendations.append("No strong warning signs were found. Stay cautious with unexpected requests for money, passwords or urgent action.")

    if "attachments" in categories and verdict != "safe":
        recommendations.append("Do not open or enable content in the flagged attachments.")

    if "qr" in categories:
        recommendations.append("Do not scan the QR code with your phone.")

    if ids & {"sender.brand_impersonation", "sender.lookalike_domain", "links.lookalike_domain"}:
        recommendations.append("Go to the real website by typing its address yourself instead of using this email.")

    statuses = {entry["component"]: entry["status"] for entry in coverage_entries}

    if statuses.get("authentication") == "unavailable" and verdict != "safe":
        recommendations.append("To check SPF/DKIM/DMARC yourself, open ⋮ → \"Show original\" in Gmail.")

    return list(dict.fromkeys(recommendations))


def get_summary(verdict, classification, score, findings):
    top = [item["title"] for item in sort_findings(findings) if item["severity"] != "info"][:2]

    label = {
        "dangerous": "Dangerous",
        "suspicious": "Suspicious",
        "safe": "Safe"
    }[verdict]

    kind = {
        "malware": "possible malware delivery",
        "phishing": "likely phishing",
        "spam": "likely spam",
        "suspicious": "unusual signals",
        "legitimate": "no strong warning signs",
    }[classification]

    text = f"{label} ({score}/100): {kind}."

    if top:
        text += " Main reasons: " + "; ".join(top) + "."

    return text
