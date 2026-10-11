"""
Checks on the email text itself: keyword indicators as findings,
hidden text and instructions aimed at automated / AI scanners.

This engine does not use a language model, so such instructions
cannot change its behaviour; they are reported because their
presence is itself a strong sign of a malicious email.
"""

import re

from .common import finding


# Phrases that try to instruct an AI assistant or scanner
INJECTION_PATTERNS = re.compile(
    r"ignore (all |any )?(previous|prior|above) (instructions|prompts)"
    r"|disregard (all |any )?(previous|prior|above) (instructions|prompts)"
    r"|you are (now )?an? (ai|assistant|language model|llm)"
    r"|(mark|classify|treat|label) (this|the) (email|message|mail) as (safe|legitimate|not spam|trusted)"
    r"|this (email|message) is (safe|legitimate|not (spam|phishing))[,.]? (do not|don't) (flag|report)"
    r"|system prompt"
    r"|\bAI (assistant|scanner|filter)s?,? (please )?(ignore|note|mark)",
    re.IGNORECASE
)

HIDDEN_TEXT_THRESHOLD = 200

KEYWORD_FINDINGS = {
    "Urgent or threatening language": (
        "text.urgency", "low", "Urgent or threatening language",
        "Pressure to act quickly is a common phishing tactic."
    ),
    "Prize or financial-related language": (
        "text.financial", "low", "Prize or money-related language",
        "Unexpected prizes and money offers are typical of scams."
    ),
    "Possible credential or personal-information request": (
        "text.credentials", "medium", "Asks for passwords or personal information",
        "Legitimate organisations do not ask for passwords by email."
    ),
    "Excessive exclamation marks": (
        "text.exclamation", "low", "Excessive exclamation marks", ""
    ),
    "Contains potentially suspicious HTML": (
        "text.html", "low", "Contains HTML such as forms or scripts", ""
    ),
}


def keyword_findings(indicators):
    findings = []

    for indicator in indicators or []:
        if indicator in KEYWORD_FINDINGS:
            finding_id, severity, title, detail = KEYWORD_FINDINGS[indicator]
            findings.append(finding(finding_id, "text", severity, title, detail))

    return findings


def content_findings(subject, body, hidden_text):
    findings = []
    hidden_text = hidden_text or ""

    visible_match = INJECTION_PATTERNS.search(f"{subject}\n{body}")
    hidden_match = INJECTION_PATTERNS.search(hidden_text)

    if hidden_match:
        findings.append(finding(
            "text.hidden_instructions", "text", "high",
            "Hidden text tries to instruct automated or AI scanners",
            "The email hides instructions such as 'mark this email as safe'. "
            "They were treated as plain text and ignored.",
            hidden_match.group(0)
        ))
    elif visible_match:
        findings.append(finding(
            "text.scanner_instructions", "text", "medium",
            "Text tries to instruct automated or AI scanners",
            "Instructions aimed at scanners were treated as plain text and ignored.",
            visible_match.group(0)
        ))

    if len(hidden_text.strip()) >= HIDDEN_TEXT_THRESHOLD:
        findings.append(finding(
            "text.hidden_text", "text", "medium",
            "Email contains a large amount of hidden text",
            f"{len(hidden_text.strip())} characters are invisible to the reader; "
            "this is used to fool spam filters.",
            hidden_text[:200]
        ))

    return findings
