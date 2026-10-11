"""
Sender analysis: display-name spoofing, brand impersonation and
look-alike sender domains. Uses only the From name and address
shown by Gmail; authentication results come from headers.py.
"""

import re

from .common import coverage, finding
from .domains import (
    brands_in_host,
    brands_in_text,
    FREE_MAIL_DOMAINS,
    is_official_domain,
    registrable_domain,
)


EMAIL_IN_TEXT = re.compile(r"[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}", re.IGNORECASE)

# Display names that claim an organisation role
ROLE_WORDS = re.compile(
    r"\b(support|security|billing|helpdesk|help desk|service|admin|"
    r"administrator|account|team|bank|payroll|it department|no-?reply)\b",
    re.IGNORECASE
)


def analyze_sender(sender):
    """
    sender: {"name": str, "email": str} (either may be missing).
    Returns (findings, coverage_entry, summary).
    """

    sender = sender or {}
    name = (sender.get("name") or "").strip()
    email = (sender.get("email") or "").strip().lower()

    if not email or "@" not in email:
        return [], coverage(
            "sender",
            "unavailable",
            "The sender's address could not be read from the page."
        ), None

    domain = registrable_domain(email.rsplit("@", 1)[1])
    findings = []

    # A different email address written inside the display name,
    # e.g. "service@paypal.com <random@evil.example>"
    for shown in EMAIL_IN_TEXT.findall(name):
        if shown.lower() != email:
            findings.append(finding(
                "sender.name_contains_other_address", "sender", "high",
                "Display name contains a different email address",
                f"The name shows {shown} but the message was sent from {email}.",
                f"{name} <{email}>"
            ))
            break

    # Brand named in the display name but sent from another domain
    for brand in brands_in_text(name):
        if not is_official_domain(domain, brand):
            findings.append(finding(
                "sender.brand_impersonation", "sender", "high",
                f"Sender name claims to be {brand} but uses another domain",
                f"Messages from {brand} come from official domains, not {domain}.",
                f"{name} <{email}>"
            ))

    # Look-alike or brand-containing sender domain
    for brand, kind in brands_in_host(domain):
        if is_official_domain(domain, brand):
            continue

        if kind == "lookalike":
            findings.append(finding(
                "sender.lookalike_domain", "sender", "critical",
                f"Sender domain imitates {brand}",
                f"{domain} is spelled to resemble {brand}.",
                email
            ))
        else:
            findings.append(finding(
                "sender.brand_in_domain", "sender", "medium",
                f"Sender domain contains '{brand}' but is not an official {brand} domain",
                "",
                email
            ))

    if "xn--" in domain:
        findings.append(finding(
            "sender.punycode_domain", "sender", "high",
            "Sender domain uses punycode (possible look-alike characters)",
            "",
            email
        ))

    # Organisation-style name sent from a free webmail account
    if domain in FREE_MAIL_DOMAINS and ROLE_WORDS.search(name):
        findings.append(finding(
            "sender.freemail_role", "sender", "medium",
            "Organisation-style sender uses a free webmail account",
            f"'{name}' was sent from a personal {domain} address.",
            f"{name} <{email}>"
        ))

    return findings, coverage(
        "sender",
        "analyzed",
        "Display name and address checked. The address shown by Gmail "
        "is not proof of identity; see authentication results."
    ), {
        "name": name,
        "email": email,
        "domain": domain
    }
