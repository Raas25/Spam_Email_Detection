"""
Domain helpers shared by link and sender analysis:
registrable domains, brand impersonation and look-alike domains.
"""

import ipaddress
import re


# Second-level labels used under two-letter country codes,
# e.g. bbc.co.uk, example.com.au (a small, offline approximation
# of the Public Suffix List).
SECOND_LEVEL_LABELS = {"co", "com", "org", "net", "gov", "ac", "edu", "ne", "or"}

# Brands commonly impersonated in phishing, with official domains.
BRANDS = {
    "paypal": ["paypal.com", "paypal.me"],
    "microsoft": ["microsoft.com", "office.com", "office365.com", "live.com",
                  "outlook.com", "microsoftonline.com", "sharepoint.com"],
    "office365": ["office.com", "office365.com", "microsoft.com"],
    "outlook": ["outlook.com", "live.com", "microsoft.com"],
    "apple": ["apple.com", "icloud.com"],
    "icloud": ["icloud.com", "apple.com"],
    "amazon": ["amazon.com", "amazon.co.uk", "amazon.de", "amazon.in",
               "amazon.ca", "amazon.fr", "amazonaws.com"],
    "google": ["google.com", "gmail.com", "youtube.com", "googleusercontent.com"],
    "gmail": ["gmail.com", "google.com"],
    "netflix": ["netflix.com"],
    "facebook": ["facebook.com", "facebookmail.com", "meta.com", "fb.com"],
    "instagram": ["instagram.com", "facebookmail.com"],
    "whatsapp": ["whatsapp.com", "whatsapp.net"],
    "linkedin": ["linkedin.com"],
    "dropbox": ["dropbox.com", "dropboxmail.com"],
    "docusign": ["docusign.com", "docusign.net"],
    "adobe": ["adobe.com"],
    "dhl": ["dhl.com", "dhl.de"],
    "fedex": ["fedex.com"],
    "ups": ["ups.com"],
    "usps": ["usps.com"],
    "chase": ["chase.com"],
    "wellsfargo": ["wellsfargo.com"],
    "bankofamerica": ["bankofamerica.com"],
    "citibank": ["citi.com", "citibank.com"],
    "hsbc": ["hsbc.com", "hsbc.co.uk"],
    "irs": ["irs.gov"],
    "coinbase": ["coinbase.com"],
    "binance": ["binance.com"],
    "steam": ["steampowered.com", "steamcommunity.com"],
}

# How brand names appear in display names / text
BRAND_DISPLAY_NAMES = {
    "paypal": "paypal",
    "microsoft": "microsoft",
    "office 365": "office365",
    "office365": "office365",
    "outlook": "outlook",
    "apple": "apple",
    "icloud": "icloud",
    "amazon": "amazon",
    "google": "google",
    "gmail": "gmail",
    "netflix": "netflix",
    "facebook": "facebook",
    "instagram": "instagram",
    "whatsapp": "whatsapp",
    "linkedin": "linkedin",
    "dropbox": "dropbox",
    "docusign": "docusign",
    "adobe": "adobe",
    "dhl": "dhl",
    "fedex": "fedex",
    "ups": "ups",
    "usps": "usps",
    "chase": "chase",
    "wells fargo": "wellsfargo",
    "bank of america": "bankofamerica",
    "citibank": "citibank",
    "hsbc": "hsbc",
    "irs": "irs",
    "coinbase": "coinbase",
    "binance": "binance",
    "steam": "steam",
}

FREE_MAIL_DOMAINS = {
    "gmail.com", "googlemail.com", "yahoo.com", "yahoo.co.uk", "ymail.com",
    "hotmail.com", "outlook.com", "live.com", "msn.com", "aol.com",
    "icloud.com", "me.com", "mail.com", "gmx.com", "gmx.de", "yandex.com",
    "yandex.ru", "proton.me", "protonmail.com", "zoho.com", "qq.com",
    "163.com", "rediffmail.com",
}

# Characters attackers swap to imitate brand names
HOMOGLYPHS = {
    "0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t",
    "8": "b", "@": "a", "$": "s", "|": "l", "!": "i",
}

# Top-level domains frequently abused in phishing campaigns
SUSPICIOUS_TLDS = {
    "zip", "mov", "xyz", "top", "click", "country", "gq", "tk", "ml", "cf",
    "ga", "work", "support", "loan", "rest", "cam", "icu", "monster",
    "quest", "sbs", "buzz", "cfd", "lol",
}


def normalize_host(host):
    host = (host or "").strip().lower().rstrip(".")

    if host.startswith("www."):
        host = host[4:]

    return host


def is_ip_address(host):
    try:
        ipaddress.ip_address((host or "").strip("[]"))
        return True
    except ValueError:
        return False


def registrable_domain(host):
    """
    Reduce a hostname to its registrable domain, e.g.
    "login.paypal.com" -> "paypal.com", "www.bbc.co.uk" -> "bbc.co.uk".
    """

    host = normalize_host(host)

    if not host or is_ip_address(host):
        return host

    labels = host.split(".")

    if (
        len(labels) >= 3
        and len(labels[-1]) == 2
        and labels[-2] in SECOND_LEVEL_LABELS
    ):
        return ".".join(labels[-3:])

    return ".".join(labels[-2:])


def is_official_domain(host, brand):
    domain = registrable_domain(host)

    return domain in BRANDS.get(brand, [])


def deobfuscate(text):
    """Undo common character swaps: "paypa1" -> "paypal", "rn" -> "m"."""

    text = text.lower()
    text = "".join(HOMOGLYPHS.get(ch, ch) for ch in text)

    return text.replace("rn", "m").replace("vv", "w")


def brands_in_host(host):
    """
    Brands that appear as a label/token of the host, either literally
    ("paypal-secure.com") or disguised ("paypa1.com", "rnicrosoft.com").
    Returns [(brand, "literal" | "lookalike")].
    """

    host = normalize_host(host)
    tokens = [token for token in re.split(r"[.\-_]", host) if token]

    found = []

    for brand in BRANDS:
        for token in tokens:
            if token == brand or (len(brand) >= 5 and brand in token):
                found.append((brand, "literal"))
                break

            if len(brand) >= 4 and token != brand and deobfuscate(token) == brand:
                found.append((brand, "lookalike"))
                break

    return found


def brands_in_text(text):
    """Brands mentioned as whole words in a display name or text."""

    text = (text or "").lower()

    found = []

    for name, brand in BRAND_DISPLAY_NAMES.items():
        if re.search(r"\b" + re.escape(name) + r"\b", text) and brand not in found:
            found.append(brand)

    return found


def get_tld(host):
    host = normalize_host(host)

    return host.rsplit(".", 1)[-1] if "." in host else ""
