"""
URL analysis: deceptive links, risky hosts, schemes and downloads.
Links are only parsed as text; they are never opened or followed.
"""

import re
from urllib.parse import parse_qs, unquote, urlparse

from .common import MAX_LINKS, finding
from .domains import (
    brands_in_host,
    get_tld,
    is_ip_address,
    is_official_domain,
    normalize_host,
    registrable_domain,
    SUSPICIOUS_TLDS,
)


URL_IN_TEXT = re.compile(r"https?://[^\s<>\"')\]]+|www\.[^\s<>\"')\]]+", re.IGNORECASE)

# Visible link text that looks like a domain or URL
DOMAIN_TEXT = re.compile(
    r"^(?:https?://)?((?:[a-z0-9-]+\.)+[a-z]{2,})(?::\d+)?(?:[/?#]\S*)?$",
    re.IGNORECASE
)

URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "cutt.ly", "rb.gy",
    "ow.ly", "buff.ly", "shorturl.at", "tiny.cc", "qrco.de", "s.id",
    "rebrand.ly", "t.ly", "lnkd.in",
}

QR_URL_PATH_WORDS = [
    "login", "signin", "verify", "account", "password", "update", "secure"
]

DANGEROUS_SCHEMES = {"javascript", "data", "vbscript", "file"}

EXECUTABLE_EXTENSIONS = {
    "exe", "scr", "msi", "bat", "cmd", "com", "pif", "js", "jse", "vbs",
    "vbe", "wsf", "hta", "ps1", "jar", "apk", "dmg", "pkg", "iso", "img",
    "lnk", "reg", "dll", "cpl", "appx", "msix",
}

# Redirect wrappers whose real destination is in a query parameter
REDIRECT_WRAPPERS = {
    "google.com": ("/url", "q"),
    "safelinks.protection.outlook.com": ("/", "url"),
}


# ---------------------------------------------------------
# Parsing helpers
# ---------------------------------------------------------

def parse_url(url):
    url = (url or "").strip()

    if url.lower().startswith("www."):
        url = "http://" + url

    try:
        return urlparse(url)
    except ValueError:
        return None


def unwrap_redirect(url, depth=0):
    """Follow known redirect wrappers (without making requests)."""

    parsed = parse_url(url)

    if not parsed or depth > 3:
        return url

    host = normalize_host(parsed.hostname)

    for wrapper, (path, param) in REDIRECT_WRAPPERS.items():
        if (host == wrapper or host.endswith("." + wrapper)) and parsed.path.startswith(path):
            target = parse_qs(parsed.query).get(param)
            if target and target[0].lower().startswith(("http://", "https://")):
                return unwrap_redirect(unquote(target[0]), depth + 1)

    return url


def extract_urls_from_text(text, limit=MAX_LINKS):
    urls = []

    for match in URL_IN_TEXT.finditer(text or ""):
        url = match.group(0).rstrip(".,;:!?")
        if url not in urls:
            urls.append(url)
        if len(urls) >= limit:
            break

    return urls


# ---------------------------------------------------------
# Simple URL indicators (used by /scan-qr)
# ---------------------------------------------------------

def get_url_indicators(url):
    indicators = []

    if url.lower().startswith("www."):
        url = "http://" + url

    parsed = urlparse(url)
    host = (parsed.hostname or "").lower()

    if parsed.scheme != "https":
        indicators.append("Link does not use HTTPS")

    if is_ip_address(host):
        indicators.append("Link points to an IP address instead of a domain")

    if host in URL_SHORTENERS or host.removeprefix("www.") in URL_SHORTENERS:
        indicators.append("Link uses a URL shortener that hides the destination")

    if "xn--" in host:
        indicators.append("Domain uses punycode (possible look-alike domain)")

    if "@" in parsed.netloc:
        indicators.append("Link contains '@', which can disguise the real destination")

    if host.count(".") >= 4:
        indicators.append("Domain has an unusually large number of subdomains")

    path = f"{parsed.path} {parsed.query}".lower()

    if any(word in path for word in QR_URL_PATH_WORDS):
        indicators.append("Link path suggests a login or account-verification page")

    return indicators


# ---------------------------------------------------------
# Detailed URL analysis (used by /analyze)
# ---------------------------------------------------------

def analyze_url(url, category="links", link_text=None):
    """
    Return findings for one URL. category is "links" or "qr".
    """

    findings = []
    original = (url or "").strip()

    scheme = original.split(":", 1)[0].lower() if ":" in original else ""

    if scheme in DANGEROUS_SCHEMES:
        findings.append(finding(
            f"{category}.dangerous_scheme", category, "high",
            f"Link uses a dangerous '{scheme}:' scheme",
            "Links like this can run code or load hidden content when clicked.",
            original
        ))
        return findings

    if scheme in ("mailto", "tel", "sms"):
        return findings

    url = unwrap_redirect(original)
    parsed = parse_url(url)

    if not parsed or not parsed.hostname:
        return findings

    host = normalize_host(parsed.hostname)
    domain = registrable_domain(host)

    # Deceptive link text: shows one domain, goes to another
    if link_text:
        match = DOMAIN_TEXT.match(link_text.strip())
        if match:
            shown = registrable_domain(match.group(1))
            if shown and shown != domain:
                findings.append(finding(
                    f"{category}.deceptive_text", category, "high",
                    "Link text shows a different website than it opens",
                    f"The text shows {shown} but the link goes to {domain}.",
                    f"{link_text.strip()} -> {host}"
                ))

    if "@" in (parsed.netloc or ""):
        findings.append(finding(
            f"{category}.at_sign", category, "high",
            "Link contains '@', which can disguise the real destination",
            "Everything before '@' is ignored by the browser.",
            url
        ))

    if is_ip_address(host):
        findings.append(finding(
            f"{category}.ip_host", category, "high",
            "Link points to a raw IP address",
            "Legitimate organisations almost always use a domain name.",
            url
        ))
    else:
        for brand, kind in brands_in_host(host):
            if is_official_domain(host, brand):
                continue

            if kind == "lookalike":
                findings.append(finding(
                    f"{category}.lookalike_domain", category, "critical",
                    f"Look-alike domain imitating {brand}",
                    f"{host} is spelled to resemble {brand} but is not an official {brand} domain.",
                    host
                ))
            else:
                findings.append(finding(
                    f"{category}.brand_in_domain", category, "high",
                    f"Domain uses the {brand} name but is not an official {brand} domain",
                    f"Official domains include {', '.join(_official(brand))}.",
                    host
                ))

        if "xn--" in host:
            findings.append(finding(
                f"{category}.punycode", category, "high",
                "Domain uses punycode (possible look-alike characters)",
                "Punycode domains can imitate familiar names with foreign letters.",
                host
            ))

        if domain in URL_SHORTENERS or host in URL_SHORTENERS:
            findings.append(finding(
                f"{category}.shortener", category, "medium",
                "Link uses a URL shortener that hides the destination",
                "The final website cannot be checked without opening the link.",
                url
            ))

        if get_tld(host) in SUSPICIOUS_TLDS:
            findings.append(finding(
                f"{category}.suspicious_tld", category, "low",
                f"Domain uses the .{get_tld(host)} ending, often abused in phishing",
                "",
                host
            ))

        if host.count(".") >= 4:
            findings.append(finding(
                f"{category}.many_subdomains", category, "low",
                "Domain has an unusually large number of subdomains",
                "",
                host
            ))

    path = unquote(parsed.path or "").lower()
    extension = path.rsplit(".", 1)[-1] if "." in path.rsplit("/", 1)[-1] else ""

    if extension in EXECUTABLE_EXTENSIONS:
        findings.append(finding(
            f"{category}.executable_download", category, "high",
            f"Link downloads a .{extension} file that can run programs",
            "Do not download or open it.",
            url
        ))

    if parsed.scheme == "http":
        findings.append(finding(
            f"{category}.no_https", category, "low",
            "Link does not use HTTPS",
            "Information sent to this page is not encrypted.",
            url
        ))

    if any(word in f"{path} {parsed.query}".lower() for word in QR_URL_PATH_WORDS):
        findings.append(finding(
            f"{category}.login_path", category, "low",
            "Link path suggests a login or account-verification page",
            "",
            url
        ))

    return findings


def _official(brand):
    from .domains import BRANDS

    return BRANDS.get(brand, [])[:3]


def analyze_links(links, body_text=""):
    """
    Analyze hyperlinks ({"text", "href"}) plus URLs written in the
    body text. Returns (findings, summary).
    """

    items = []
    seen = set()

    for link in (links or [])[:MAX_LINKS]:
        href = (link.get("href") or "").strip()
        if href and (href, link.get("text")) not in seen:
            seen.add((href, link.get("text")))
            items.append((href, link.get("text") or ""))

    known = {href for href, _ in items}

    for url in extract_urls_from_text(body_text):
        if len(items) >= MAX_LINKS:
            break
        if url not in known:
            known.add(url)
            items.append((url, ""))

    findings = []
    domains = set()

    for href, text in items:
        findings.extend(analyze_url(href, "links", text))

        parsed = parse_url(unwrap_redirect(href))
        if parsed and parsed.hostname:
            domains.add(registrable_domain(parsed.hostname))

    return findings, {
        "total": len(items),
        "unique_domains": sorted(domains)[:50],
        "truncated": len(links or []) > MAX_LINKS
    }
