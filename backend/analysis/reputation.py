"""
Optional URL reputation lookups.

Provider: Google Safe Browsing Lookup API v4, enabled only when the
backend is started with the SAFE_BROWSING_API_KEY environment
variable. The key stays on the backend (never in the extension).
Enabling it sends the email's link URLs (not the email text) to
Google. Without a key, reputation is reported as "unavailable";
links are never reported as "clean".
"""

import json
import os
import urllib.error
import urllib.request

from .common import coverage, finding


SAFE_BROWSING_URL = "https://safebrowsing.googleapis.com/v4/threatMatches:find?key={key}"
MAX_URLS = 50
TIMEOUT_SECONDS = 5

THREAT_LABELS = {
    "MALWARE": "malware",
    "SOCIAL_ENGINEERING": "phishing / social engineering",
    "UNWANTED_SOFTWARE": "unwanted software",
    "POTENTIALLY_HARMFUL_APPLICATION": "a potentially harmful app",
}


def _post_json(url, payload, timeout):
    if not url.startswith("https://safebrowsing.googleapis.com/"):
        raise ValueError("Unexpected reputation service URL")

    request = urllib.request.Request(  # noqa: S310 - URL checked above

        url,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST"
    )

    with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310 - fixed https URL
        return json.loads(response.read(1024 * 1024).decode("utf-8") or "{}")


def check_urls(urls, api_key=None, post_json=_post_json):
    """
    Returns (findings, coverage_entry).
    post_json is injectable for tests.
    """

    api_key = api_key if api_key is not None else os.environ.get("SAFE_BROWSING_API_KEY", "")
    urls = [url for url in dict.fromkeys(urls or []) if url.lower().startswith(("http://", "https://"))]

    if not api_key:
        return [], coverage(
            "reputation",
            "unavailable",
            "No reputation service configured (set SAFE_BROWSING_API_KEY on the backend). "
            "Links were not checked against blocklists."
        )

    if not urls:
        return [], coverage("reputation", "not_applicable", "No web links to check.")

    payload = {
        "client": {"clientId": "spam-email-checker", "clientVersion": "2.0.0"},
        "threatInfo": {
            "threatTypes": list(THREAT_LABELS),
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url} for url in urls[:MAX_URLS]]
        }
    }

    try:
        response = post_json(SAFE_BROWSING_URL.format(key=api_key), payload, TIMEOUT_SECONDS)
    except (urllib.error.URLError, TimeoutError, ValueError, OSError) as error:
        return [], coverage(
            "reputation",
            "unavailable",
            f"Google Safe Browsing request failed ({type(error).__name__}); links were not checked."
        )

    findings = []

    for match in response.get("matches", []) or []:
        threat = THREAT_LABELS.get(match.get("threatType"), "a known threat")
        url = (match.get("threat") or {}).get("url", "")

        findings.append(finding(
            "reputation.blocklisted", "reputation", "critical",
            f"Link is on Google Safe Browsing's list for {threat}",
            "Do not open this link.",
            url
        ))

    detail = f"{min(len(urls), MAX_URLS)} link(s) checked with Google Safe Browsing."

    if len(urls) > MAX_URLS:
        return findings, coverage("reputation", "partial", detail + f" {len(urls) - MAX_URLS} not checked.")

    return findings, coverage("reputation", "analyzed", detail)
