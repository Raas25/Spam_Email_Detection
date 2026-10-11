"""
Authentication header analysis (SPF, DKIM, DMARC, Reply-To).

Results are only reported when the raw headers were actually
provided (from Gmail's "Show original"). Without them, nothing is
claimed to have passed.
"""

import re
from email.parser import HeaderParser
from email.utils import getaddresses

from .common import coverage, finding, MAX_HEADER_CHARS
from .domains import registrable_domain


RESULT_PATTERN = re.compile(r"\b(spf|dkim|dmarc)\s*=\s*([a-z]+)", re.IGNORECASE)

# Results ordered from worst to best when one mechanism appears
# several times (e.g. multiple DKIM signatures).
RESULT_RANK = ["fail", "permerror", "softfail", "temperror", "neutral", "none", "policy", "pass"]


def extract_header_block(raw):
    """Keep only the header section (before the first blank line)."""

    raw = (raw or "")[:MAX_HEADER_CHARS].replace("\r\n", "\n")
    return raw.split("\n\n", 1)[0]


def _best_result(values):
    values = [v.lower() for v in values]

    if "pass" in values:
        return "pass"

    for result in RESULT_RANK:
        if result in values:
            return result

    return values[0] if values else None


def parse_authentication_results(headers):
    """
    Use the Authentication-Results header added by the receiving
    server (Gmail adds "mx.google.com"). Earlier hops can be forged
    by the sender, so only the top-most header is trusted.
    """

    values = headers.get_all("Authentication-Results") or []

    if not values:
        return None

    chosen = values[0]

    for value in values:
        if value.strip().lower().startswith("mx.google.com"):
            chosen = value
            break

    authserv_id = chosen.split(";", 1)[0].strip()
    results = {}

    for mechanism, result in RESULT_PATTERN.findall(chosen):
        results.setdefault(mechanism.lower(), []).append(result)

    return {
        "authserv_id": authserv_id,
        "spf": _best_result(results.get("spf", [])),
        "dkim": _best_result(results.get("dkim", [])),
        "dmarc": _best_result(results.get("dmarc", []))
    }


def _first_address(value):
    addresses = getaddresses([value or ""])

    for _, address in addresses:
        if "@" in address:
            return address.lower()

    return None


def analyze_headers(raw_headers, unavailable_reason=None):
    """
    Returns (findings, coverage_entry, summary).
    """

    if not raw_headers or not raw_headers.strip():
        return [], coverage(
            "authentication",
            "unavailable",
            unavailable_reason
            or "Message headers were not available, so SPF, DKIM and DMARC were not checked."
        ), {"spf": "not checked", "dkim": "not checked", "dmarc": "not checked"}

    headers = HeaderParser().parsestr(extract_header_block(raw_headers))
    findings = []

    auth = parse_authentication_results(headers)
    from_address = _first_address(headers.get("From"))
    reply_to = _first_address(headers.get("Reply-To"))

    summary = {
        "spf": "not reported",
        "dkim": "not reported",
        "dmarc": "not reported",
        "authserv_id": None,
        "from": from_address,
        "reply_to": reply_to
    }

    if auth is None:
        status = coverage(
            "authentication",
            "partial",
            "Headers were provided but contain no Authentication-Results header."
        )
    else:
        summary.update({
            "spf": auth["spf"] or "not reported",
            "dkim": auth["dkim"] or "not reported",
            "dmarc": auth["dmarc"] or "not reported",
            "authserv_id": auth["authserv_id"]
        })
        status = coverage(
            "authentication",
            "analyzed",
            f"Results as reported by {auth['authserv_id'] or 'the receiving server'}."
        )

        reporter = auth["authserv_id"] or "receiving server"

        for mechanism in ("spf", "dkim", "dmarc"):
            result = auth[mechanism]

            if result is None:
                continue

            label = mechanism.upper()

            if result == "pass":
                findings.append(finding(
                    f"auth.{mechanism}_pass", "authentication", "info",
                    f"{label} passed",
                    f"Reported by {reporter}. This confirms the sending domain, "
                    "not that the content is safe.",
                    f"{mechanism}={result}"
                ))
            elif result in ("fail", "permerror"):
                findings.append(finding(
                    f"auth.{mechanism}_fail", "authentication",
                    "high" if mechanism in ("spf", "dmarc") else "medium",
                    f"{label} failed",
                    f"Reported by {reporter}. The message may not come from the domain it claims.",
                    f"{mechanism}={result}"
                ))
            elif result == "softfail":
                findings.append(finding(
                    f"auth.{mechanism}_softfail", "authentication", "medium",
                    f"{label} soft-failed",
                    f"Reported by {reporter}.",
                    f"{mechanism}={result}"
                ))
            elif result == "none":
                findings.append(finding(
                    f"auth.{mechanism}_none", "authentication", "low",
                    f"No {label} result for the sending domain",
                    f"Reported by {reporter}.",
                    f"{mechanism}={result}"
                ))

    if from_address and reply_to:
        from_domain = registrable_domain(from_address.rsplit("@", 1)[1])
        reply_domain = registrable_domain(reply_to.rsplit("@", 1)[1])

        if from_domain != reply_domain:
            findings.append(finding(
                "auth.reply_to_mismatch", "authentication", "medium",
                "Replies go to a different domain than the sender",
                f"From {from_domain}, but Reply-To is {reply_domain}.",
                f"Reply-To: {reply_to}"
            ))

    return findings, status, summary
