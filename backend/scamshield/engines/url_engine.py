import ipaddress
from urllib.parse import urlparse

from scamshield.config import Config
from scamshield.engines.risk_engine import (
    URL_INDICATOR_WEIGHTS,
    calculate_rule_score,
    classify_risk,
)


SHORTENER_DOMAINS = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
}

SENSITIVE_PATH_KEYWORDS = {
    "login",
    "verify",
    "account",
    "secure",
}


def analyze_url(value):
    if not isinstance(value, str):
        return None, "URL must be a string"

    value = value.strip()

    if not value or len(value) > Config.MAX_URL_LENGTH:
        return None, "URL is empty or exceeds the allowed length"

    if any(char.isspace() for char in value):
        return None, "URL must not contain whitespace"

    try:
        parsed = urlparse(value)

        if parsed.scheme.lower() not in ("http", "https"):
            return None, "Only HTTP and HTTPS URLs are supported"

        hostname = parsed.hostname

        if not hostname:
            return None, "A valid hostname is required"

        parsed.port

    except ValueError:
        return None, "Invalid URL format"

    warnings = []
    hostname = hostname.lower().rstrip(".")
    path_segments = set(parsed.path.lower().split("/"))

    if parsed.scheme.lower() == "http":
        warnings.append("Connection does not use HTTPS")

    if parsed.username is not None or parsed.password is not None:
        warnings.append("URL contains embedded user credentials")

    try:
        ipaddress.ip_address(hostname)
        warnings.append("URL uses an IP address instead of a domain")
    except ValueError:
        pass

    if hostname in SHORTENER_DOMAINS:
        warnings.append("URL uses a URL-shortening service")

    if path_segments.intersection(SENSITIVE_PATH_KEYWORDS):
        warnings.append("URL path contains a sensitive-action keyword")

    risk_score = calculate_rule_score(
        warnings,
        URL_INDICATOR_WEIGHTS
    )

    return {
        "risk": classify_risk(risk_score),
        "risk_score": risk_score,
        "warnings": warnings,
        "notice": (
            "This is a preliminary automated assessment, "
            "not a guarantee of safety."
        )
    }, None
