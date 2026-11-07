import ipaddress
import re
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


def validate_hostname(hostname):
    """
    Validate a hostname and return its ASCII representation.

    Returns:
        (ascii_hostname, is_internationalized)
        (None, False) if the hostname is invalid.
    """
    if not isinstance(hostname, str) or not hostname:
        return None, False

    hostname = hostname.lower()

    if hostname.endswith("."):
        hostname = hostname[:-1]

    try:
        ascii_hostname = hostname.encode("idna").decode("ascii").lower()
    except UnicodeError:
        return None, False

    if not ascii_hostname or len(ascii_hostname) > 253:
        return None, False

    labels = ascii_hostname.split(".")

    if any(not label or len(label) > 63 for label in labels):
        return None, False

    if any(
        not label[0].isalnum()
        or not label[-1].isalnum()
        or any(not (char.isalnum() or char == "-") for char in label)
        for label in labels
    ):
        return None, False

    for label in labels:
        if label.startswith("xn--"):
            try:
                label.encode("ascii").decode("idna")
            except UnicodeError:
                return None, False

    is_internationalized = (
        hostname != ascii_hostname
        or any(label.startswith("xn--") for label in labels)
    )

    return ascii_hostname, is_internationalized

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

        # Validate the port if one is supplied.
        parsed.port

    except ValueError:
        return None, "Invalid URL format"

    warnings = []

    hostname = hostname.lower().rstrip(".")

    # Check whether the hostname is an IP address.
    try:
        ipaddress.ip_address(hostname)
        is_ip_address = True
    except ValueError:
        is_ip_address = False

    if is_ip_address:
        warnings.append(
            "URL uses an IP address instead of a domain"
        )
    else:
        ascii_hostname, is_internationalized = validate_hostname(
            hostname
        )

        if ascii_hostname is None:
            return None, "Invalid hostname format"

        hostname = ascii_hostname

        if is_internationalized:
            warnings.append(
                "Hostname uses internationalized domain encoding"
            )

    if parsed.scheme.lower() == "http":
        warnings.append("Connection does not use HTTPS")

    if parsed.username is not None or parsed.password is not None:
        warnings.append("URL contains embedded user credentials")

    if hostname in SHORTENER_DOMAINS:
        warnings.append("URL uses a URL-shortening service")

    path_segments = set(parsed.path.lower().split("/"))

    if path_segments.intersection(SENSITIVE_PATH_KEYWORDS):
        warnings.append(
            "URL path contains a sensitive-action keyword"
        )

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
