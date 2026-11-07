import re

from scamshield.config import Config
from scamshield.engines.risk_engine import (
    MESSAGE_INDICATOR_WEIGHTS,
    calculate_rule_score,
    classify_risk,
)


SUSPICIOUS_MESSAGE_PATTERNS = [
    (
        r"\b(urgent|immediately|act now|final warning)\b",
        "Urgency or pressure language"
    ),
         (
        r"\b(verify your account|account\s+(?:(?:is|has been)\s+)?(?:suspended|locked))\b",
        "Account verification or suspension claim"
    ),
    (
        r"\b(won a prize|claim your reward|free gift)\b",
        "Unexpected reward claim"
    ),
    (
        r"\b(send money|transfer funds|payment required)\b",
        "Financial request"
    ),
    (
        r"\b(password|otp|one[- ]time password|verification code)\b",
        "Sensitive credential reference"
    ),
    (
        r"\b(click here|click the link)\b",
        "Encouragement to click a link"
    ),
]


def analyze_message(value):
    if not isinstance(value, str):
        return None, "Message must be a string"

    value = value.strip()

    if not value or len(value) > Config.MAX_MESSAGE_LENGTH:
        return None, "Message is empty or exceeds the allowed length"

    indicators = []

    for pattern, description in SUSPICIOUS_MESSAGE_PATTERNS:
        if re.search(pattern, value, re.IGNORECASE):
            indicators.append(description)

    risk_score = calculate_rule_score(
        indicators,
        MESSAGE_INDICATOR_WEIGHTS
    )

    return {
        "risk": classify_risk(risk_score),
        "risk_score": risk_score,
        "indicators": indicators,
        "notice": (
            "This is a preliminary screening result. "
            "Verify suspicious requests independently."
        )
    }, None
