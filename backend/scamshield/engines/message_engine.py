
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
        r"\b(verify your account|account\s+(?:(?:is|has been)\s+)?(?:suspended|locked))"
        r"|\b(?:profile|account)\s+(?:will be|may be|is being)\s+(?:disabled|deactivated|restricted)\b",
        "Account verification or suspension claim"
    ),
    (
        r"\b(won a prize|claim your reward|free gift)\b",
        "Unexpected reward claim"
    ),
    (
        r"\b(send money|transfer (?:funds|the amount)|payment required)\b",
        "Financial request"
    ),
    (
        r"(?<!not )(?<!never )(?<!don't )"
        r"\b(?:send|share|provide|enter|submit|give)\s+"
        r"(?:(?:us|me)\s+)?(?:your\s+)?"
        r"(?:password|passcode|otp|one[- ]time password|verification code)\b",
        "Sensitive credential reference"
    ),
    (
        r"\b(click here|click the link)\b",
        "Encouragement to click a link"
    ),
]


# Provisional contextual bonus:
# urgency combined with an account verification or suspension claim.
ACCOUNT_PRESSURE_COMBINATION_BONUS = 5


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

    # Apply a small contextual bonus when urgency and
    # an account verification or suspension claim coexist.
    if (
        "Urgency or pressure language" in indicators
        and "Account verification or suspension claim" in indicators
    ):
        risk_score = min(
            risk_score + ACCOUNT_PRESSURE_COMBINATION_BONUS,
            100
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
