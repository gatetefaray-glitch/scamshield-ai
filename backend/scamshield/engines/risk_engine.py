MAX_RISK_SCORE = 100

RISK_THRESHOLDS = {
    "LOW": (0, 29),
    "MEDIUM": (30, 69),
    "HIGH": (70, 100),
}

URL_INDICATOR_WEIGHTS = {
    "Connection does not use HTTPS": 10,
    "URL contains embedded user credentials": 30,
    "URL uses an IP address instead of a domain": 25,
    "URL uses a URL-shortening service": 15,
    "URL path contains a sensitive-action keyword": 10,
}

MESSAGE_INDICATOR_WEIGHTS = {
    "Urgency or pressure language": 10,
    "Account verification or suspension claim": 15,
    "Unexpected reward claim": 15,
    "Financial request": 20,
    "Sensitive credential reference": 30,
    "Encouragement to click a link": 15,
}


def calculate_rule_score(indicators, weights):
    score = sum(
        weights.get(indicator, 0)
        for indicator in set(indicators)
    )

    return min(score, MAX_RISK_SCORE)


def classify_risk(score):
    if not isinstance(score, (int, float)) or isinstance(score, bool):
        raise ValueError("Risk score must be numeric")

    if not 0 <= score <= MAX_RISK_SCORE:
        raise ValueError("Risk score must be between 0 and 100")

    for risk, (minimum, maximum) in RISK_THRESHOLDS.items():
        if minimum <= score <= maximum:
            return risk

    raise ValueError("Unable to classify risk")
