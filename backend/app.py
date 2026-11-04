
import re
from urllib.parse import urlparse

from flask import Flask, jsonify, request
from flask_cors import CORS

app = Flask(__name__)
CORS(app)

MAX_URL_LENGTH = 2048
MAX_MESSAGE_LENGTH = 10000

SUSPICIOUS_MESSAGE_PATTERNS = [
    (r"\b(urgent|immediately|act now)\b", "Urgency language"),
    (r"\b(verify your account|account suspended|account locked)\b", "Account verification or suspension claim"),
    (r"\b(won a prize|claim your reward|free gift)\b", "Unexpected reward claim"),
    (r"\b(send money|transfer funds|payment required)\b", "Financial request"),
    (r"\b(password|otp|one.time password|verification code)\b", "Sensitive credential reference"),
    (r"\b(click here|click the link)\b", "Encouragement to click a link"),
]


def analyze_url(value):
    value = value.strip()

    if not value or len(value) > MAX_URL_LENGTH:
        return None, "URL is empty or exceeds the allowed length"

    if any(char.isspace() for char in value):
        return None, "URL must not contain whitespace"

    try:
        parsed = urlparse(value)

        if parsed.scheme not in ("http", "https"):
            return None, "Only HTTP and HTTPS URLs are supported"

        if not parsed.hostname:
            return None, "A valid hostname is required"

        parsed.port

    except ValueError:
        return None, "Invalid URL format"

    warnings = []

    hostname = parsed.hostname.lower()
    path = parsed.path.lower()

    if parsed.scheme == "http":
        warnings.append("Connection does not use HTTPS")

    if parsed.username is not None or parsed.password is not None:
        warnings.append("URL contains embedded user credentials")

    if re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", hostname):
        warnings.append("URL uses an IP address instead of a domain")

    if any(word in path for word in ("login", "verify", "account", "secure")):
        warnings.append("URL path contains a sensitive-action keyword")

    if hostname in ("bit.ly", "tinyurl.com", "t.co"):
        warnings.append("URL uses a URL-shortening service")

    risk = "HIGH" if len(warnings) >= 2 else (
        "MEDIUM" if warnings else "LOW"
    )

    return {
        "risk": risk,
        "warnings": warnings,
        "notice": "This is a preliminary automated assessment, not a guarantee of safety."
    }, None


def analyze_message(value):
    value = value.strip()

    if not value or len(value) > MAX_MESSAGE_LENGTH:
        return None, "Message is empty or exceeds the allowed length"

    indicators = []

    for pattern, description in SUSPICIOUS_MESSAGE_PATTERNS:
        if re.search(pattern, value, re.IGNORECASE):
            indicators.append(description)

    risk = "HIGH" if len(indicators) >= 3 else (
        "MEDIUM" if indicators else "LOW"
    )

    return {
        "risk": risk,
        "indicators": indicators,
        "notice": "This is a preliminary screening result. Verify suspicious requests independently."
    }, None


@app.get("/api/health")
def health():
    return jsonify({
        "status": "ok",
        "service": "ScamShield AI API"
    }), 200


@app.post("/api/analyze-url")
def analyze_url_endpoint():
    data = request.get_json(silent=True)

    if not isinstance(data, dict):
        return jsonify({"error": "A valid JSON object is required"}), 400

    if not isinstance(data.get("url"), str):
        return jsonify({"error": "URL must be a string"}), 400

    result, error = analyze_url(data["url"])

    if error:
        return jsonify({"error": error}), 400

    return jsonify(result), 200


@app.post("/api/analyze-message")
def analyze_message_endpoint():
    data = request.get_json(silent=True)

    if not isinstance(data, dict):
        return jsonify({"error": "A valid JSON object is required"}), 400

    if not isinstance(data.get("message"), str):
        return jsonify({"error": "Message must be a string"}), 400

    result, error = analyze_message(data["message"])

    if error:
        return jsonify({"error": error}), 400

    return jsonify(result), 200


@app.errorhandler(404)
def not_found(error):
    return jsonify({"error": "Endpoint not found"}), 404


@app.errorhandler(500)
def server_error(error):
    return jsonify({"error": "Internal server error"}), 500


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)

