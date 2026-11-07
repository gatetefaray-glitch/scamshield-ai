import unittest

from scamshield.engines.url_engine import analyze_url
from scamshield.engines.message_engine import analyze_message
from scamshield.engines.risk_engine import (
    calculate_rule_score,
    classify_risk,
    URL_INDICATOR_WEIGHTS,
    MESSAGE_INDICATOR_WEIGHTS,
)


class URLDetectionTests(unittest.TestCase):

    def test_normal_https_url(self):
        result, error = analyze_url("https://example.com")
        self.assertIsNone(error)
        self.assertEqual(result["risk"], "LOW")
        self.assertEqual(result["risk_score"], 0)

    def test_http_url(self):
        result, error = analyze_url("http://example.com")
        self.assertIsNone(error)
        self.assertIn("Connection does not use HTTPS", result["warnings"])

    def test_ip_address_url(self):
        result, error = analyze_url("http://192.0.2.10/login")
        self.assertIsNone(error)
        self.assertEqual(result["risk"], "MEDIUM")
        self.assertEqual(result["risk_score"], 45)

    def test_url_shortener(self):
        result, error = analyze_url("https://bit.ly/example")
        self.assertIsNone(error)
        self.assertIn("URL uses a URL-shortening service", result["warnings"])

    def test_embedded_credentials(self):
        result, error = analyze_url("https://user:password@example.com")
        self.assertIsNone(error)
        self.assertIn("URL contains embedded user credentials", result["warnings"])

    def test_invalid_scheme(self):
        result, error = analyze_url("javascript:alert(1)")
        self.assertIsNone(result)
        self.assertIsNotNone(error)


class MessageDetectionTests(unittest.TestCase):

    def test_normal_message(self):
        result, error = analyze_message(
            "Your appointment is confirmed for tomorrow."
        )
        self.assertIsNone(error)
        self.assertEqual(result["risk"], "LOW")
        self.assertEqual(result["risk_score"], 0)

    def test_urgent_message(self):
        result, error = analyze_message(
            "URGENT! Act now to avoid account suspension."
        )
        self.assertIsNone(error)
        self.assertIn("Urgency or pressure language", result["indicators"])

    def test_credential_request(self):
        result, error = analyze_message(
            "Please provide your OTP and password."
        )
        self.assertIsNone(error)
        self.assertIn("Sensitive credential reference", result["indicators"])

    def test_financial_request(self):
        result, error = analyze_message(
            "Please transfer funds immediately."
        )
        self.assertIsNone(error)
        self.assertIn("Financial request", result["indicators"])

    def test_multiple_suspicious_indicators(self):
        result, error = analyze_message(
            "Urgent! Your account is suspended. "
            "Provide your OTP and click here."
        )
        self.assertIsNone(error)
        self.assertEqual(result["risk"], "HIGH")


class RiskScoringTests(unittest.TestCase):

    def test_low_risk_classification(self):
        self.assertEqual(classify_risk(10), "LOW")

    def test_medium_risk_classification(self):
        self.assertEqual(classify_risk(45), "MEDIUM")

    def test_high_risk_classification(self):
        self.assertEqual(classify_risk(75), "HIGH")

    def test_score_is_capped_at_100(self):
        indicators = ["Indicator A", "Indicator B"]
        weights = {"Indicator A": 80, "Indicator B": 50}

        score = calculate_rule_score(indicators, weights)
        self.assertEqual(score, 100)

    def test_duplicate_indicators_are_not_double_counted(self):
        indicators = [
            "Sensitive credential reference",
            "Sensitive credential reference",
        ]

        score = calculate_rule_score(
            indicators,
            MESSAGE_INDICATOR_WEIGHTS
        )
        self.assertEqual(score, 30)


if __name__ == "__main__":
    unittest.main()

