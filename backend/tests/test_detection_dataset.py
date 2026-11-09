
import unittest

from scamshield.engines.message_engine import analyze_message
from scamshield.engines.url_engine import analyze_url


class MessageDatasetTests(unittest.TestCase):
    """Synthetic message examples for detection and false-positive checks."""

    def test_legitimate_messages(self):
        examples = [
            "Your appointment is confirmed for tomorrow.",
            "Your account statement is now available.",
            "Please verify your email address through the official app.",
            "Thank you for attending our customer service session.",
            "Your monthly subscription renewal is confirmed.",
        ]

        for message in examples:
            with self.subTest(message=message):
                result, error = analyze_message(message)

                self.assertIsNone(error)
                self.assertEqual(result["risk"], "LOW")
                self.assertEqual(result["risk_score"], 0)
                self.assertEqual(result["indicators"], [])

    def test_suspicious_message_examples(self):
        examples = [
            (
                "URGENT! Click here to review this message.",
                "Urgency or pressure language",
            ),
            (
                "Your account has been suspended. Verify your account.",
                "Account verification or suspension claim",
            ),
            (
                "You won a prize! Claim your reward today.",
                "Unexpected reward claim",
            ),
            (
                "Payment required. Please transfer funds.",
                "Financial request",
            ),
            (
                "Please provide your OTP to continue.",
                "Sensitive credential reference",
            ),
            (
                "Click here to claim your free gift.",
                "Unexpected reward claim",
            ),
        ]

        for message, expected_indicator in examples:
            with self.subTest(message=message):
                result, error = analyze_message(message)

                self.assertIsNone(error)
                self.assertIn(
                    expected_indicator,
                    result["indicators"],
                )
                self.assertGreater(result["risk_score"], 0)

    def test_urgency_and_multiple_indicators(self):
        message = (
            "URGENT! Your account has been suspended. "
            "Click here to verify your account."
        )

        result, error = analyze_message(message)

        self.assertIsNone(error)
        self.assertIn(
            "Urgency or pressure language",
            result["indicators"],
        )
        self.assertIn(
            "Account verification or suspension claim",
            result["indicators"],
        )
        self.assertIn(
            "Encouragement to click a link",
            result["indicators"],
        )
        self.assertEqual(result["risk_score"], 45)

    def test_ordinary_account_wording_is_not_flagged(self):
        message = (
            "Your account balance and monthly statement "
            "are available in the official application."
        )

        result, error = analyze_message(message)

        self.assertIsNone(error)
        self.assertEqual(result["risk_score"], 0)
        self.assertEqual(result["indicators"], [])

    def test_ordinary_verification_wording_is_not_flagged(self):
        message = (
            "Please verify your attendance with the event organiser."
        )

        result, error = analyze_message(message)

        self.assertIsNone(error)
        self.assertEqual(result["risk_score"], 0)
        self.assertEqual(result["indicators"], [])


    def test_password_change_notification_is_not_credential_request(self):
        message = (
            "Your password was changed successfully. "
            "Contact support through the official app."
        )

        result, error = analyze_message(message)

        self.assertIsNone(error)
        self.assertNotIn(
            "Sensitive credential reference",
            result["indicators"],
        )

    def test_security_advice_is_not_credential_request(self):
        message = (
            "Please do not share your verification code with anyone."
        )

        result, error = analyze_message(message)

        self.assertIsNone(error)
        self.assertNotIn(
            "Sensitive credential reference",
            result["indicators"],
        )

    def test_passcode_request_is_detected(self):
        message = "Please share your passcode to complete the process."

        result, error = analyze_message(message)

        self.assertIsNone(error)
        self.assertIn(
            "Sensitive credential reference",
            result["indicators"],
        )

    def test_profile_disabling_pressure_is_detected(self):
        message = (
            "Your profile will be disabled unless you confirm your details."
        )

        result, error = analyze_message(message)

        self.assertIsNone(error)
        self.assertIn(
            "Account verification or suspension claim",
            result["indicators"],
        )

    def test_broader_financial_request_is_detected(self):
        message = "Please transfer the amount to complete your order."

        result, error = analyze_message(message)

        self.assertIsNone(error)
        self.assertIn(
            "Financial request",
            result["indicators"],
        )

class URLDatasetTests(unittest.TestCase):
    """Synthetic URL examples using reserved example domains and IPs."""

    def test_legitimate_https_urls(self):
        examples = [
            "https://example.com",
            "https://www.example.com/about",
            "https://example.org/contact",
            "https://example.net/products",
        ]

        for url in examples:
            with self.subTest(url=url):
                result, error = analyze_url(url)

                self.assertIsNone(error)
                self.assertEqual(result["risk"], "LOW")
                self.assertEqual(result["risk_score"], 0)
                self.assertEqual(result["warnings"], [])

    def test_http_url_is_flagged(self):
        result, error = analyze_url("http://example.com")

        self.assertIsNone(error)
        self.assertIn(
            "Connection does not use HTTPS",
            result["warnings"],
        )
        self.assertEqual(result["risk_score"], 10)

    def test_sensitive_path_keyword(self):
        result, error = analyze_url(
            "https://example.com/login"
        )

        self.assertIsNone(error)
        self.assertIn(
            "URL path contains a sensitive-action keyword",
            result["warnings"],
        )
        self.assertEqual(result["risk_score"], 10)

    def test_multiple_url_indicators(self):
        result, error = analyze_url(
            "http://192.0.2.10/login"
        )

        self.assertIsNone(error)
        self.assertIn(
            "Connection does not use HTTPS",
            result["warnings"],
        )
        self.assertIn(
            "URL uses an IP address instead of a domain",
            result["warnings"],
        )
        self.assertIn(
            "URL path contains a sensitive-action keyword",
            result["warnings"],
        )
        self.assertEqual(result["risk_score"], 45)

    def test_keyword_inside_longer_path_segment_is_not_matched(self):
        result, error = analyze_url(
            "https://example.com/login-help"
        )

        self.assertIsNone(error)
        self.assertNotIn(
            "URL path contains a sensitive-action keyword",
            result["warnings"],
        )

    def test_url_shortener_indicator(self):
        result, error = analyze_url(
            "https://bit.ly/example"
        )

        self.assertIsNone(error)
        self.assertIn(
            "URL uses a URL-shortening service",
            result["warnings"],
        )
        self.assertEqual(result["risk_score"], 15)


if __name__ == "__main__":
    unittest.main()
