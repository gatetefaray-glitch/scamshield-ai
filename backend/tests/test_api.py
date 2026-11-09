import unittest
from unittest.mock import patch

from scamshield import create_app


class ScamShieldAPITests(unittest.TestCase):

    def setUp(self):
        self.ollama_patcher = patch(
            "scamshield.services.analysis_service.OllamaService.analyze",
            return_value=None
        )
        self.mock_ollama = self.ollama_patcher.start()
        self.addCleanup(self.ollama_patcher.stop)

        self.app = create_app()
        self.client = self.app.test_client()

    def test_health_endpoint(self):
        response = self.client.get("/api/health")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json["status"], "ok")

    def test_normal_url(self):
        response = self.client.post(
            "/api/analyze-url",
            json={"url": "https://example.com"}
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json["risk"], "LOW")
        self.assertEqual(response.json["analysis_mode"], "rule_based")

    def test_suspicious_url(self):
        response = self.client.post(
            "/api/analyze-url",
            json={"url": "http://192.0.2.10/login"}
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json["risk"], "MEDIUM")
        self.assertEqual(response.json["risk_score"], 45)

    def test_invalid_url_scheme(self):
        response = self.client.post(
            "/api/analyze-url",
            json={"url": "javascript:alert(1)"}
        )
        self.assertEqual(response.status_code, 400)

    def test_suspicious_message(self):
        response = self.client.post(
            "/api/analyze-message",
            json={
                "message": (
                    "Urgent! Verify your account immediately. "
                    "Click here to claim your reward and provide your OTP."
                )
            }
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json["risk"], "HIGH")
        self.assertEqual(response.json["analysis_mode"], "rule_based")

    def test_normal_message(self):
        response = self.client.post(
            "/api/analyze-message",
            json={"message": "Your appointment is confirmed for tomorrow."}
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json["risk"], "LOW")
        self.assertEqual(response.json["analysis_mode"], "rule_based")

    def test_missing_message_field(self):
        response = self.client.post(
            "/api/analyze-message",
            json={"text": "Hello there"}
        )
        self.assertEqual(response.status_code, 400)

    def test_oversized_request_returns_413(self):
        response = self.client.post(
            "/api/analyze-message",
            data=b"x" * 65537,
            content_type="application/json"
        )

        self.assertEqual(response.status_code, 413)
        self.assertEqual(
            response.json["error"],
            "Request body exceeds the 64 KB limit"
        )

    def test_unexpected_exception_returns_generic_error(self):
        with patch(
            "scamshield.services.analysis_service.AnalysisService.analyze_message",
            side_effect=RuntimeError("Internal database connection details")
        ):
            response = self.client.post(
                "/api/analyze-message",
                json={"message": "Hello, how are you?"}
            )

        self.assertEqual(response.status_code, 500)
        self.assertEqual(
            response.json,
            {"error": "Internal server error"}
        )
        self.assertNotIn(
            "database connection details",
            response.get_data(as_text=True).lower()
        )


if __name__ == "__main__":
    unittest.main()
