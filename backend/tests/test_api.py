import unittest

from scamshield import create_app


class ScamShieldAPITests(unittest.TestCase):

    def setUp(self):
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

    def test_normal_message(self):
        response = self.client.post(
            "/api/analyze-message",
            json={"message": "Your appointment is confirmed for tomorrow."}
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json["risk"], "LOW")

    def test_missing_message_field(self):
        response = self.client.post(
            "/api/analyze-message",
            json={"text": "Hello there"}
        )
        self.assertEqual(response.status_code, 400)


if __name__ == "__main__":
    unittest.main()
