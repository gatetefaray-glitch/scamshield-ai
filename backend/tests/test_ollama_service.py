import json
import unittest
from unittest.mock import Mock, patch

import requests

from scamshield.services.ollama_service import OllamaService


class OllamaServiceTests(unittest.TestCase):

    def setUp(self):
        self.valid_ai_result = {
            "suspicious": True,
            "confidence": 85,
            "indicators": ["Urgency or pressure language"],
            "explanation": "Suspicious language detected.",
            "recommendation": "Verify independently."
        }

    def make_streaming_response(self, payload):
        mock_response = Mock()
        mock_response.__enter__ = Mock(return_value=mock_response)
        mock_response.__exit__ = Mock(return_value=False)
        mock_response.iter_content.return_value = [
            json.dumps(payload).encode("utf-8")
        ]
        return mock_response

    @patch("scamshield.services.ollama_service.requests.post")
    def test_successful_ai_analysis(self, mock_post):
        mock_post.return_value = self.make_streaming_response({
            "response": json.dumps(self.valid_ai_result)
        })

        result = OllamaService.analyze(
            "Urgent! Verify your account.",
            "message"
        )

        self.assertEqual(result, self.valid_ai_result)
        mock_post.assert_called_once()

    @patch("scamshield.services.ollama_service.requests.post")
    def test_unsupported_content_type(self, mock_post):
        result = OllamaService.analyze(
            "Test content",
            "unsupported"
        )

        self.assertIsNone(result)
        mock_post.assert_not_called()

    @patch("scamshield.services.ollama_service.requests.post")
    def test_connection_failure_returns_none(self, mock_post):
        mock_post.side_effect = requests.ConnectionError(
            "Sensitive connection details"
        )

        with self.assertLogs(
            "scamshield.services.ollama_service",
            level="WARNING"
        ) as captured:
            result = OllamaService.analyze(
                "Test message",
                "message"
            )

        self.assertIsNone(result)
        self.assertTrue(captured.output)
        self.assertNotIn(
            "Sensitive connection details",
            " ".join(captured.output)
        )

    @patch("scamshield.services.ollama_service.requests.post")
    def test_invalid_ai_json_returns_none(self, mock_post):
        mock_post.return_value = self.make_streaming_response({
            "response": "This is not valid JSON"
        })

        result = OllamaService.analyze(
            "Test message",
            "message"
        )

        self.assertIsNone(result)

    @patch("scamshield.services.ollama_service.requests.post")
    def test_unexpected_response_format_returns_none(self, mock_post):
        mock_post.return_value = self.make_streaming_response(
            ["unexpected", "response"]
        )

        result = OllamaService.analyze(
            "Test message",
            "message"
        )

        self.assertIsNone(result)

    @patch("scamshield.services.ollama_service.requests.post")
    def test_invalid_confidence_returns_none(self, mock_post):
        invalid_result = self.valid_ai_result.copy()
        invalid_result["confidence"] = 150

        mock_post.return_value = self.make_streaming_response({
            "response": json.dumps(invalid_result)
        })

        result = OllamaService.analyze(
            "Test message",
            "message"
        )

        self.assertIsNone(result)


if __name__ == "__main__":
    unittest.main()
