import unittest
from unittest.mock import patch

from scamshield.services.analysis_service import AnalysisService


class AnalysisServiceTests(unittest.TestCase):

    @patch(
        "scamshield.services.analysis_service.OllamaService.analyze"
    )
    def test_hybrid_analysis_when_ai_available(self, mock_ai):
        mock_ai.return_value = {
            "suspicious": True,
            "confidence": 80,
            "indicators": ["Urgent language"],
            "explanation": "Suspicious message detected.",
            "recommendation": "Verify independently."
        }

        result, error = AnalysisService.analyze_message(
            "Urgent! Verify your account and provide your OTP."
        )

        self.assertIsNone(error)
        self.assertEqual(result["analysis_mode"], "hybrid")
        self.assertIsNotNone(result["ai_analysis"])
        self.assertEqual(result["ai_analysis"]["confidence"], 80)

    @patch(
        "scamshield.services.analysis_service.OllamaService.analyze",
        return_value=None
    )
    def test_rule_based_fallback_when_ai_unavailable(self, mock_ai):
        result, error = AnalysisService.analyze_message(
            "Your appointment is confirmed for tomorrow."
        )

        self.assertIsNone(error)
        self.assertEqual(result["analysis_mode"], "rule_based")
        self.assertIsNone(result["ai_analysis"])

    @patch(
        "scamshield.services.analysis_service.OllamaService.analyze",
        return_value=None
    )
    def test_ai_unavailable_does_not_change_rule_based_risk(self, mock_ai):
        result, error = AnalysisService.analyze_message(
            "Urgent! Verify your account immediately. "
            "Click here to claim your reward and provide your OTP."
        )

        self.assertIsNone(error)
        self.assertEqual(result["risk"], "HIGH")
        self.assertEqual(result["analysis_mode"], "rule_based")


if __name__ == "__main__":
    unittest.main()
