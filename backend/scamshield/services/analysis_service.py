from scamshield.engines.url_engine import analyze_url
from scamshield.engines.message_engine import analyze_message
from scamshield.services.ollama_service import OllamaService


class AnalysisService:

    @staticmethod
    def _add_ai_analysis(result, value, content_type):
        """
        Add supplementary AI findings to deterministic analysis.

        The existing rule-based risk assessment remains authoritative.
        AI unavailability must not interrupt the analysis.
        """

        ai_result = OllamaService.analyze(
            value,
            content_type
        )

        result["ai_analysis"] = ai_result

        result["analysis_mode"] = (
            "hybrid" if ai_result is not None
            else "rule_based"
        )

        return result

    @staticmethod
    def analyze_url(value):
        result, error = analyze_url(value)

        if error:
            return result, error

        result = AnalysisService._add_ai_analysis(
            result,
            value,
            "url"
        )

        return result, None

    @staticmethod
    def analyze_message(value):
        result, error = analyze_message(value)

        if error:
            return result, error

        result = AnalysisService._add_ai_analysis(
            result,
            value,
            "message"
        )

        return result, None
