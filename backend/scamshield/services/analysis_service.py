from scamshield.engines.url_engine import analyze_url
from scamshield.engines.message_engine import analyze_message


class AnalysisService:

    @staticmethod
    def analyze_url(value):
        return analyze_url(value)

    @staticmethod
    def analyze_message(value):
        return analyze_message(value)
