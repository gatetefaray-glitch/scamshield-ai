from flask import Blueprint, jsonify, request

from scamshield.services.analysis_service import AnalysisService

url_bp = Blueprint("url", __name__)


@url_bp.post("/api/analyze-url")
def analyze_url_endpoint():
    data = request.get_json(silent=True)

    if not isinstance(data, dict):
        return jsonify({"error": "A valid JSON object is required"}), 400

    if not isinstance(data.get("url"), str):
        return jsonify({"error": "URL must be a string"}), 400

    result, error = AnalysisService.analyze_url(data["url"])

    if error:
        return jsonify({"error": error}), 400

    return jsonify(result), 200
