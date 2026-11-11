from flask import Blueprint, jsonify, request

from scamshield.services.analysis_service import AnalysisService

message_bp = Blueprint("message", __name__)


@message_bp.post("/api/analyze-message")
def analyze_message_endpoint():
    data = request.get_json(silent=True)

    if not isinstance(data, dict):
        return jsonify({"error": "A valid JSON object is required"}), 400

    if not isinstance(data.get("message"), str):
        return jsonify({"error": "Message must be a string"}), 400

    result, error = AnalysisService.analyze_message(data["message"])

    if error:
        return jsonify({"error": error}), 400

    return jsonify(result), 200
