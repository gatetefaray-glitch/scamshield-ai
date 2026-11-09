import logging

from flask import Flask, jsonify
from flask_cors import CORS

from scamshield.config import Config
from scamshield.routes import register_routes


def create_app():

    # Configure standard application logging.
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s"
    )

    app = Flask(__name__)
    app.config.from_object(Config)

    CORS(
        app,
        resources={
            r"/api/*": {
                "origins": app.config["FRONTEND_ORIGIN"]
            }
        }
    )

    register_routes(app)

    @app.errorhandler(404)
    def not_found(error):
        return jsonify({
            "error": "Endpoint not found"
        }), 404

    @app.errorhandler(413)
    def request_too_large(error):
        return jsonify({
            "error": "Request body exceeds the 64 KB limit"
        }), 413

    @app.errorhandler(500)
    def server_error(error):
        return jsonify({
            "error": "Internal server error"
        }), 500

    return app
