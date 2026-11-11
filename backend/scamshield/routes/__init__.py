from scamshield.routes.health import health_bp
from scamshield.routes.url import url_bp
from scamshield.routes.message import message_bp


def register_routes(app):
    app.register_blueprint(health_bp)
    app.register_blueprint(url_bp)
    app.register_blueprint(message_bp)
