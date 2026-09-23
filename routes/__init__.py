"""
Blueprint registration for all route modules.
"""


def register_blueprints(app):
    from routes.bot import bot_bp
    from routes.pages import pages_bp
    from routes.api import api_bp
    from routes.hosts import register_host_routing

    register_host_routing(app)

    app.register_blueprint(bot_bp)
    app.register_blueprint(pages_bp)
    app.register_blueprint(api_bp)

    print("[ROUTES] All blueprints registered")
