# app/__init__.py
# LoginManager is removed. A context processor is added for current_user.
from flask import Flask, g
from flask_wtf.csrf import CSRFProtect
from flask_mongoengine import MongoEngine
from config import config_by_name

db = MongoEngine()
csrf = CSRFProtect()

def create_app(config_name='dev'):
    """
    Creates and configures the Flask application.
    """
    app = Flask(__name__)
    app.config.from_object(config_by_name[config_name])

    db.init_app(app)
    csrf.init_app(app)

    from .auth import auth as auth_blueprint
    app.register_blueprint(auth_blueprint, url_prefix='/auth')

    from .main import main as main_blueprint
    app.register_blueprint(main_blueprint)

    @app.context_processor
    def inject_user():
        """
        Injects the current_user into all templates.
        g.user is set by the @jwt_required decorator.
        """
        return dict(current_user=g.get('user'))

    return app