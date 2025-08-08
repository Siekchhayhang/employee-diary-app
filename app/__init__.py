# app/__init__.py
# Updated with a before_request hook to load the user on every request.
from flask import Flask, g, request, current_app
from flask_wtf.csrf import CSRFProtect
from flask_mongoengine import MongoEngine
from config import config_by_name
import jwt
from .models import User

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

    @app.before_request
    def load_logged_in_user():
        """
        This function runs before every request. It checks for a valid JWT cookie
        and loads the user into the application context (g.user).
        """
        g.user = None
        token = request.cookies.get('token')
        if token:
            try:
                payload = jwt.decode(token, current_app.config['SECRET_KEY'], algorithms=["HS256"])
                user = User.objects(pk=payload['sub']).first()
                if user and user.session_token == payload.get('jti'):
                    g.user = user
            except (jwt.ExpiredSignatureError, jwt.InvalidTokenError):
                # If the token is bad, we just treat the user as logged out.
                g.user = None

    from .auth import auth as auth_blueprint
    app.register_blueprint(auth_blueprint, url_prefix='/auth')

    from .main import main as main_blueprint
    app.register_blueprint(main_blueprint)

    @app.context_processor
    def inject_user():
        """
        Injects the current_user (from g.user) into all templates.
        """
        return dict(current_user=g.get('user'))

    return app