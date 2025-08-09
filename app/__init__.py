# app/__init__.py
# Updated with a custom Jinja filter for local time display.
from flask import Flask, g, request, current_app
from flask_wtf.csrf import CSRFProtect
from flask_mongoengine import MongoEngine
from config import config_by_name
import jwt
import pytz
from datetime import datetime

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

    # Import models here to avoid circular import
    from .models import User

    @app.before_request
    def load_logged_in_user():
        g.user = None
        token = request.cookies.get('token')
        if token:
            try:
                payload = jwt.decode(token, current_app.config['SECRET_KEY'], algorithms=["HS256"])
                user = User.objects(pk=payload['sub']).first()
                if user and user.session_token == payload.get('jti'):
                    g.user = user
            except (jwt.ExpiredSignatureError, jwt.InvalidTokenError):
                g.user = None

    from .auth import auth as auth_blueprint
    app.register_blueprint(auth_blueprint, url_prefix='/auth')

    from .main import main as main_blueprint
    app.register_blueprint(main_blueprint)

    @app.context_processor
    def inject_user():
        return dict(current_user=g.get('user'))

    # Custom Jinja filter for timezone conversion
    def format_datetime_local(value, format='%B %d, %Y at %I:%M %p'):
        if value is None:
            return ""
        local_tz = pytz.timezone('Asia/Phnom_Penh')
        local_dt = value.replace(tzinfo=pytz.utc).astimezone(local_tz)
        return local_dt.strftime(format)

    app.jinja_env.filters['datetime_local'] = format_datetime_local

    return app