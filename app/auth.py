# app/auth.py
# Updated to handle the 'secure' and 'samesite' cookie flags dynamically.
from flask import Blueprint, render_template, redirect, url_for, flash, request, make_response, current_app, g
from werkzeug.security import generate_password_hash
from .models import User
from .forms import LoginForm, RegistrationForm
import jwt
from datetime import datetime, timedelta
from functools import wraps

auth = Blueprint('auth', __name__)

def jwt_required(f):
    """
    A decorator to protect routes with JWT authentication.
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        token = request.cookies.get('token')
        if not token:
            flash('Please log in to access this page.', 'info')
            return redirect(url_for('auth.login'))
        try:
            payload = jwt.decode(token, current_app.config['SECRET_KEY'], algorithms=["HS256"])
            user = User.objects(pk=payload['sub']).first()
            if not user or user.session_token != payload.get('jti'):
                # Token is invalid or session has been terminated
                flash('Your session is invalid. Please log in again.', 'danger')
                return redirect(url_for('auth.login'))
            g.user = user  # Make user available for the duration of the request
        except jwt.ExpiredSignatureError:
            flash('Your session has expired. Please log in again.', 'info')
            return redirect(url_for('auth.login'))
        except jwt.InvalidTokenError:
            flash('Invalid token. Please log in again.', 'danger')
            return redirect(url_for('auth.login'))
        return f(*args, **kwargs)
    return decorated_function


@auth.route('/login', methods=['GET', 'POST'])
def login():
    if g.get('user'): # Check if user is already loaded by a previous check
        return redirect(url_for('main.index'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.objects(email=form.email.data).first()
        if user and user.check_password(form.password.data):
            # Create JWT
            token = jwt.encode({
                'sub': str(user.id),
                'jti': user.session_token, # JWT ID for session invalidation
                'iat': datetime.utcnow(),
                'exp': datetime.utcnow() + timedelta(hours=24)
            }, current_app.config['SECRET_KEY'], algorithm="HS256")

            response = make_response(redirect(url_for('main.index')))
            
            is_production = current_app.config['ENV'] == 'production'
            samesite_policy = 'Lax' if is_production else None

            response.set_cookie('token', token, httponly=True, secure=is_production, samesite=samesite_policy)
            return response
        else:
            flash('Login Unsuccessful. Please check email and password', 'danger')
    return render_template('login.html', title='Login', form=form)

@auth.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data, method='pbkdf2:sha256')
        user = User(username=form.username.data, email=form.email.data, password=hashed_password)
        user.save()
        flash('Your account has been created! You are now able to log in', 'success')
        return redirect(url_for('auth.login'))
    return render_template('register.html', title='Register', form=form)

@auth.route('/logout')
@jwt_required
def logout():
    response = make_response(redirect(url_for('main.index')))
    # Clear the cookie to log the user out
    response.delete_cookie('token')
    return response