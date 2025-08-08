# app/auth.py
# Corrected the cookie settings for local development vs. production.
from flask import Blueprint, render_template, redirect, url_for, flash, request, make_response, current_app, g
from werkzeug.security import generate_password_hash
from .models import User
from .forms import LoginForm, RegistrationForm
import jwt
from datetime import datetime, timedelta
from functools import wraps

auth = Blueprint('auth', __name__)

def jwt_required(f):
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
                flash('Your session is invalid. Please log in again.', 'danger')
                return redirect(url_for('auth.login'))
            g.user = user
        except (jwt.ExpiredSignatureError, jwt.InvalidTokenError):
            flash('Your session is invalid or has expired. Please log in again.', 'info')
            return redirect(url_for('auth.login'))
        return f(*args, **kwargs)
    return decorated_function

@auth.route('/login', methods=['GET', 'POST'])
def login():
    if g.get('user'):
        return redirect(url_for('main.index'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.objects(email=form.email.data).first()
        if user and user.check_password(form.password.data):
            token = jwt.encode({
                'sub': str(user.id),
                'jti': user.session_token,
                'iat': datetime.utcnow(),
                'exp': datetime.utcnow() + timedelta(hours=24)
            }, current_app.config['SECRET_KEY'], algorithm="HS256")
            
            response = make_response(redirect(url_for('main.index')))
            
            is_production = current_app.config['ENV'] == 'production'
            
            response.set_cookie(
                'token', 
                token, 
                httponly=True, 
                secure=is_production, 
                samesite='Lax',
                path='/'  # This is the crucial fix
            )
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
    response.delete_cookie('token', path='/')
    return response