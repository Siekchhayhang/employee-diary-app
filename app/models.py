# app/models.py
# Added reverse_delete_rule to DiaryEntry for better data integrity.
from werkzeug.security import generate_password_hash, check_password_hash
from . import db
from datetime import datetime
import secrets

class User(db.Document):
    """User model for MongoDB."""
    email = db.EmailField(required=True, unique=True)
    username = db.StringField(required=True, unique=True, max_length=100)
    password = db.StringField(required=True)
    role = db.StringField(required=True, default='employee', max_length=20)
    created_at = db.DateTimeField(default=datetime.utcnow)
    session_token = db.StringField(default=lambda: secrets.token_hex(16))

    @property
    def is_authenticated(self):
        return True

    @property
    def is_active(self):
        return True

    @property
    def is_anonymous(self):
        return False

    def get_id(self):
        return str(self.id)

    def check_password(self, password):
        return check_password_hash(self.password, password)

    def __repr__(self):
        return f'<User {self.username}>'

class DiaryEntry(db.Document):
    """DiaryEntry model for MongoDB."""
    title = db.StringField(required=True, max_length=200)
    content = db.StringField(required=True)
    date_posted = db.DateTimeField(required=True, default=datetime.utcnow)
    author = db.ReferenceField(User, required=True, reverse_delete_rule=db.CASCADE)

    def __repr__(self):
        return f'<DiaryEntry {self.title}>'