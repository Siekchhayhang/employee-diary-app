# config.py
# Updated to include an ENV variable.
import os
from dotenv import load_dotenv

load_dotenv()

class Config:
    """Base configuration."""
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'a-very-secret-key-that-you-should-change'
    WTF_CSRF_ENABLED = True
    # MongoDB settings
    MONGODB_SETTINGS = {
        'host': os.environ.get('MONGODB_URI') or 'mongodb://localhost:27017/employee_diary'
    }

class DevelopmentConfig(Config):
    """Development configuration."""
    ENV = 'development'
    DEBUG = True

class ProductionConfig(Config):
    """Production configuration."""
    ENV = 'production'
    DEBUG = False
    # In production, MONGODB_URI MUST be set.
    MONGODB_SETTINGS = {
        'host': os.environ.get('MONGODB_URI')
    }

config_by_name = dict(
    dev=DevelopmentConfig,
    prod=ProductionConfig
)