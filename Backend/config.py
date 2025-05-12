import os
from datetime import timedelta


class Config:
    """Base configuration class"""
    SECRET_KEY = 'sahil'
    JWT_SECRET_KEY = 'sahil'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(hours=24)
    UPLOAD_FOLDER = 'uploads'
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16MB max upload

    # Model paths
    MODEL_DIR = 'models'
    MODEL_PATH = os.path.join(MODEL_DIR, 'url_malware_model_latest.h5')
    TOKENIZER_PATH = os.path.join(MODEL_DIR, 'url_tokenizer.pickle')
    CHAR_TOKENIZER_PATH = os.path.join(MODEL_DIR, 'url_char_tokenizer.pickle')


class DevelopmentConfig(Config):
    """Development configuration"""
    DEBUG = True
    SQLALCHEMY_DATABASE_URI = os.environ.get('DEV_DATABASE_URL') or \
                              'mysql://root:@localhost/malware_detector'


class TestingConfig(Config):
    """Testing configuration"""
    TESTING = True
    SQLALCHEMY_DATABASE_URI = os.environ.get('TEST_DATABASE_URL') or \
                              'sqlite:///:memory:'


class ProductionConfig(Config):
    """Production configuration"""
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or \
                              'mysql://malware_user:password@localhost/malware_detector'
    JWT_COOKIE_SECURE = True  # Only send cookies over HTTPS


# Configuration dictionary
config = {
    'development': DevelopmentConfig,
    'testing': TestingConfig,
    'production': ProductionConfig,
    'default': DevelopmentConfig
}