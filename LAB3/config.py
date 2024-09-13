import os

class Config:
    SECRET_KEY = os.getenv('SECRET_KEY', '123')
    SQLALCHEMY_DATABASE_URI = os.getenv('DATABASE_URL', 'sqlite:///library.db')
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    JWT_SECRET_KEY = os.getenv('JWT_SECRET_KEY', '1234')
    SESSION_TYPE = 'filesystem'
