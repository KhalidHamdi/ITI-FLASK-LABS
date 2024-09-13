from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_jwt_extended import JWTManager
from flask_migrate import Migrate

db = SQLAlchemy()
login_manager = LoginManager()
jwt = JWTManager()

def create_app():
    app = Flask(__name__)
    app.config['SECRET_KEY'] = '123'
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///library.db'
    app.config['JWT_SECRET_KEY'] = '123'  

    db.init_app(app)
    login_manager.init_app(app)
    jwt.init_app(app)
    migrate = Migrate(app, db)

    from .models import User
    from .views import main_bp, get_user_from_token

    @login_manager.user_loader
    def load_user(user_id):
        return User.query.get(int(user_id))

    app.register_blueprint(main_bp)

    @app.context_processor
    def inject_user():
        return dict(get_user_from_token=get_user_from_token)

    return app