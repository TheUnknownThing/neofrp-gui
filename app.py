import os
import logging
from flask import Flask
from flask_login import LoginManager
from flask_wtf.csrf import CSRFProtect
from dotenv import load_dotenv
from database import db, migrate

# Initialize extensions
login_manager = LoginManager()
csrf = CSRFProtect()

# Load environment variables
load_dotenv()

def create_app(config_name='production'):
    """Create and configure the Flask application."""
    app = Flask(__name__)

    # Configure app
    app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-secret-key-change-in-production')
    app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///neofrp.db')
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    app.config['WTF_CSRF_ENABLED'] = True

    # Session security
    app.config['SESSION_COOKIE_HTTPONLY'] = True
    app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
    if config_name == 'production':
        app.config['SESSION_COOKIE_SECURE'] = os.environ.get('SESSION_COOKIE_SECURE', 'true').lower() == 'true'

    # Configure logging
    if config_name == 'production':
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
    else:
        logging.basicConfig(
            level=logging.DEBUG,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )

    # Initialize extensions with app
    db.init_app(app)
    login_manager.init_app(app)
    migrate.init_app(app, db)
    csrf.init_app(app)

    # Configure login manager
    login_manager.login_view = 'auth.login'
    login_manager.login_message = 'Please log in to access this page.'

    # Register blueprints
    from views.auth import auth_bp
    from views.admin import admin_bp
    from views.user import user_bp
    from views.main import main_bp

    app.register_blueprint(main_bp)
    app.register_blueprint(auth_bp, url_prefix='/auth')
    app.register_blueprint(admin_bp, url_prefix='/admin')
    app.register_blueprint(user_bp, url_prefix='/user')

    # Configure user loader for Flask-Login
    @login_manager.user_loader
    def load_user(user_id):
        """Load user by ID for Flask-Login."""
        from models import User
        return db.session.get(User, int(user_id))

    # Template context processor for global settings
    @app.context_processor
    def inject_global_settings():
        """Inject global settings into all templates."""
        from models import AdminSettings
        return {
            'website_name': AdminSettings.get_setting('website_name', 'Neofrp Admin Panel'),
            'notification_banner': AdminSettings.get_setting('notification_banner', ''),
            'port_range_start': AdminSettings.get_setting('port_range_start', 20000),
            'port_range_end': AdminSettings.get_setting('port_range_end', 50000)
        }

    # Create database tables
    with app.app_context():
        db.create_all()

    return app

if __name__ == '__main__':
    app = create_app('development')
    app.run(debug=True, host='0.0.0.0', port=int(os.environ.get('APP_PORT', 5000)))
