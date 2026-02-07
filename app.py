import os
import logging
import secrets
from datetime import timedelta
from flask import Flask
from flask_login import LoginManager
from flask_wtf.csrf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from dotenv import load_dotenv
from database import db, migrate

# Initialize extensions
login_manager = LoginManager()
csrf = CSRFProtect()
limiter = Limiter(
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://",
    strategy="fixed-window"
)

# Load environment variables
load_dotenv()

def create_app(config_name='production'):
    """Create and configure the Flask application."""
    app = Flask(__name__)

    # Store config name for later use
    app.config['CONFIG_ENV'] = config_name

    # Configure app - SECRET_KEY must be explicitly set in production
    secret_key = os.environ.get('SECRET_KEY')
    if config_name == 'production' and not secret_key:
        raise RuntimeError(
            'SECRET_KEY environment variable is not set. '
            'Refusing to start in production without a secure secret key. '
            'Generate one with: python -c "import secrets; print(secrets.token_hex(32))"'
        )
    app.config['SECRET_KEY'] = secret_key or secrets.token_hex(32)

    app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///neofrp.db')
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    app.config['WTF_CSRF_ENABLED'] = True

    # Session security
    app.config['SESSION_COOKIE_HTTPONLY'] = True
    app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
    app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(
        hours=int(os.environ.get('SESSION_LIFETIME_HOURS', '24'))
    )
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

    # Initialize rate limiter with configurable storage
    storage_uri = os.environ.get('RATELIMIT_STORAGE_URI', 'memory://')
    limiter.storage_uri = storage_uri
    limiter.init_app(app)

    # Configure login manager
    login_manager.login_view = 'auth.login'
    login_manager.login_message = 'Please log in to access this page.'
    login_manager.login_message_category = 'warning'

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
        from datetime import datetime
        return {
            'website_name': AdminSettings.get_setting('website_name', 'Neofrp'),
            'notification_banner': AdminSettings.get_setting('notification_banner', ''),
            'port_range_start': AdminSettings.get_setting('port_range_start', 20000),
            'port_range_end': AdminSettings.get_setting('port_range_end', 50000),
            'current_year': datetime.now().year,
        }

    # Security headers
    @app.after_request
    def set_security_headers(response):
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'SAMEORIGIN'
        response.headers['X-XSS-Protection'] = '1; mode=block'
        response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'

        # Content Security Policy - allows CDN resources and inline scripts for Alpine.js
        csp_policy = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' https://cdn.tailwindcss.com https://cdn.jsdelivr.net; "
            "style-src 'self' 'unsafe-inline' https://cdn.tailwindcss.com https://cdnjs.cloudflare.com; "
            "font-src 'self' https://cdnjs.cloudflare.com; "
            "img-src 'self' data: https:; "
            "connect-src 'self'; "
            "frame-ancestors 'self';"
        )
        response.headers['Content-Security-Policy'] = csp_policy

        # Strict-Transport-Security (HSTS) in production with HTTPS
        if app.config.get('CONFIG_ENV') == 'production' and app.config.get('SESSION_COOKIE_SECURE'):
            response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'

        return response

    # Rate limit error handler
    @app.errorhandler(429)
    def ratelimit_handler(e):
        from flask import render_template, flash
        flash('Too many requests. Please try again later.', 'error')
        return render_template('errors/429.html'), 429

    # 404 Not Found error handler
    @app.errorhandler(404)
    def not_found_error(e):
        from flask import render_template
        return render_template('errors/404.html'), 404

    # 403 Forbidden error handler
    @app.errorhandler(403)
    def forbidden_error(e):
        from flask import render_template
        return render_template('errors/403.html'), 403

    # 500 Internal Server Error handler
    @app.errorhandler(500)
    def internal_error(e):
        from flask import render_template
        # Rollback database session on error
        db.session.rollback()
        logger = logging.getLogger(__name__)
        logger.error(f'Internal server error: {e}')
        return render_template('errors/500.html'), 500

    # Create database tables
    with app.app_context():
        db.create_all()

    return app

if __name__ == '__main__':
    # Read environment configuration
    env = os.environ.get('FLASK_ENV', 'production')
    app = create_app(env)
    debug_mode = env == 'development'

    # Security check: Never allow debug mode in production
    if env == 'production' and debug_mode:
        raise RuntimeError('Debug mode cannot be enabled in production!')

    # Log startup configuration
    logger = logging.getLogger(__name__)
    logger.info(f'Starting application in {env} mode')
    logger.info(f'Debug mode: {debug_mode}')

    app.run(
        debug=debug_mode,
        host=os.environ.get('APP_HOST', '0.0.0.0'),
        port=int(os.environ.get('APP_PORT', 5000))
    )
