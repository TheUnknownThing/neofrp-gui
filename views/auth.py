from flask import Blueprint, render_template, redirect, url_for, flash, request, current_app
from flask_login import login_user, logout_user, current_user
from urllib.parse import urlparse
from datetime import datetime, timezone
import logging

auth_bp = Blueprint('auth', __name__)
logger = logging.getLogger(__name__)

# Import limiter for rate limiting
from app import limiter


def _is_safe_redirect_url(target):
    """Validate that the redirect URL is safe (same-origin, no scheme tricks)."""
    if not target:
        return False
    # Reject URLs with backslashes (browsers interpret \ as /)
    if '\\' in target:
        return False
    parsed = urlparse(target)
    # Only allow relative paths (no scheme, no netloc)
    if parsed.scheme or parsed.netloc:
        return False
    # Must start with / to be a relative path on the same host
    if not target.startswith('/'):
        return False
    return True


@auth_bp.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def login():
    """User login route."""
    if current_user.is_authenticated:
        return redirect(url_for('main.index'))

    from forms import LoginForm
    from models import User
    from database import db

    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()

        if user is None or not user.check_password(form.password.data):
            flash('Invalid username or password', 'error')
            logger.warning(f'Failed login attempt for username: {form.username.data}')
            return redirect(url_for('auth.login'))

        if not user.is_active:
            flash('Your account has been deactivated. Please contact an administrator.', 'error')
            return redirect(url_for('auth.login'))

        if not user.is_verified:
            flash('Your account is pending admin verification. Please contact an administrator.', 'error')
            return redirect(url_for('auth.login'))

        # Update last login time
        user.last_login = datetime.now(timezone.utc)
        db.session.commit()

        login_user(user, remember=form.remember_me.data)
        logger.info(f'User {user.username} logged in successfully')

        # Redirect to next page or appropriate dashboard
        next_page = request.args.get('next')
        if not _is_safe_redirect_url(next_page):
            if user.is_administrator:
                next_page = url_for('admin.dashboard')
            else:
                next_page = url_for('user.dashboard')

        return redirect(next_page)

    return render_template('auth/login.html', form=form)

@auth_bp.route('/register', methods=['GET', 'POST'])
@limiter.limit("3 per hour")
def register():
    """User registration route."""
    if current_user.is_authenticated:
        return redirect(url_for('main.index'))

    from forms import RegistrationForm
    from models import User, AdminSettings
    from database import db
    from server_manager import ServerConfigManager
    from sqlalchemy.exc import IntegrityError

    # Check if registration is enabled
    registration_enabled = AdminSettings.get_setting('registration_enabled', True)
    if not registration_enabled:
        return render_template('auth/register.html', registration_disabled=True)

    form = RegistrationForm()
    if form.validate_on_submit():
        # Check if admin verification is required
        require_verification = AdminSettings.get_setting('require_verification', False)

        # Create new user
        user = User(
            username=form.username.data,
            email=form.email.data
        )
        user.set_password(form.password.data)
        user.generate_token()

        # First user becomes root user and is automatically verified.
        # Use IntegrityError handling to guard against the race condition
        # where two users register simultaneously as the "first user".
        is_first_user = User.query.count() == 0
        if is_first_user:
            user.set_role('root_user')
            user.is_verified = True
        else:
            # Set verification status based on admin settings
            user.is_verified = not require_verification

        db.session.add(user)
        try:
            db.session.commit()
        except IntegrityError:
            db.session.rollback()
            flash('Username or email already taken. Please try again.', 'error')
            return render_template('auth/register.html', form=form)

        # If we promoted this user to root but another user already exists
        # (race condition), demote back to normal user
        if is_first_user and User.query.count() > 1:
            first_user = User.query.order_by(User.id.asc()).first()
            if first_user.id != user.id:
                user.set_role('user')
                user.is_verified = not require_verification
                db.session.commit()
            else:
                flash('As the first user, you have been granted root administrator privileges.', 'info')
        elif is_first_user:
            flash('As the first user, you have been granted root administrator privileges.', 'info')

        # Sync tokens to server config so backend recognizes the new user
        ServerConfigManager.sync_and_reload()

        logger.info(f'New user registered: {user.username}')

        if require_verification and not user.is_administrator:
            flash('Registration successful! Your account is pending admin verification before you can log in.', 'info')
        else:
            flash('Registration successful! You can now log in.', 'success')

        return redirect(url_for('auth.login'))

    return render_template('auth/register.html', form=form)

@auth_bp.route('/logout', methods=['POST'])
def logout():
    """User logout route."""
    if current_user.is_authenticated:
        logger.info(f'User {current_user.username} logged out')
        logout_user()
        flash('You have been logged out successfully.', 'info')

    return redirect(url_for('main.index'))
