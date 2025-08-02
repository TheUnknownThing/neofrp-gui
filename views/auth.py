from flask import Blueprint, render_template, redirect, url_for, flash, request, current_app
from flask_login import login_user, logout_user, current_user
from urllib.parse import urlparse
from datetime import datetime
import logging

auth_bp = Blueprint('auth', __name__)
logger = logging.getLogger(__name__)

@auth_bp.route('/login', methods=['GET', 'POST'])
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
        user.last_login = datetime.utcnow()
        db.session.commit()
        
        login_user(user, remember=form.remember_me.data)
        logger.info(f'User {user.username} logged in successfully')
        
        # Redirect to next page or appropriate dashboard
        next_page = request.args.get('next')
        if not next_page or urlparse(next_page).netloc != '':
            if user.is_admin:
                next_page = url_for('admin.dashboard')
            else:
                next_page = url_for('user.dashboard')
        
        return redirect(next_page)
    
    return render_template('auth/login.html', form=form)

@auth_bp.route('/register', methods=['GET', 'POST'])
def register():
    """User registration route."""
    if current_user.is_authenticated:
        return redirect(url_for('main.index'))
    
    from forms import RegistrationForm
    from models import User, AdminSettings
    from database import db
    
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
        
        # First user becomes admin and is automatically verified
        if User.query.count() == 0:
            user.is_admin = True
            user.is_verified = True
            flash('As the first user, you have been granted administrator privileges.', 'info')
        else:
            # Set verification status based on admin settings
            user.is_verified = not require_verification
        
        db.session.add(user)
        db.session.commit()
        
        logger.info(f'New user registered: {user.username}')
        
        if require_verification and not user.is_admin:
            flash('Registration successful! Your account is pending admin verification before you can log in.', 'info')
        else:
            flash('Registration successful! You can now log in.', 'success')
        
        return redirect(url_for('auth.login'))
    
    return render_template('auth/register.html', form=form)

@auth_bp.route('/logout')
def logout():
    """User logout route."""
    if current_user.is_authenticated:
        logger.info(f'User {current_user.username} logged out')
        logout_user()
        flash('You have been logged out successfully.', 'info')
    
    return redirect(url_for('main.index'))