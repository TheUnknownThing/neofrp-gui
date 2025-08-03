from flask import Blueprint, render_template, redirect, url_for, flash, request, jsonify
from flask_login import login_required, current_user
from functools import wraps
import logging
import psutil
import os

admin_bp = Blueprint('admin', __name__)
logger = logging.getLogger(__name__)

# Admin required decorator
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_administrator:
            flash('You need administrator privileges to access this page.', 'error')
            return redirect(url_for('main.index'))
        return f(*args, **kwargs)
    return decorated_function

# Root user required decorator
def root_user_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_root_user:
            flash('You need root administrator privileges to access this page.', 'error')
            return redirect(url_for('admin.dashboard'))
        return f(*args, **kwargs)
    return decorated_function

@admin_bp.route('/dashboard')
@login_required
@admin_required
def dashboard():
    """Admin dashboard with system overview."""
    from models import User, Tunnel, Configuration
    from database import db
    
    # Get system statistics
    stats = {
        'total_users': User.query.count(),
        'active_users': User.query.filter_by(is_active=True).count(),
        'total_tunnels': Tunnel.query.count(),
        'active_tunnels': Tunnel.query.filter_by(is_active=True).count(),
        'total_configs': Configuration.query.count(),
    }
    
    # Get recent users
    recent_users = User.query.order_by(User.created_at.desc()).limit(5).all()
    
    return render_template('admin/dashboard.html', 
                         stats=stats,
                         recent_users=recent_users)

@admin_bp.route('/users')
@login_required
@admin_required
def users():
    """User management page."""
    from models import User
    
    page = request.args.get('page', 1, type=int)
    per_page = 20
    
    users_pagination = User.query.order_by(User.created_at.desc()).paginate(
        page=page, per_page=per_page, error_out=False
    )
    
    return render_template('admin/users.html', users=users_pagination)

@admin_bp.route('/users/<int:user_id>/edit', methods=['GET', 'POST'])
@login_required
@admin_required
def edit_user(user_id):
    """Edit user information."""
    from models import User
    from database import db
    from forms import UserEditForm
    
    user = User.query.get_or_404(user_id)
    
    # Prevent self-demotion from admin
    if user.id == current_user.id and user.is_admin:
        can_change_admin = False
    else:
        can_change_admin = True
    
    form = UserEditForm(user_id=user_id, obj=user)
    
    # Populate form with current user data on GET requests
    if request.method == 'GET':
        form.user_role.data = user.user_role
    
    if form.validate_on_submit():
        user.username = form.username.data
        user.email = form.email.data
        
        if can_change_admin:
            # Only root users can create/edit root users
            if form.user_role.data == 'root_user' and not current_user.is_root_user:
                flash('Only root administrators can manage root user accounts.', 'error')
                return render_template('admin/edit_user.html', 
                                     form=form, 
                                     user=user,
                                     can_change_admin=can_change_admin)
            user.set_role(form.user_role.data)
        
        user.is_active = form.is_active.data
        user.is_verified = form.is_verified.data
        user.tunnel_limit = form.tunnel_limit.data
        
        if form.new_password.data:
            user.set_password(form.new_password.data)
        
        db.session.commit()
        flash(f'User {user.username} has been updated successfully.', 'success')
        logger.info(f'Admin {current_user.username} updated user {user.username}')
        
        return redirect(url_for('admin.users'))
    
    return render_template('admin/edit_user.html', 
                         form=form, 
                         user=user,
                         can_change_admin=can_change_admin)

@admin_bp.route('/users/<int:user_id>/delete', methods=['POST'])
@login_required
@admin_required
def delete_user(user_id):
    """Delete a user."""
    from models import User
    from database import db
    
    user = User.query.get_or_404(user_id)
    
    # Prevent self-deletion
    if user.id == current_user.id:
        flash('You cannot delete your own account.', 'error')
        return redirect(url_for('admin.users'))
    
    username = user.username
    db.session.delete(user)
    db.session.commit()
    
    flash(f'User {username} has been deleted.', 'success')
    logger.info(f'Admin {current_user.username} deleted user {username}')
    
    return redirect(url_for('admin.users'))

@admin_bp.route('/users/<int:user_id>/reset-token', methods=['POST'])
@login_required
@admin_required
def reset_user_token(user_id):
    """Reset a user's authentication token."""
    from models import User
    from database import db
    
    user = User.query.get_or_404(user_id)
    
    old_token = user.token
    new_token = user.generate_token()
    db.session.commit()
    
    logger.info(f'Admin {current_user.username} reset token for user {user.username}')
    
    return jsonify({
        'success': True,
        'message': f'Token reset successfully for {user.username}',
        'new_token': new_token
    })

@admin_bp.route('/tunnels')
@login_required
@admin_required
def tunnels():
    """View all tunnels in the system."""
    from models import Tunnel
    from models import User
    
    page = request.args.get('page', 1, type=int)
    per_page = 20
    
    tunnels_pagination = Tunnel.query.join(User).order_by(Tunnel.created_at.desc()).paginate(
        page=page, per_page=per_page, error_out=False
    )
    
    return render_template('admin/tunnels.html', tunnels=tunnels_pagination)

@admin_bp.route('/settings', methods=['GET', 'POST'])
@login_required
@admin_required
def settings():
    """Admin settings management."""
    from forms import AdminSettingsForm
    from models import AdminSettings
    from database import db
    
    form = AdminSettingsForm()
    
    if form.validate_on_submit():
        # Update settings
        AdminSettings.set_setting('registration_enabled', form.registration_enabled.data)
        AdminSettings.set_setting('require_verification', form.require_verification.data)
        
        flash('Settings updated successfully.', 'success')
        logger.info(f'Admin {current_user.username} updated registration settings')
        
        return redirect(url_for('admin.settings'))
    
    # Only populate form with current settings on GET requests
    if request.method == 'GET':
        registration_enabled = AdminSettings.get_setting('registration_enabled', True)
        require_verification = AdminSettings.get_setting('require_verification', False)
        
        form.registration_enabled.data = registration_enabled
        form.require_verification.data = require_verification
    
    return render_template('admin/settings.html', form=form)

@admin_bp.route('/root-settings', methods=['GET', 'POST'])
@login_required
@root_user_required
def root_settings():
    """Root administrator settings management."""
    from forms import RootSettingsForm
    from models import AdminSettings
    from database import db
    
    form = RootSettingsForm()
    
    if form.validate_on_submit():
        # Update root-only settings
        AdminSettings.set_setting('website_name', form.website_name.data)
        AdminSettings.set_setting('notification_banner', form.notification_banner.data)
        AdminSettings.set_setting('port_range_start', form.port_range_start.data)
        AdminSettings.set_setting('port_range_end', form.port_range_end.data)
        
        flash('Root settings updated successfully.', 'success')
        logger.info(f'Root user {current_user.username} updated root settings')
        
        return redirect(url_for('admin.root_settings'))
    
    # Only populate form with current settings on GET requests
    if request.method == 'GET':
        website_name = AdminSettings.get_setting('website_name', 'Neofrp Admin Panel')
        notification_banner = AdminSettings.get_setting('notification_banner', '')
        port_range_start = AdminSettings.get_setting('port_range_start', 20000)
        port_range_end = AdminSettings.get_setting('port_range_end', 50000)
        
        form.website_name.data = website_name
        form.notification_banner.data = notification_banner
        form.port_range_start.data = port_range_start
        form.port_range_end.data = port_range_end
    
    return render_template('admin/root_settings.html', form=form)

@admin_bp.route('/create-user', methods=['GET', 'POST'])
@login_required
@admin_required
def create_user():
    """Create a new user directly by admin."""
    from forms import AdminCreateUserForm
    from models import User
    from database import db
    
    form = AdminCreateUserForm()
    if form.validate_on_submit():
        # Only root users can create root users
        if form.user_role.data == 'root_user' and not current_user.is_root_user:
            flash('Only root administrators can create root user accounts.', 'error')
            return render_template('admin/create_user.html', form=form)
        
        # Create new user
        user = User(
            username=form.username.data,
            email=form.email.data,
            is_active=form.is_active.data,
            is_verified=form.is_verified.data,
            tunnel_limit=form.tunnel_limit.data
        )
        user.set_password(form.password.data)
        user.set_role(form.user_role.data)
        user.generate_token()
        
        db.session.add(user)
        db.session.commit()
        
        flash(f'User {user.username} created successfully.', 'success')
        logger.info(f'Admin {current_user.username} created new user: {user.username}')
        
        return redirect(url_for('admin.users'))
    
    return render_template('admin/create_user.html', form=form)

@admin_bp.route('/users/<int:user_id>/verify', methods=['POST'])
@login_required
@admin_required
def verify_user(user_id):
    """Verify a user."""
    from models import User
    from database import db
    
    user = User.query.get_or_404(user_id)
    user.is_verified = True
    db.session.commit()
    
    flash(f'User {user.username} has been verified.', 'success')
    logger.info(f'Admin {current_user.username} verified user {user.username}')
    
    return redirect(url_for('admin.users'))

@admin_bp.route('/users/<int:user_id>/unverify', methods=['POST'])
@login_required
@admin_required
def unverify_user(user_id):
    """Unverify a user."""
    from models import User
    from database import db
    
    user = User.query.get_or_404(user_id)
    
    # Prevent unverifying self
    if user.id == current_user.id:
        flash('You cannot unverify your own account.', 'error')
        return redirect(url_for('admin.users'))
    
    user.is_verified = False
    db.session.commit()
    
    flash(f'User {user.username} has been unverified.', 'success')
    logger.info(f'Admin {current_user.username} unverified user {user.username}')
    
    return redirect(url_for('admin.users'))

@admin_bp.route('/server-config')
@login_required
@admin_required
def server_config():
    """Server configuration management."""
    # This would interact with the actual neofrp server configuration
    # For now, we'll show a placeholder
    return render_template('admin/server_config.html')