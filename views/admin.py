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
        if not current_user.is_authenticated or not current_user.is_admin:
            flash('You need administrator privileges to access this page.', 'error')
            return redirect(url_for('main.index'))
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
    
    # Get system resource usage
    cpu_percent = psutil.cpu_percent(interval=1)
    memory = psutil.virtual_memory()
    disk = psutil.disk_usage('/')
    
    system_info = {
        'cpu_percent': cpu_percent,
        'memory_percent': memory.percent,
        'memory_used': memory.used // (1024 * 1024),  # MB
        'memory_total': memory.total // (1024 * 1024),  # MB
        'disk_percent': disk.percent,
        'disk_used': disk.used // (1024 * 1024 * 1024),  # GB
        'disk_total': disk.total // (1024 * 1024 * 1024),  # GB
    }
    
    # Get recent users
    recent_users = User.query.order_by(User.created_at.desc()).limit(5).all()
    
    return render_template('admin/dashboard.html', 
                         stats=stats, 
                         system_info=system_info,
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
    
    if form.validate_on_submit():
        user.username = form.username.data
        user.email = form.email.data
        
        if can_change_admin:
            user.is_admin = form.is_admin.data
        
        user.is_active = form.is_active.data
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

@admin_bp.route('/server-config')
@login_required
@admin_required
def server_config():
    """Server configuration management."""
    # This would interact with the actual neofrp server configuration
    # For now, we'll show a placeholder
    return render_template('admin/server_config.html')