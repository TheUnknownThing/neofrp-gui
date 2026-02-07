from flask import Blueprint, render_template, redirect, url_for, flash, request, jsonify
from flask_login import login_required, current_user
from functools import wraps
import logging

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
    from server_manager import ServerConfigManager

    user = User.query.get_or_404(user_id)

    # Prevent regular admins from editing root users
    if user.is_root_user and not current_user.is_root_user:
        flash('Only root administrators can manage root user accounts.', 'error')
        return redirect(url_for('admin.users'))

    # Prevent self-demotion from admin
    if user.id == current_user.id and user.is_administrator:
        can_change_admin = False
    else:
        can_change_admin = True

    form = UserEditForm(user_id=user_id, current_user=current_user, obj=user)

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

        old_active = user.is_active
        old_verified = user.is_verified

        user.is_active = form.is_active.data
        user.is_verified = form.is_verified.data
        user.tunnel_limit = form.tunnel_limit.data

        if form.new_password.data:
            user.set_password(form.new_password.data)

        db.session.commit()

        # Sync tokens if active/verified status changed
        if old_active != user.is_active or old_verified != user.is_verified:
            if not ServerConfigManager.sync_all():
                flash('User updated but server config sync failed. Check server logs.', 'warning')

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
    from server_manager import ServerConfigManager

    user = User.query.get_or_404(user_id)

    # Prevent self-deletion
    if user.id == current_user.id:
        flash('You cannot delete your own account.', 'error')
        return redirect(url_for('admin.users'))

    # Prevent regular admins from deleting root users
    if user.is_root_user and not current_user.is_root_user:
        flash('Only root administrators can delete root user accounts.', 'error')
        return redirect(url_for('admin.users'))

    username = user.username
    db.session.delete(user)
    db.session.commit()

    # Sync both tokens and ports since user's tunnels are also deleted
    if not ServerConfigManager.sync_all():
        flash('User deleted but server config sync failed. Check server logs.', 'warning')

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
    from server_manager import ServerConfigManager

    user = User.query.get_or_404(user_id)

    # Prevent regular admins from resetting root user tokens
    if user.is_root_user and not current_user.is_root_user:
        return jsonify({
            'success': False,
            'message': 'Only root administrators can reset root user tokens.'
        }), 403

    new_token = user.generate_token()
    db.session.commit()

    # Sync tokens so the server recognizes the new token
    if not ServerConfigManager.sync_all():
        return jsonify({
            'success': True,
            'message': f'Token reset for {user.username} but server sync failed.',
            'new_token': new_token
        })

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
    from models import Tunnel, User

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

    form = AdminSettingsForm()

    if form.validate_on_submit():
        AdminSettings.set_setting('registration_enabled', form.registration_enabled.data)
        AdminSettings.set_setting('require_verification', form.require_verification.data)

        flash('Settings updated successfully.', 'success')
        logger.info(f'Admin {current_user.username} updated registration settings')

        return redirect(url_for('admin.settings'))

    if request.method == 'GET':
        form.registration_enabled.data = AdminSettings.get_setting('registration_enabled', True)
        form.require_verification.data = AdminSettings.get_setting('require_verification', False)

    return render_template('admin/settings.html', form=form)

@admin_bp.route('/root-settings', methods=['GET', 'POST'])
@login_required
@root_user_required
def root_settings():
    """Root administrator settings management."""
    from forms import RootSettingsForm
    from models import AdminSettings

    form = RootSettingsForm()

    if form.validate_on_submit():
        AdminSettings.set_setting('website_name', form.website_name.data)
        AdminSettings.set_setting('notification_banner', form.notification_banner.data)
        AdminSettings.set_setting('port_range_start', form.port_range_start.data)
        AdminSettings.set_setting('port_range_end', form.port_range_end.data)

        flash('Root settings updated successfully.', 'success')
        logger.info(f'Root user {current_user.username} updated root settings')

        return redirect(url_for('admin.root_settings'))

    if request.method == 'GET':
        form.website_name.data = AdminSettings.get_setting('website_name', 'Neofrp')
        form.notification_banner.data = AdminSettings.get_setting('notification_banner', '')
        form.port_range_start.data = AdminSettings.get_setting('port_range_start', 20000)
        form.port_range_end.data = AdminSettings.get_setting('port_range_end', 50000)

    return render_template('admin/root_settings.html', form=form)

@admin_bp.route('/create-user', methods=['GET', 'POST'])
@login_required
@admin_required
def create_user():
    """Create a new user directly by admin."""
    from forms import AdminCreateUserForm
    from models import User
    from database import db
    from server_manager import ServerConfigManager

    form = AdminCreateUserForm(current_user=current_user)
    if form.validate_on_submit():
        if form.user_role.data == 'root_user' and not current_user.is_root_user:
            flash('Only root administrators can create root user accounts.', 'error')
            return render_template('admin/create_user.html', form=form)

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

        # Sync tokens so backend recognizes the new user
        if not ServerConfigManager.sync_all():
            flash('User created but server config sync failed. Check server logs.', 'warning')

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
    from server_manager import ServerConfigManager

    user = User.query.get_or_404(user_id)

    if user.is_root_user and not current_user.is_root_user:
        flash('Only root administrators can verify root user accounts.', 'error')
        return redirect(url_for('admin.users'))

    user.is_verified = True
    db.session.commit()

    # Sync tokens since verified users can now connect
    if not ServerConfigManager.sync_all():
        flash('User verified but server config sync failed. Check server logs.', 'warning')

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
    from server_manager import ServerConfigManager

    user = User.query.get_or_404(user_id)

    if user.id == current_user.id:
        flash('You cannot unverify your own account.', 'error')
        return redirect(url_for('admin.users'))

    if user.is_root_user and not current_user.is_root_user:
        flash('Only root administrators can unverify root user accounts.', 'error')
        return redirect(url_for('admin.users'))

    user.is_verified = False
    db.session.commit()

    # Sync tokens since unverified users should no longer connect
    if not ServerConfigManager.sync_all():
        flash('User unverified but server config sync failed. Check server logs.', 'warning')

    flash(f'User {user.username} has been unverified.', 'success')
    logger.info(f'Admin {current_user.username} unverified user {user.username}')

    return redirect(url_for('admin.users'))

@admin_bp.route('/server-config', methods=['GET', 'POST'])
@login_required
@root_user_required
def server_config():
    """Server configuration management."""
    from forms import ServerConfigForm
    from models import AdminSettings
    from server_manager import ServerConfigManager

    form = ServerConfigForm()

    if form.validate_on_submit():
        # Save admin settings
        AdminSettings.set_setting('server_config_path', form.server_config_path.data)
        AdminSettings.set_setting('server_name', form.server_name.data)
        AdminSettings.set_setting('default_ca_file', form.default_ca_file.data)
        AdminSettings.set_setting('server_ip', form.server_ip.data)

        # Update server config file
        if not ServerConfigManager.update_transport(
            protocol=form.transport_protocol.data,
            port=form.transport_port.data,
            cert_file=form.cert_file.data,
            key_file=form.key_file.data
        ):
            flash('Failed to update transport settings. Check server logs.', 'error')
            return redirect(url_for('admin.server_config'))

        # Update log level in server config
        config = ServerConfigManager.read_config()
        if config is not None:
            if 'log' not in config:
                config['log'] = {}
            config['log']['log_level'] = form.log_level.data
            ServerConfigManager.write_config(config)

        # Full sync to ensure tokens and ports are up to date
        if ServerConfigManager.sync_all():
            flash('Server configuration updated and synced successfully.', 'success')
        else:
            flash('Server configuration saved but sync failed. Check server logs.', 'warning')
        logger.info(f'Root user {current_user.username} updated server configuration')

        return redirect(url_for('admin.server_config'))

    # Populate form on GET
    if request.method == 'GET':
        form.server_config_path.data = AdminSettings.get_setting('server_config_path', '/etc/neofrp/server.json')
        form.server_name.data = AdminSettings.get_setting('server_name', '')
        form.default_ca_file.data = AdminSettings.get_setting('default_ca_file', '')
        form.server_ip.data = AdminSettings.get_setting('server_ip', '')

        config = ServerConfigManager.read_config()
        if config:
            transport = config.get('transport', {})
            form.transport_protocol.data = transport.get('protocol', 'quic')
            form.transport_port.data = transport.get('port', 3400)
            form.cert_file.data = transport.get('cert_file', '')
            form.key_file.data = transport.get('key_file', '')
            form.log_level.data = config.get('log', {}).get('log_level', 'info')

    # Get current sync status for display
    config = ServerConfigManager.read_config()
    sync_status = {
        'config_exists': config is not None,
        'config_path': AdminSettings.get_setting('server_config_path', '/etc/neofrp/server.json'),
        'tcp_ports': config.get('connections', {}).get('tcp_ports', []) if config else [],
        'udp_ports': config.get('connections', {}).get('udp_ports', []) if config else [],
        'server_running': ServerConfigManager.get_server_pid() is not None,
    }

    return render_template('admin/server_config.html', form=form, sync_status=sync_status)

@admin_bp.route('/server-config/sync', methods=['POST'])
@login_required
@root_user_required
def sync_server_config():
    """Manually trigger a full sync of server configuration."""
    from server_manager import ServerConfigManager

    success = ServerConfigManager.sync_all()

    if success:
        flash('Server configuration synced successfully.', 'success')
        logger.info(f'Root user {current_user.username} triggered server config sync')
    else:
        flash('Failed to sync server configuration. Check server logs.', 'error')
        logger.error(f'Root user {current_user.username} failed to sync server config')

    return redirect(url_for('admin.server_config'))

@admin_bp.route('/server-config/reload', methods=['POST'])
@login_required
@root_user_required
def reload_server_config():
    """Trigger hot reload of the neofrp server configuration.

    Sends SIGHUP to the running neofrp server process to reload its
    configuration without a full restart. Token and port access changes
    take effect immediately.
    """
    from server_manager import ServerConfigManager

    pid = ServerConfigManager.get_server_pid()
    if pid is None:
        flash('Cannot reload: neofrp server process not found.', 'error')
        return redirect(url_for('admin.server_config'))

    success = ServerConfigManager.trigger_reload()

    if success:
        flash(f'Configuration reloaded successfully (server PID: {pid}).', 'success')
        logger.info(f'Root user {current_user.username} triggered server config reload')
    else:
        flash('Failed to reload server configuration. Check server logs.', 'error')
        logger.error(f'Root user {current_user.username} failed to reload server config')

    return redirect(url_for('admin.server_config'))
