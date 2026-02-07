import re
from flask import Blueprint, render_template, redirect, url_for, flash, request, jsonify, Response
from flask_login import login_required, current_user
from forms import TunnelForm, ConfigurationForm, ChangePasswordForm
import json
import logging
from datetime import datetime, timezone

user_bp = Blueprint('user', __name__)
logger = logging.getLogger(__name__)

# Import limiter for rate limiting
from app import limiter


def _sanitize_filename(name):
    """Sanitize a string for use in Content-Disposition filename."""
    # Remove any characters that are not alphanumeric, dash, underscore, or dot
    return re.sub(r'[^\w\-.]', '_', name)


@user_bp.route('/dashboard')
@login_required
def dashboard():
    """User dashboard with overview of their resources."""
    from models import Tunnel, Configuration

    # Get user's tunnels and configurations
    tunnels = current_user.tunnels.order_by(Tunnel.created_at.desc()).limit(5).all()
    configurations = current_user.configurations.order_by(Configuration.created_at.desc()).limit(5).all()

    stats = {
        'total_tunnels': current_user.tunnels.count(),
        'active_tunnels': current_user.tunnels.filter_by(is_active=True).count(),
        'total_configs': current_user.configurations.count(),
    }

    return render_template('user/dashboard.html',
                         tunnels=tunnels,
                         configurations=configurations,
                         stats=stats)

@user_bp.route('/tunnels')
@login_required
def tunnels():
    """List user's tunnels."""
    from models import Tunnel

    page = request.args.get('page', 1, type=int)
    per_page = 10

    tunnels_pagination = current_user.tunnels.order_by(Tunnel.created_at.desc()).paginate(
        page=page, per_page=per_page, error_out=False
    )

    return render_template('user/tunnels.html', tunnels=tunnels_pagination)

@user_bp.route('/tunnels/new', methods=['GET', 'POST'])
@login_required
def new_tunnel():
    """Create a new tunnel."""
    from models import Tunnel
    from database import db
    from server_manager import ServerConfigManager
    from sqlalchemy.exc import IntegrityError

    form = TunnelForm()

    if form.validate_on_submit():
        # Check tunnel limit
        if current_user.tunnel_limit > 0:  # 0 means unlimited
            current_tunnel_count = current_user.tunnels.count()
            if current_tunnel_count >= current_user.tunnel_limit:
                flash(f'You have reached your tunnel limit of {current_user.tunnel_limit} tunnels.', 'error')
                return render_template('user/tunnel_form.html', form=form, title='New Tunnel')

        # Check if tunnel name already exists for this user
        existing = Tunnel.query.filter_by(
            user_id=current_user.id,
            name=form.name.data
        ).first()

        if existing:
            flash('A tunnel with this name already exists.', 'error')
            return render_template('user/tunnel_form.html', form=form, title='New Tunnel')

        # Check if server port is already in use by any user
        port_conflict = Tunnel.query.filter_by(
            server_port=form.server_port.data
        ).first()

        if port_conflict:
            flash(f'Server port {form.server_port.data} is already in use. Please choose a different port.', 'error')
            return render_template('user/tunnel_form.html', form=form, title='New Tunnel')

        tunnel = Tunnel(
            user_id=current_user.id,
            name=form.name.data,
            protocol=form.protocol.data,
            local_port=form.local_port.data,
            server_port=form.server_port.data
        )

        db.session.add(tunnel)
        try:
            db.session.commit()
        except IntegrityError:
            db.session.rollback()
            flash('Server port conflict. Please choose a different port.', 'error')
            return render_template('user/tunnel_form.html', form=form, title='New Tunnel')

        # Sync ports to server config so the backend opens the new port
        if not ServerConfigManager.sync_ports():
            flash('Tunnel created but server config sync failed. Contact an administrator.', 'warning')

        flash(f'Tunnel "{tunnel.name}" created successfully!', 'success')
        logger.info(f'User {current_user.username} created tunnel {tunnel.name}')

        return redirect(url_for('user.tunnels'))

    return render_template('user/tunnel_form.html', form=form, title='New Tunnel')

@user_bp.route('/tunnels/<int:tunnel_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_tunnel(tunnel_id):
    """Edit an existing tunnel."""
    from models import Tunnel
    from database import db
    from server_manager import ServerConfigManager
    from sqlalchemy.exc import IntegrityError

    tunnel = Tunnel.query.filter_by(id=tunnel_id, user_id=current_user.id).first_or_404()
    form = TunnelForm(obj=tunnel)

    if form.validate_on_submit():
        # Check if new name conflicts with another tunnel
        if tunnel.name != form.name.data:
            existing = Tunnel.query.filter_by(
                user_id=current_user.id,
                name=form.name.data
            ).first()

            if existing:
                flash('A tunnel with this name already exists.', 'error')
                return render_template('user/tunnel_form.html',
                                     form=form,
                                     title='Edit Tunnel',
                                     tunnel=tunnel)

        # Check if server port is already in use by another tunnel
        if tunnel.server_port != form.server_port.data:
            port_conflict = Tunnel.query.filter_by(
                server_port=form.server_port.data
            ).first()

            if port_conflict:
                flash(f'Server port {form.server_port.data} is already in use. Please choose a different port.', 'error')
                return render_template('user/tunnel_form.html',
                                     form=form,
                                     title='Edit Tunnel',
                                     tunnel=tunnel)

        tunnel.name = form.name.data
        tunnel.protocol = form.protocol.data
        tunnel.local_port = form.local_port.data
        tunnel.server_port = form.server_port.data
        tunnel.updated_at = datetime.now(timezone.utc)

        try:
            db.session.commit()
        except IntegrityError:
            db.session.rollback()
            flash('Server port conflict. Please choose a different port.', 'error')
            return render_template('user/tunnel_form.html',
                                 form=form,
                                 title='Edit Tunnel',
                                 tunnel=tunnel)

        # Sync ports to server config in case port or protocol changed
        if not ServerConfigManager.sync_ports():
            flash('Tunnel updated but server config sync failed. Contact an administrator.', 'warning')

        flash(f'Tunnel "{tunnel.name}" updated successfully!', 'success')
        logger.info(f'User {current_user.username} updated tunnel {tunnel.name}')

        return redirect(url_for('user.tunnels'))

    return render_template('user/tunnel_form.html',
                         form=form,
                         title='Edit Tunnel',
                         tunnel=tunnel)

@user_bp.route('/tunnels/<int:tunnel_id>/toggle', methods=['POST'])
@login_required
def toggle_tunnel(tunnel_id):
    """Toggle tunnel active status."""
    from models import Tunnel
    from database import db
    from server_manager import ServerConfigManager

    tunnel = Tunnel.query.filter_by(id=tunnel_id, user_id=current_user.id).first_or_404()

    tunnel.is_active = not tunnel.is_active
    tunnel.updated_at = datetime.now(timezone.utc)
    db.session.commit()

    # Sync ports since active status changed
    if not ServerConfigManager.sync_ports():
        logger.warning(f'Failed to sync ports after toggling tunnel {tunnel.name}')

    status = 'activated' if tunnel.is_active else 'deactivated'
    logger.info(f'User {current_user.username} {status} tunnel {tunnel.name}')

    return jsonify({
        'success': True,
        'is_active': tunnel.is_active,
        'message': f'Tunnel {status} successfully'
    })

@user_bp.route('/tunnels/<int:tunnel_id>/delete', methods=['POST'])
@login_required
def delete_tunnel(tunnel_id):
    """Delete a tunnel."""
    from models import Tunnel
    from database import db
    from server_manager import ServerConfigManager

    tunnel = Tunnel.query.filter_by(id=tunnel_id, user_id=current_user.id).first_or_404()

    tunnel_name = tunnel.name
    db.session.delete(tunnel)
    db.session.commit()

    # Sync ports since a tunnel was removed
    if not ServerConfigManager.sync_ports():
        flash('Tunnel deleted but server config sync failed. Contact an administrator.', 'warning')

    flash(f'Tunnel "{tunnel_name}" deleted successfully.', 'success')
    logger.info(f'User {current_user.username} deleted tunnel {tunnel_name}')

    return redirect(url_for('user.tunnels'))

@user_bp.route('/configurations')
@login_required
def configurations():
    """List user's configurations."""
    from models import Configuration

    configs = current_user.configurations.order_by(Configuration.created_at.desc()).all()
    return render_template('user/configurations.html', configurations=configs)

@user_bp.route('/configurations/generate', methods=['GET', 'POST'])
@login_required
def generate_config():
    """Generate a new configuration."""
    from models import Configuration, AdminSettings
    from database import db

    form = ConfigurationForm()

    # Pre-fill defaults from admin settings on GET
    if request.method == 'GET':
        default_server_name = AdminSettings.get_setting('server_name', '')
        default_ca_file = AdminSettings.get_setting('default_ca_file', '')
        if default_server_name and not form.server_name.data:
            form.server_name.data = default_server_name
        if default_ca_file and not form.ca_file.data:
            form.ca_file.data = default_ca_file

    if form.validate_on_submit():
        # Get server settings from admin configuration (not user input)
        from server_manager import ServerConfigManager

        server_ip = AdminSettings.get_setting('server_ip', '')
        if not server_ip:
            flash('Server IP/domain not configured. Please contact an administrator.', 'error')
            active_tunnels = current_user.tunnels.filter_by(is_active=True).all()
            return render_template('user/generate_config.html',
                                 form=form,
                                 active_tunnels=active_tunnels,
                                 user_token=current_user.token)

        # Get transport settings from server config
        server_config = ServerConfigManager.read_config()
        if not server_config or 'transport' not in server_config:
            flash('Server transport not configured. Please contact an administrator.', 'error')
            active_tunnels = current_user.tunnels.filter_by(is_active=True).all()
            return render_template('user/generate_config.html',
                                 form=form,
                                 active_tunnels=active_tunnels,
                                 user_token=current_user.token)

        transport_protocol = server_config['transport'].get('protocol', 'quic')
        server_port = server_config['transport'].get('port', 3400)

        # Get user's active tunnels
        active_tunnels = current_user.tunnels.filter_by(is_active=True).all()

        if not active_tunnels:
            flash('You need at least one active tunnel to generate a configuration.', 'warning')
            return redirect(url_for('user.tunnels'))

        # Check for duplicate config name
        existing = Configuration.query.filter_by(
            user_id=current_user.id,
            name=form.name.data
        ).first()
        if existing:
            flash('A configuration with this name already exists.', 'error')
            active_tunnels = current_user.tunnels.filter_by(is_active=True).all()
            return render_template('user/generate_config.html',
                                 form=form,
                                 active_tunnels=active_tunnels,
                                 user_token=current_user.token)

        # Build configuration JSON matching backend's ClientConfig format
        transport_config = {
            "protocol": transport_protocol,
            "server_ip": server_ip,
            "server_port": server_port
        }

        # Add TLS fields required for QUIC/TLS connections
        if form.ca_file.data:
            transport_config["ca_file"] = form.ca_file.data
        if form.server_name.data:
            transport_config["server_name"] = form.server_name.data

        config_data = {
            "log": {
                "log_level": "info"
            },
            "token": current_user.token,
            "transport": transport_config,
            "connections": [tunnel.to_dict() for tunnel in active_tunnels]
        }

        # Save configuration (store admin settings for audit trail)
        config = Configuration(
            user_id=current_user.id,
            name=form.name.data,
            server_ip=server_ip,
            server_port=server_port,
            transport_protocol=transport_protocol
        )
        config.set_config(config_data)

        db.session.add(config)
        db.session.commit()

        flash(f'Configuration "{config.name}" generated successfully!', 'success')
        logger.info(f'User {current_user.username} generated configuration {config.name}')

        return redirect(url_for('user.configurations'))

    # Get active tunnels for preview
    active_tunnels = current_user.tunnels.filter_by(is_active=True).all()

    # Get server info from admin settings for display
    from server_manager import ServerConfigManager
    server_ip = AdminSettings.get_setting('server_ip', 'Not configured yet')
    server_config = ServerConfigManager.read_config()
    server_port = server_config['transport'].get('port', 3400) if server_config and 'transport' in server_config else 'Not configured'
    transport_protocol = server_config['transport'].get('protocol', 'quic') if server_config and 'transport' in server_config else 'Not configured'

    return render_template('user/generate_config.html',
                         form=form,
                         active_tunnels=active_tunnels,
                         user_token=current_user.token,
                         server_ip=server_ip,
                         server_port=server_port,
                         transport_protocol=transport_protocol)

@user_bp.route('/configurations/<int:config_id>/download')
@login_required
def download_config(config_id):
    """Download configuration as JSON file."""
    from models import Configuration

    config = Configuration.query.filter_by(
        id=config_id,
        user_id=current_user.id
    ).first_or_404()

    safe_name = _sanitize_filename(config.name)
    response = Response(
        config.config_json,
        mimetype='application/json',
        headers={
            'Content-Disposition': f'attachment; filename="{safe_name}.json"'
        }
    )

    return response

@user_bp.route('/configurations/<int:config_id>/delete', methods=['POST'])
@login_required
def delete_config(config_id):
    """Delete a configuration."""
    from models import Configuration
    from database import db

    config = Configuration.query.filter_by(
        id=config_id,
        user_id=current_user.id
    ).first_or_404()

    config_name = config.name
    db.session.delete(config)
    db.session.commit()

    flash(f'Configuration "{config_name}" deleted successfully.', 'success')
    logger.info(f'User {current_user.username} deleted configuration {config_name}')

    return redirect(url_for('user.configurations'))

@user_bp.route('/profile')
@login_required
def profile():
    """User profile page."""
    return render_template('user/profile.html')

@user_bp.route('/change-password', methods=['GET', 'POST'])
@login_required
@limiter.limit("5 per hour")
def change_password():
    """Allow users to change their own password."""
    from database import db

    form = ChangePasswordForm()

    if form.validate_on_submit():
        # Verify current password
        if not current_user.check_password(form.current_password.data):
            flash('Current password is incorrect.', 'error')
            return render_template('user/change_password.html', form=form)

        # Set new password
        current_user.set_password(form.new_password.data)
        db.session.commit()

        flash('Password changed successfully!', 'success')
        logger.info(f'User {current_user.username} changed their password')

        return redirect(url_for('user.profile'))

    return render_template('user/change_password.html', form=form)

