from flask import Blueprint, render_template, redirect, url_for, flash, request, jsonify, Response
from flask_login import login_required, current_user
from forms import *
import json
import logging
from datetime import datetime

user_bp = Blueprint('user', __name__)
logger = logging.getLogger(__name__)

@user_bp.route('/dashboard')
@login_required
def dashboard():
    """User dashboard with overview of their resources."""
    from models import Tunnel, Configuration
    from database import db
    
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
    
    form = TunnelForm()
    
    if form.validate_on_submit():
        # Check if tunnel name already exists for this user
        existing = Tunnel.query.filter_by(
            user_id=current_user.id,
            name=form.name.data
        ).first()
        
        if existing:
            flash('A tunnel with this name already exists.', 'error')
            return render_template('user/tunnel_form.html', form=form, title='New Tunnel')
        
        tunnel = Tunnel(
            user_id=current_user.id,
            name=form.name.data,
            protocol=form.protocol.data,
            local_port=form.local_port.data,
            server_port=form.server_port.data
        )
        
        db.session.add(tunnel)
        db.session.commit()
        
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
        
        tunnel.name = form.name.data
        tunnel.protocol = form.protocol.data
        tunnel.local_port = form.local_port.data
        tunnel.server_port = form.server_port.data
        tunnel.updated_at = datetime.utcnow()
        
        db.session.commit()
        
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

    tunnel = Tunnel.query.filter_by(id=tunnel_id, user_id=current_user.id).first_or_404()
    
    tunnel.is_active = not tunnel.is_active
    tunnel.updated_at = datetime.utcnow()
    db.session.commit()
    
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

    tunnel = Tunnel.query.filter_by(id=tunnel_id, user_id=current_user.id).first_or_404()
    
    tunnel_name = tunnel.name
    db.session.delete(tunnel)
    db.session.commit()
    
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
    from models import Configuration
    from database import db
    
    form = ConfigurationForm()
    
    if form.validate_on_submit():
        # Get user's active tunnels
        active_tunnels = current_user.tunnels.filter_by(is_active=True).all()
        
        if not active_tunnels:
            flash('You need at least one active tunnel to generate a configuration.', 'warning')
            return redirect(url_for('user.tunnels'))
        
        # Build configuration JSON
        config_data = {
            "log": {
                "log_level": "info"
            },
            "token": current_user.token,
            "transport": {
                "protocol": form.transport_protocol.data,
                "server_ip": form.server_ip.data,
                "server_port": form.server_port.data
            },
            "connections": [tunnel.to_dict() for tunnel in active_tunnels]
        }
        
        # Save configuration
        config = Configuration(
            user_id=current_user.id,
            name=form.name.data,
            server_ip=form.server_ip.data,
            server_port=form.server_port.data,
            transport_protocol=form.transport_protocol.data
        )
        config.set_config(config_data)
        
        db.session.add(config)
        db.session.commit()
        
        flash(f'Configuration "{config.name}" generated successfully!', 'success')
        logger.info(f'User {current_user.username} generated configuration {config.name}')
        
        return redirect(url_for('user.configurations'))
    
    # Get active tunnels for preview
    active_tunnels = current_user.tunnels.filter_by(is_active=True).all()
    
    return render_template('user/generate_config.html', 
                         form=form,
                         active_tunnels=active_tunnels,
                         user_token=current_user.token)

@user_bp.route('/configurations/<int:config_id>/download')
@login_required
def download_config(config_id):
    """Download configuration as JSON file."""
    from models import Configuration
    
    config = Configuration.query.filter_by(
        id=config_id, 
        user_id=current_user.id
    ).first_or_404()
    
    # Create response with JSON content
    response = Response(
        config.config_json,
        mimetype='application/json',
        headers={
            'Content-Disposition': f'attachment; filename="{config.name}.json"'
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