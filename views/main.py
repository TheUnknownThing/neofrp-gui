from flask import Blueprint, render_template, redirect, url_for, jsonify
from flask_login import current_user
from datetime import datetime, timezone
import markdown
import logging

main_bp = Blueprint('main', __name__)

# Import csrf for health check exemption
from app import csrf

@main_bp.route('/')
def index():
    """Homepage route."""
    if current_user.is_authenticated:
        # Redirect authenticated users to their dashboard
        if current_user.is_administrator:
            return redirect(url_for('admin.dashboard'))
        else:
            return redirect(url_for('user.dashboard'))
    
    # Prepare feature list for homepage
    features = [
        {
            'title': 'High Performance',
            'description': 'Built with Go for concurrent processing and ultra-low latency',
            'icon': 'rocket'
        },
        {
            'title': 'Secure Transport',
            'description': 'Enforced secure communication via QUIC and TLS protocols',
            'icon': 'shield'
        },
        {
            'title': 'Port Multiplexing',
            'description': 'Efficient handling of multiple TCP/UDP port forwarding',
            'icon': 'network'
        },
        {
            'title': 'Easy Management',
            'description': 'User-friendly web interface for tunnel configuration',
            'icon': 'settings'
        }
    ]
    
    return render_template('index.html', features=features)

@main_bp.route('/about')
def about():
    """About page with project information."""
    about_content = """
# About Neofrp

Neofrp is a modern, high-performance reverse proxy implementation in Go, 
focusing on speed, multiplexing, and secure transport protocols.

## Key Features

- **Performance First**: Built with Go's concurrency model for maximum throughput
- **Security by Default**: All connections are encrypted using QUIC or TLS
- **Flexible Configuration**: Support for both TCP and UDP forwarding
- **Web Management**: Easy-to-use admin panel for configuration

## Use Cases

- Expose local development servers to the internet
- Access home services from anywhere
- Bypass NAT and firewall restrictions
- Create secure tunnels for remote access
    """
    
    about_html = markdown.markdown(about_content)
    return render_template('about.html', content=about_html)

@main_bp.route('/docs')
def docs():
    """Documentation page."""
    return render_template('docs.html')

@main_bp.route('/health')
@csrf.exempt
def health():
    """Health check endpoint for monitoring systems."""
    from database import db
    logger = logging.getLogger(__name__)

    status = {
        'status': 'healthy',
        'timestamp': datetime.now(timezone.utc).isoformat(),
        'checks': {}
    }

    # Database connectivity check
    try:
        db.session.execute(db.text('SELECT 1'))
        status['checks']['database'] = 'ok'
    except Exception as e:
        status['status'] = 'unhealthy'
        status['checks']['database'] = 'error'
        logger.error(f'Health check database error: {e}')

    # Application check (always passes if we got here)
    status['checks']['application'] = 'ok'

    http_code = 200 if status['status'] == 'healthy' else 503
    return jsonify(status), http_code