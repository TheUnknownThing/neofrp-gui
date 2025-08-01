from datetime import datetime
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from database import db
import json


class User(UserMixin, db.Model):
    """User model for authentication and user management."""
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False, index=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(256))
    is_admin = db.Column(db.Boolean, default=False)
    is_active = db.Column(db.Boolean, default=True)
    tunnel_limit = db.Column(db.Integer, default=10)  # Default limit of 10 tunnels per user
    token = db.Column(db.String(128), unique=True, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime)
    
    # Relationships
    tunnels = db.relationship('Tunnel', backref='user', lazy='dynamic', cascade='all, delete-orphan')
    configurations = db.relationship('Configuration', backref='user', lazy='dynamic', cascade='all, delete-orphan')
    
    def set_password(self, password):
        """Set password hash."""
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        """Check if password matches."""
        return check_password_hash(self.password_hash, password)
    
    def generate_token(self):
        """Generate a unique token for the user."""
        import secrets
        self.token = secrets.token_urlsafe(32)
        return self.token
    
    def __repr__(self):
        return f'<User {self.username}>'


class Tunnel(db.Model):
    """Tunnel model for managing port forwarding configurations."""
    __tablename__ = 'tunnels'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    name = db.Column(db.String(128), nullable=False)
    protocol = db.Column(db.String(10), nullable=False)  # 'tcp' or 'udp'
    local_port = db.Column(db.Integer, nullable=False)
    server_port = db.Column(db.Integer, nullable=False)
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Constraints
    __table_args__ = (
        db.UniqueConstraint('user_id', 'name', name='_user_tunnel_name_uc'),
        db.CheckConstraint('protocol IN ("tcp", "udp")', name='_protocol_check'),
        db.CheckConstraint('local_port BETWEEN 1 AND 65535', name='_local_port_check'),
        db.CheckConstraint('server_port BETWEEN 1 AND 65535', name='_server_port_check'),
    )
    
    def to_dict(self):
        """Convert tunnel to dictionary for JSON serialization."""
        return {
            'type': self.protocol,
            'local_port': self.local_port,
            'server_port': self.server_port
        }
    
    def __repr__(self):
        return f'<Tunnel {self.name} ({self.protocol} {self.local_port}:{self.server_port})>'


class Configuration(db.Model):
    """Configuration model for storing generated client configurations."""
    __tablename__ = 'configurations'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    name = db.Column(db.String(128), nullable=False)
    server_ip = db.Column(db.String(45), nullable=False)  # Support IPv6
    server_port = db.Column(db.Integer, nullable=False)
    transport_protocol = db.Column(db.String(10), default='quic')  # 'quic' or 'tcp'
    config_json = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Constraints
    __table_args__ = (
        db.UniqueConstraint('user_id', 'name', name='_user_config_name_uc'),
        db.CheckConstraint('transport_protocol IN ("quic", "tcp")', name='_transport_check'),
        db.CheckConstraint('server_port BETWEEN 1 AND 65535', name='_server_port_check'),
    )
    
    def get_config(self):
        """Get configuration as dictionary."""
        return json.loads(self.config_json)
    
    def set_config(self, config_dict):
        """Set configuration from dictionary."""
        self.config_json = json.dumps(config_dict, indent=2)
    
    def __repr__(self):
        return f'<Configuration {self.name} for {self.user.username}>'


