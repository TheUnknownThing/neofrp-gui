from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, IntegerField, SelectField, TextAreaField
from wtforms.validators import DataRequired, Email, EqualTo, Length, NumberRange, ValidationError, Optional
from models import User


class LoginForm(FlaskForm):
    """Form for user login."""
    username = StringField('Username', validators=[
        DataRequired(message='Username is required')
    ])
    password = PasswordField('Password', validators=[
        DataRequired(message='Password is required')
    ])
    remember_me = BooleanField('Remember Me')


class RegistrationForm(FlaskForm):
    """Form for user registration."""
    username = StringField('Username', validators=[
        DataRequired(message='Username is required'),
        Length(min=3, max=64, message='Username must be between 3 and 64 characters')
    ])
    email = StringField('Email', validators=[
        DataRequired(message='Email is required'),
        Email(message='Invalid email address')
    ])
    password = PasswordField('Password', validators=[
        DataRequired(message='Password is required'),
        Length(min=8, message='Password must be at least 8 characters long')
    ])
    password_confirm = PasswordField('Confirm Password', validators=[
        DataRequired(message='Please confirm your password'),
        EqualTo('password', message='Passwords must match')
    ])
    
    def validate_username(self, username):
        """Check if username is already taken."""
        user = User.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError('Username already taken. Please choose another one.')
    
    def validate_email(self, email):
        """Check if email is already registered."""
        user = User.query.filter_by(email=email.data).first()
        if user:
            raise ValidationError('Email already registered. Please use another one.')


class TunnelForm(FlaskForm):
    """Form for creating/editing tunnels."""
    name = StringField('Tunnel Name', validators=[
        DataRequired(message='Tunnel name is required'),
        Length(min=1, max=128, message='Name must be between 1 and 128 characters')
    ])
    protocol = SelectField('Protocol', choices=[
        ('tcp', 'TCP'),
        ('udp', 'UDP')
    ], validators=[
        DataRequired(message='Protocol is required')
    ])
    local_port = IntegerField('Local Port', validators=[
        DataRequired(message='Local port is required'),
        NumberRange(min=1, max=65535, message='Port must be between 1 and 65535')
    ])
    server_port = IntegerField('Server Port', validators=[
        DataRequired(message='Server port is required'),
        NumberRange(min=1, max=65535, message='Port must be between 1 and 65535')
    ])
    
    def validate_server_port(self, server_port):
        """Validate server port is within the allowed range."""
        from models import AdminSettings
        
        # Get port range settings
        port_range_start = AdminSettings.get_setting('port_range_start', 20000)
        port_range_end = AdminSettings.get_setting('port_range_end', 50000)
        
        if server_port.data < port_range_start or server_port.data > port_range_end:
            raise ValidationError(f'Server port must be between {port_range_start} and {port_range_end}.')


class ConfigurationForm(FlaskForm):
    """Form for creating/editing configurations."""
    name = StringField('Configuration Name', validators=[
        DataRequired(message='Configuration name is required'),
        Length(min=1, max=128, message='Name must be between 1 and 128 characters')
    ])
    server_ip = StringField('Server IP/Domain', validators=[
        DataRequired(message='Server IP or domain is required'),
        Length(min=1, max=255)
    ])
    server_port = IntegerField('Server Port', validators=[
        DataRequired(message='Server port is required'),
        NumberRange(min=1, max=65535, message='Port must be between 1 and 65535')
    ])
    transport_protocol = SelectField('Transport Protocol', choices=[
        ('quic', 'QUIC (UDP-based)'),
        ('tcp', 'TCP with TLS')
    ], validators=[
        DataRequired(message='Transport protocol is required')
    ])


class UserEditForm(FlaskForm):
    """Form for editing user information (admin use)."""
    username = StringField('Username', validators=[
        DataRequired(message='Username is required'),
        Length(min=3, max=64)
    ])
    email = StringField('Email', validators=[
        DataRequired(message='Email is required'),
        Email(message='Invalid email address')
    ])
    user_role = SelectField('User Role', choices=[
        ('user', 'Regular User'),
        ('admin', 'Administrator'),
        ('root_user', 'Root Administrator')
    ], validators=[
        DataRequired(message='User role is required')
    ])
    is_admin = BooleanField('Administrator')  # Keep for compatibility, will be auto-set
    is_active = BooleanField('Active')
    is_verified = BooleanField('Verified')
    tunnel_limit = IntegerField('Tunnel Limit', validators=[
        DataRequired(message='Tunnel limit is required'),
        NumberRange(min=0, max=1000, message='Tunnel limit must be between 0 and 1000')
    ])
    new_password = PasswordField('New Password', validators=[
        Optional(),
        Length(min=8, message='Password must be at least 8 characters long')
    ])
    
    def __init__(self, user_id=None, *args, **kwargs):
        super(UserEditForm, self).__init__(*args, **kwargs)
        self.user_id = user_id
    
    def validate_username(self, username):
        """Check if username is already taken by another user."""
        user = User.query.filter_by(username=username.data).first()
        if user and user.id != self.user_id:
            raise ValidationError('Username already taken.')
    
    def validate_email(self, email):
        """Check if email is already registered by another user."""
        user = User.query.filter_by(email=email.data).first()
        if user and user.id != self.user_id:
            raise ValidationError('Email already registered.')


class AdminSettingsForm(FlaskForm):
    """Form for admin settings management."""
    registration_enabled = BooleanField('Allow New Registrations', 
                                      default=True,
                                      description='Enable or disable new user registration')
    require_verification = BooleanField('Require Admin Verification', 
                                       default=False,
                                       description='New users must be verified by admin before they can use the system')


class RootSettingsForm(FlaskForm):
    """Form for root administrator settings management."""
    website_name = StringField('Website Name', validators=[
        DataRequired(message='Website name is required'),
        Length(min=1, max=100, message='Website name must be between 1 and 100 characters')
    ], default='Neofrp Admin Panel',
    description='Name displayed in the header and browser title')
    
    notification_banner = TextAreaField('Notification Banner', validators=[
        Optional(),
        Length(max=500, message='Notification banner must be less than 500 characters')
    ], description='Important announcement displayed at the top of all pages (leave empty to disable)')
    
    port_range_start = IntegerField('Port Range Start', validators=[
        DataRequired(message='Port range start is required'),
        NumberRange(min=1, max=65535, message='Port must be between 1 and 65535')
    ], default=20000,
    description='Starting port number for available tunnel ports')
    
    port_range_end = IntegerField('Port Range End', validators=[
        DataRequired(message='Port range end is required'),
        NumberRange(min=1, max=65535, message='Port must be between 1 and 65535')
    ], default=50000,
    description='Ending port number for available tunnel ports')
    
    def validate_port_range_end(self, port_range_end):
        """Ensure end port is greater than start port."""
        if hasattr(self, 'port_range_start') and self.port_range_start.data:
            if port_range_end.data <= self.port_range_start.data:
                raise ValidationError('End port must be greater than start port.')


class AdminCreateUserForm(FlaskForm):
    """Form for admin to create new users directly."""
    username = StringField('Username', validators=[
        DataRequired(message='Username is required'),
        Length(min=3, max=64, message='Username must be between 3 and 64 characters')
    ])
    email = StringField('Email', validators=[
        DataRequired(message='Email is required'),
        Email(message='Invalid email address')
    ])
    password = PasswordField('Password', validators=[
        DataRequired(message='Password is required'),
        Length(min=8, message='Password must be at least 8 characters long')
    ])
    user_role = SelectField('User Role', choices=[
        ('user', 'Regular User'),
        ('admin', 'Administrator'),
        ('root_user', 'Root Administrator')
    ], validators=[
        DataRequired(message='User role is required')
    ], default='user')
    is_admin = BooleanField('Administrator')  # Keep for compatibility, will be auto-set
    is_active = BooleanField('Active', default=True)
    is_verified = BooleanField('Verified', default=True)
    tunnel_limit = IntegerField('Tunnel Limit', validators=[
        DataRequired(message='Tunnel limit is required'),
        NumberRange(min=0, max=1000, message='Tunnel limit must be between 0 and 1000')
    ], default=10)
    
    def validate_username(self, username):
        """Check if username is already taken."""
        user = User.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError('Username already taken. Please choose another one.')
    
    def validate_email(self, email):
        """Check if email is already registered."""
        user = User.query.filter_by(email=email.data).first()
        if user:
            raise ValidationError('Email already registered. Please use another one.')