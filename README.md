# Neofrp Admin Panel

A modern web-based administration panel for managing Neofrp reverse proxy users and configurations.

## Features

- **User Management**: Register, login, and manage user accounts
- **Admin Dashboard**: System overview, user management, and resource monitoring
- **Tunnel Management**: Create and manage port forwarding rules
- **Configuration Generator**: Generate client configuration files
- **Modern UI**: Clean, responsive interface built with Tailwind CSS

## Installation

### Prerequisites

- Python 3.8 or higher
- pip (Python package installer)
- Neofrp server and client binaries

### Setup

1. **Clone the repository** (if not already done):
   ```bash
   git clone https://github.com/RayZh-hs/neofrp/
   cd neofrp-gui/neofrp-admin
   ```

2. **Create a virtual environment** (recommended):
   ```bash
   uv venv
   source .venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. **Install dependencies**:
   ```bash
   uv pip install -r requirements.txt
   ```

4. **Set up environment variables**:
   ```bash
   cp env.example .env
   # Edit .env with your configuration
   ```

5. **Initialize the database**:
   ```bash
   python init_db.py
   ```

## Running the Application

### Development Mode

```bash
python app.py
```

The application will be available at `http://localhost:5000`

### Production Mode

For production deployment, use a WSGI server like Gunicorn:

```bash
gunicorn -w 4 -b 0.0.0.0:5000 app:create_app()
```

Or use the provided run script:

```bash
./run.sh
```

## Default Credentials

If the database is empty, a default admin user will be created:
- **Username**: admin
- **Password**: admin123

⚠️ **Important**: Change the default password immediately after first login!

## Configuration

### Environment Variables

- `SECRET_KEY`: Flask secret key for session management
- `DATABASE_URL`: Database connection string (default: SQLite)
- `FLASK_ENV`: Environment mode (development/production)

### Database Support

The admin panel supports multiple databases:
- SQLite (default): `sqlite:///neofrp.db`
- PostgreSQL: `postgresql://user:password@localhost/neofrp`
- MySQL: `mysql://user:password@localhost/neofrp`

## Usage Guide

### For Regular Users

1. **Register an account** or login with existing credentials
2. **Create tunnels** to define port forwarding rules
3. **Generate configuration** files for your active tunnels
4. **Download the config** and use with Neofrp client

### For Administrators

1. **Access admin dashboard** for system overview
2. **Manage users**: View, edit, or delete user accounts
3. **Monitor tunnels**: See all tunnels across the system
4. **Reset user tokens** when needed

## Security Considerations

1. Always use HTTPS in production
2. Set a strong `SECRET_KEY` in production
3. Regularly update dependencies
4. Use a proper database (not SQLite) for production
5. Implement rate limiting for API endpoints
6. Regular backup your database

## Troubleshooting

### Database Issues

```bash
# Reset database (WARNING: This will delete all data)
rm neofrp.db
python init_db.py
```

### Migration Issues

```bash
# Initialize migrations
flask db init

# Create a new migration
flask db migrate -m "Description"

# Apply migrations
flask db upgrade
```

## Contributing

Contributions are welcome! Please follow these steps:

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details.