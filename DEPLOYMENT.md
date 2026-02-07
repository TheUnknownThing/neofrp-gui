# Neofrp-GUI Production Deployment Guide

This guide provides comprehensive instructions for deploying neofrp-gui to a production environment.

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [System Requirements](#system-requirements)
3. [Installation Steps](#installation-steps)
4. [Configuration](#configuration)
5. [Database Setup](#database-setup)
6. [Web Server Configuration](#web-server-configuration)
7. [Security Hardening](#security-hardening)
8. [neofrp Server Integration](#neofrp-server-integration)
9. [Monitoring and Maintenance](#monitoring-and-maintenance)
10. [Troubleshooting](#troubleshooting)

---

## Prerequisites

- Linux server (Ubuntu 20.04+ or similar)
- Root or sudo access
- Domain name (recommended for HTTPS)
- SSL/TLS certificates (Let's Encrypt recommended)
- Python 3.8 or higher
- PostgreSQL 12+ or MySQL 8+ (for production) or SQLite (for testing only)

---

## System Requirements

### Minimum Requirements
- CPU: 1 core
- RAM: 512 MB
- Disk: 5 GB
- Network: 100 Mbps

### Recommended for Production
- CPU: 2+ cores
- RAM: 2 GB+
- Disk: 20 GB+ (SSD preferred)
- Network: 1 Gbps

---

## Installation Steps

### 1. Update System Packages

```bash
sudo apt update && sudo apt upgrade -y
```

### 2. Install System Dependencies

```bash
sudo apt install -y python3 python3-pip python3-venv git nginx postgresql redis-server
```

### 3. Create Application User

```bash
sudo useradd -m -s /bin/bash neofrp
sudo usermod -aG www-data neofrp
```

### 4. Clone the Repository

```bash
sudo su - neofrp
git clone https://github.com/yourusername/neofrp-gui.git /home/neofrp/neofrp-gui
cd /home/neofrp/neofrp-gui
```

### 5. Create Virtual Environment

```bash
python3 -m venv venv
source venv/bin/activate
```

### 6. Install Python Dependencies

```bash
pip install --upgrade pip
pip install -r requirements.txt
```

---

## Configuration

### 1. Create Environment File

Copy the example environment file and customize it:

```bash
cp env.example .env
nano .env
```

### 2. Configure Environment Variables

Edit `.env` with the following production settings:

```bash
# Flask Configuration
FLASK_APP=app.py
FLASK_ENV=production

# CRITICAL: Generate a secure secret key
# Run: python -c "import secrets; print(secrets.token_hex(32))"
SECRET_KEY=your-production-secret-key-here-64-characters

# Database Configuration (PostgreSQL recommended)
DATABASE_URL=postgresql://neofrp_user:secure_password@localhost/neofrp_db

# Application Settings
APP_HOST=127.0.0.1  # Bind to localhost, nginx will proxy
APP_PORT=5000

# Session Security
SESSION_COOKIE_SECURE=true  # MUST be true in production with HTTPS
SESSION_LIFETIME_HOURS=24

# Rate Limiting (use Redis for multi-instance deployments)
RATELIMIT_STORAGE_URI=redis://localhost:6379

# Initial Setup (optional)
# ADMIN_DEFAULT_PASSWORD=YourSecurePassword123!
```

### 3. Generate SECRET_KEY

**CRITICAL:** Never use the default secret key in production!

```bash
python3 -c "import secrets; print(secrets.token_hex(32))"
```

Copy the output and update `SECRET_KEY` in `.env`.

---

## Database Setup

### Option 1: PostgreSQL (Recommended for Production)

#### Install and Configure PostgreSQL

```bash
# Already installed in step 2
sudo -u postgres psql

# In PostgreSQL prompt:
CREATE DATABASE neofrp_db;
CREATE USER neofrp_user WITH PASSWORD 'secure_password';
GRANT ALL PRIVILEGES ON DATABASE neofrp_db TO neofrp_user;
\q
```

#### Update DATABASE_URL in .env

```bash
DATABASE_URL=postgresql://neofrp_user:secure_password@localhost/neofrp_db
```

### Option 2: MySQL

```bash
sudo apt install -y mysql-server
sudo mysql

# In MySQL prompt:
CREATE DATABASE neofrp_db CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER 'neofrp_user'@'localhost' IDENTIFIED BY 'secure_password';
GRANT ALL PRIVILEGES ON neofrp_db.* TO 'neofrp_user'@'localhost';
FLUSH PRIVILEGES;
EXIT;
```

Update DATABASE_URL:
```bash
DATABASE_URL=mysql://neofrp_user:secure_password@localhost/neofrp_db
```

### Option 3: SQLite (Development Only)

```bash
DATABASE_URL=sqlite:////home/neofrp/neofrp-gui/neofrp.db
```

**Warning:** SQLite is NOT recommended for production with multiple workers.

### Initialize Database

```bash
cd /home/neofrp/neofrp-gui
source venv/bin/activate
python init_db.py
```

Save the generated admin password securely!

---

## Web Server Configuration

### 1. Install and Configure Nginx

#### Create Nginx Configuration

```bash
sudo nano /etc/nginx/sites-available/neofrp
```

Add the following configuration:

```nginx
# Redirect HTTP to HTTPS
server {
    listen 80;
    listen [::]:80;
    server_name your-domain.com;

    return 301 https://$server_name$request_uri;
}

# HTTPS Server
server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name your-domain.com;

    # SSL Configuration
    ssl_certificate /etc/letsencrypt/live/your-domain.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/your-domain.com/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;
    ssl_prefer_server_ciphers on;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 10m;

    # Security Headers
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;

    # Logging
    access_log /var/log/nginx/neofrp_access.log;
    error_log /var/log/nginx/neofrp_error.log;

    # Max upload size
    client_max_body_size 10M;

    location / {
        proxy_pass http://127.0.0.1:5000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        # Timeouts
        proxy_connect_timeout 60s;
        proxy_send_timeout 60s;
        proxy_read_timeout 60s;
    }

    # Health check endpoint
    location /health {
        proxy_pass http://127.0.0.1:5000/health;
        access_log off;
    }
}
```

#### Enable Site and Test Configuration

```bash
sudo ln -s /etc/nginx/sites-available/neofrp /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl reload nginx
```

### 2. Obtain SSL Certificate with Let's Encrypt

```bash
sudo apt install -y certbot python3-certbot-nginx
sudo certbot --nginx -d your-domain.com
```

Follow the prompts to configure HTTPS.

### 3. Configure Gunicorn

Create systemd service file:

```bash
sudo nano /etc/systemd/system/neofrp-gui.service
```

Add the following:

```ini
[Unit]
Description=Neofrp GUI Web Application
After=network.target postgresql.service redis.service

[Service]
Type=notify
User=neofrp
Group=www-data
WorkingDirectory=/home/neofrp/neofrp-gui
Environment="PATH=/home/neofrp/neofrp-gui/venv/bin"

# Production settings with multiple workers
ExecStart=/home/neofrp/neofrp-gui/venv/bin/gunicorn \
    --bind 127.0.0.1:5000 \
    --workers 4 \
    --worker-class sync \
    --timeout 120 \
    --max-requests 1000 \
    --max-requests-jitter 50 \
    --access-logfile /var/log/neofrp-gui/access.log \
    --error-logfile /var/log/neofrp-gui/error.log \
    --log-level info \
    "app:create_app('production')"

# Restart policy
Restart=always
RestartSec=10

# Security hardening
PrivateTmp=true
NoNewPrivileges=true
ProtectSystem=strict
ReadWritePaths=/home/neofrp/neofrp-gui
ReadWritePaths=/etc/neofrp

[Install]
WantedBy=multi-user.target
```

### 4. Create Log Directory

```bash
sudo mkdir -p /var/log/neofrp-gui
sudo chown neofrp:www-data /var/log/neofrp-gui
```

### 5. Start and Enable Service

```bash
sudo systemctl daemon-reload
sudo systemctl start neofrp-gui
sudo systemctl enable neofrp-gui
sudo systemctl status neofrp-gui
```

---

## Security Hardening

### 1. Firewall Configuration

```bash
# Install UFW if not already installed
sudo apt install -y ufw

# Allow SSH
sudo ufw allow 22/tcp

# Allow HTTP and HTTPS
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp

# Allow neofrp server port (adjust as needed)
sudo ufw allow 3400/tcp
sudo ufw allow 3400/udp

# Enable firewall
sudo ufw enable
sudo ufw status
```

### 2. File Permissions

```bash
# Set correct ownership
sudo chown -R neofrp:www-data /home/neofrp/neofrp-gui

# Secure sensitive files
chmod 600 /home/neofrp/neofrp-gui/.env

# Database file (if using SQLite)
chmod 600 /home/neofrp/neofrp-gui/neofrp.db

# Server config directory
sudo mkdir -p /etc/neofrp
sudo chown neofrp:neofrp /etc/neofrp
sudo chmod 700 /etc/neofrp
```

### 3. Disable Root Login (SSH)

```bash
sudo nano /etc/ssh/sshd_config
```

Set:
```
PermitRootLogin no
PasswordAuthentication no  # Use SSH keys only
```

Restart SSH:
```bash
sudo systemctl restart sshd
```

### 4. Configure Fail2Ban

```bash
sudo apt install -y fail2ban

# Create jail for nginx
sudo nano /etc/fail2ban/jail.d/nginx-neofrp.conf
```

Add:
```ini
[nginx-neofrp]
enabled = true
port = http,https
filter = nginx-neofrp
logpath = /var/log/nginx/neofrp_access.log
maxretry = 5
bantime = 3600
```

Create filter:
```bash
sudo nano /etc/fail2ban/filter.d/nginx-neofrp.conf
```

Add:
```ini
[Definition]
failregex = ^<HOST> .* "(GET|POST|HEAD).*" (401|403|404) .*$
ignoreregex =
```

Restart fail2ban:
```bash
sudo systemctl restart fail2ban
```

### 5. Regular Security Updates

```bash
# Enable automatic security updates
sudo apt install -y unattended-upgrades
sudo dpkg-reconfigure --priority=low unattended-upgrades
```

---

## neofrp Server Integration

### 1. Install neofrp Server

Follow the neofrp server installation instructions from the backend repository.

### 2. Configure Server Path in Web GUI

1. Log in as root administrator
2. Navigate to **Admin Dashboard** → **Server Config**
3. Set **Server Config File Path**: `/etc/neofrp/server.json`
4. Configure transport settings:
   - **Protocol**: Choose QUIC or TCP
   - **Listen Port**: 3400 (or your preferred port)
   - **Certificate File**: `/etc/letsencrypt/live/your-domain.com/fullchain.pem`
   - **Key File**: `/etc/letsencrypt/live/your-domain.com/privkey.pem`
   - **Server Name (SNI)**: `your-domain.com`
5. Set **Server IP/Domain**: Your public IP or domain name
6. Click **Save & Sync**

### 3. Grant Permissions

```bash
# Allow neofrp user to write config
sudo chown neofrp:neofrp /etc/neofrp/server.json 2>/dev/null || true
sudo chmod 600 /etc/neofrp/server.json 2>/dev/null || true
```

### 4. Start neofrp Server

Create systemd service for neofrp server:

```bash
sudo nano /etc/systemd/system/neofrp-server.service
```

Add:
```ini
[Unit]
Description=Neofrp Server
After=network.target

[Service]
Type=simple
User=neofrp
WorkingDirectory=/opt/neofrp
ExecStart=/opt/neofrp/neofrp-server -c /etc/neofrp/server.json
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

Start and enable:
```bash
sudo systemctl daemon-reload
sudo systemctl start neofrp-server
sudo systemctl enable neofrp-server
sudo systemctl status neofrp-server
```

---

## Monitoring and Maintenance

### 1. Log Monitoring

Monitor application logs:
```bash
# Gunicorn logs
sudo tail -f /var/log/neofrp-gui/error.log
sudo tail -f /var/log/neofrp-gui/access.log

# Nginx logs
sudo tail -f /var/log/nginx/neofrp_error.log
sudo tail -f /var/log/nginx/neofrp_access.log

# System logs
sudo journalctl -u neofrp-gui -f
sudo journalctl -u neofrp-server -f
```

### 2. Health Checks

The application provides a health check endpoint:

```bash
curl https://your-domain.com/health
```

Expected response:
```json
{
  "status": "healthy",
  "timestamp": "2026-02-06T12:00:00Z",
  "checks": {
    "database": "ok",
    "application": "ok"
  }
}
```

### 3. Database Backups

#### PostgreSQL Backup Script

Create backup script:
```bash
sudo nano /usr/local/bin/backup-neofrp-db.sh
```

Add:
```bash
#!/bin/bash
BACKUP_DIR="/home/neofrp/backups"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
mkdir -p $BACKUP_DIR

# Backup database
sudo -u postgres pg_dump neofrp_db | gzip > $BACKUP_DIR/neofrp_db_$TIMESTAMP.sql.gz

# Keep only last 30 days of backups
find $BACKUP_DIR -name "neofrp_db_*.sql.gz" -mtime +30 -delete

echo "Backup completed: neofrp_db_$TIMESTAMP.sql.gz"
```

Make executable:
```bash
sudo chmod +x /usr/local/bin/backup-neofrp-db.sh
```

Schedule daily backups:
```bash
sudo crontab -e
```

Add:
```
0 2 * * * /usr/local/bin/backup-neofrp-db.sh >> /var/log/neofrp-backup.log 2>&1
```

### 4. Update Application

```bash
# Switch to neofrp user
sudo su - neofrp
cd /home/neofrp/neofrp-gui

# Pull latest changes
git pull origin main

# Activate virtualenv
source venv/bin/activate

# Update dependencies
pip install --upgrade -r requirements.txt

# Run database migrations (if any)
flask db upgrade

# Restart application
sudo systemctl restart neofrp-gui
```

### 5. Monitoring Tools (Optional)

Consider installing monitoring tools:

- **Prometheus + Grafana** for metrics
- **ELK Stack** for log analysis
- **Uptime Kuma** for uptime monitoring

---

## Troubleshooting

### Common Issues

#### 1. Service Won't Start

Check logs:
```bash
sudo journalctl -u neofrp-gui -n 50 --no-pager
```

Check if port is in use:
```bash
sudo netstat -tlnp | grep 5000
```

#### 2. Database Connection Errors

Test database connection:
```bash
# PostgreSQL
sudo -u postgres psql -d neofrp_db -c "SELECT 1;"

# Check DATABASE_URL in .env
cat /home/neofrp/neofrp-gui/.env | grep DATABASE_URL
```

#### 3. Permission Denied Errors

Fix ownership:
```bash
sudo chown -R neofrp:www-data /home/neofrp/neofrp-gui
sudo chmod 755 /home/neofrp/neofrp-gui
```

#### 4. 502 Bad Gateway

Check if gunicorn is running:
```bash
sudo systemctl status neofrp-gui
```

Check nginx error log:
```bash
sudo tail -f /var/log/nginx/neofrp_error.log
```

#### 5. SSL Certificate Issues

Renew certificate:
```bash
sudo certbot renew --dry-run
sudo certbot renew
sudo systemctl reload nginx
```

#### 6. Server Config Sync Failures

Check file permissions:
```bash
ls -la /etc/neofrp/
```

Check logs:
```bash
sudo journalctl -u neofrp-gui | grep -i "sync\|config"
```

### Getting Help

- Check GitHub Issues: https://github.com/TheUnknownThing/neofrp-gui/issues
- Review application logs
- Check system logs: `sudo journalctl -xe`

---

## Security Checklist

Before going live, verify:

- [ ] SECRET_KEY is set to a secure random value
- [ ] FLASK_ENV is set to 'production'
- [ ] SESSION_COOKIE_SECURE is set to 'true'
- [ ] Database credentials are strong and unique
- [ ] SSL/TLS certificates are valid and auto-renewing
- [ ] Firewall is enabled and configured
- [ ] SSH is hardened (no root login, key-based auth)
- [ ] Admin password has been changed from default
- [ ] Database backups are automated
- [ ] Log rotation is configured
- [ ] Monitoring is in place
- [ ] fail2ban is configured and running
- [ ] Server config file has secure permissions (0600)
- [ ] Application is running as non-root user

---

## Performance Tuning

### Optimize Gunicorn Workers

Calculate workers:
```
workers = (2 × CPU_cores) + 1
```

For a 4-core system: `workers = 9`

### Database Connection Pooling

For PostgreSQL, adjust in `/etc/postgresql/*/main/postgresql.conf`:
```
max_connections = 100
shared_buffers = 256MB
```

### Redis Configuration

For multi-server deployments, use Redis for rate limiting and sessions.

Install Redis:
```bash
sudo apt install -y redis-server
```

Configure in `.env`:
```bash
RATELIMIT_STORAGE_URI=redis://localhost:6379
```

---

## Conclusion

Your neofrp-gui installation is now production-ready! Remember to:

1. Regularly update the system and application
2. Monitor logs and metrics
3. Test backups regularly
4. Keep security patches up to date
5. Review access logs for suspicious activity

For additional support, consult the project documentation or open an issue on GitHub.

---

**Last Updated:** February 6, 2026
**Version:** 1.0
