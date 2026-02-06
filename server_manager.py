"""Server configuration manager for neofrp backend integration.

This module bridges the web frontend with the neofrp server by managing
the server's JSON configuration file. It syncs user tokens and tunnel
ports so the backend server recognizes connecting clients.
"""

import json
import os
import logging
import tempfile

logger = logging.getLogger(__name__)


class ServerConfigManager:
    """Manages the neofrp server configuration file."""

    @staticmethod
    def get_config_path():
        """Get the server config file path from admin settings."""
        from models import AdminSettings
        return AdminSettings.get_setting('server_config_path', '/etc/neofrp/server.json')

    @staticmethod
    def read_config():
        """Read the current server configuration."""
        config_path = ServerConfigManager.get_config_path()
        if os.path.exists(config_path):
            try:
                with open(config_path, 'r') as f:
                    return json.load(f)
            except (json.JSONDecodeError, OSError) as e:
                logger.error(f'Failed to read server config at {config_path}: {e}')
                return None
        return ServerConfigManager._default_config()

    @staticmethod
    def write_config(config):
        """Write configuration to file atomically."""
        config_path = ServerConfigManager.get_config_path()
        config_dir = os.path.dirname(config_path)

        try:
            os.makedirs(config_dir, exist_ok=True)

            # Write to temp file first, then rename for atomicity
            fd, tmp_path = tempfile.mkstemp(dir=config_dir, suffix='.json.tmp')
            try:
                with os.fdopen(fd, 'w') as f:
                    json.dump(config, f, indent=4)
                os.replace(tmp_path, config_path)
            except Exception:
                # Clean up temp file on failure
                if os.path.exists(tmp_path):
                    os.unlink(tmp_path)
                raise

            logger.info(f'Server config written to {config_path}')
            return True
        except OSError as e:
            logger.error(f'Failed to write server config to {config_path}: {e}')
            return False

    @staticmethod
    def _default_config():
        """Return default server configuration."""
        return {
            "log": {"log_level": "info"},
            "recognized_tokens": [],
            "transport": {
                "protocol": "quic",
                "port": 3400,
                "cert_file": "",
                "key_file": ""
            },
            "connections": {
                "tcp_ports": [],
                "udp_ports": []
            }
        }

    @staticmethod
    def sync_tokens():
        """Sync all active verified user tokens to server config."""
        config = ServerConfigManager.read_config()
        if config is None:
            logger.error('Cannot sync tokens: failed to read server config')
            return False

        from models import User
        active_users = User.query.filter_by(is_active=True, is_verified=True).all()
        config['recognized_tokens'] = [user.token for user in active_users]

        return ServerConfigManager.write_config(config)

    @staticmethod
    def sync_ports():
        """Sync all active tunnel ports to server config."""
        config = ServerConfigManager.read_config()
        if config is None:
            logger.error('Cannot sync ports: failed to read server config')
            return False

        from models import Tunnel
        active_tunnels = Tunnel.query.filter_by(is_active=True).all()
        tcp_ports = sorted(set(t.server_port for t in active_tunnels if t.protocol == 'tcp'))
        udp_ports = sorted(set(t.server_port for t in active_tunnels if t.protocol == 'udp'))

        if 'connections' not in config:
            config['connections'] = {}
        config['connections']['tcp_ports'] = tcp_ports
        config['connections']['udp_ports'] = udp_ports

        return ServerConfigManager.write_config(config)

    @staticmethod
    def sync_all():
        """Full sync: tokens and ports to server config.

        Reads the config once, updates both sections, and writes once.
        """
        config = ServerConfigManager.read_config()
        if config is None:
            logger.error('Cannot sync: failed to read server config')
            return False

        from models import User, Tunnel

        # Sync tokens
        active_users = User.query.filter_by(is_active=True, is_verified=True).all()
        config['recognized_tokens'] = [user.token for user in active_users]

        # Sync ports
        active_tunnels = Tunnel.query.filter_by(is_active=True).all()
        tcp_ports = sorted(set(t.server_port for t in active_tunnels if t.protocol == 'tcp'))
        udp_ports = sorted(set(t.server_port for t in active_tunnels if t.protocol == 'udp'))

        if 'connections' not in config:
            config['connections'] = {}
        config['connections']['tcp_ports'] = tcp_ports
        config['connections']['udp_ports'] = udp_ports

        return ServerConfigManager.write_config(config)

    @staticmethod
    def update_transport(protocol=None, port=None, cert_file=None, key_file=None):
        """Update server transport settings."""
        config = ServerConfigManager.read_config()
        if config is None:
            logger.error('Cannot update transport: failed to read server config')
            return False

        if 'transport' not in config:
            config['transport'] = {}

        if protocol is not None:
            config['transport']['protocol'] = protocol
        if port is not None:
            config['transport']['port'] = port
        if cert_file is not None:
            config['transport']['cert_file'] = cert_file
        if key_file is not None:
            config['transport']['key_file'] = key_file

        return ServerConfigManager.write_config(config)

    @staticmethod
    def get_server_info():
        """Get server transport info for client config generation."""
        from models import AdminSettings
        return {
            'server_name': AdminSettings.get_setting('server_name', ''),
            'default_ca_file': AdminSettings.get_setting('default_ca_file', ''),
        }
