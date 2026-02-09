"""Server configuration manager for neofrp backend integration.

This module bridges the web frontend with the neofrp server by managing
the server's JSON configuration file. It syncs user tokens and tunnel
ports so the backend server recognizes connecting clients.
"""

import json
import os
import logging
import tempfile
import stat

logger = logging.getLogger(__name__)


class ServerConfigManager:
    """Manages the neofrp server configuration file."""

    @staticmethod
    def get_log_source():
        """Get server log source setting.

        Supported: 'journal' (systemd journalctl for neofrp-server), 'file' (log file path).
        Defaults to 'journal'.
        """
        from models import AdminSettings
        value = AdminSettings.get_setting('server_log_source', 'journal')
        return value if value in ('journal', 'file') else 'journal'

    @staticmethod
    def get_log_file_path():
        """Get server log file path setting (used when log source is 'file')."""
        from models import AdminSettings
        return AdminSettings.get_setting('server_log_file_path', '')

    @staticmethod
    def _tail_file(file_path: str, max_lines: int, max_bytes: int = 1024 * 1024) -> str:
        """Tail a text file efficiently.

        - Reads from the end of file.
        - Caps total bytes read to prevent memory issues.
        """
        if max_lines <= 0:
            return ''

        real_path = os.path.realpath(file_path)
        try:
            st = os.stat(real_path)
        except OSError as e:
            raise OSError(f'Unable to stat log file: {e}')

        if not stat.S_ISREG(st.st_mode):
            raise OSError('Log path is not a regular file')

        # Read from end in blocks until we have enough lines or hit max_bytes
        block_size = 8192
        data = b''
        bytes_read = 0
        with open(real_path, 'rb') as f:
            f.seek(0, os.SEEK_END)
            file_size = f.tell()
            offset = file_size
            while offset > 0 and data.count(b'\n') <= max_lines and bytes_read < max_bytes:
                read_size = min(block_size, offset)
                offset -= read_size
                f.seek(offset)
                chunk = f.read(read_size)
                data = chunk + data
                bytes_read += len(chunk)

        # Keep last max_lines lines
        lines = data.splitlines()[-max_lines:]
        text = b'\n'.join(lines).decode('utf-8', errors='replace')
        return text

    @staticmethod
    def read_server_logs(max_lines: int = 200, max_bytes: int = 1024 * 1024):
        """Read neofrp server logs.

        Returns a tuple: (log_text, source_label, error_message).
        """
        max_lines = int(max_lines)
        if max_lines < 1:
            max_lines = 1
        if max_lines > 5000:
            max_lines = 5000

        source = ServerConfigManager.get_log_source()

        if source == 'journal':
            import subprocess

            try:
                # journalctl output can be large; rely on -n for line cap.
                result = subprocess.run(
                    [
                        'journalctl',
                        '-u', 'neofrp-server',
                        '-n', str(max_lines),
                        '--no-pager',
                        '-o', 'short-iso'
                    ],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                if result.returncode != 0:
                    err = (result.stderr or result.stdout or '').strip()
                    if not err:
                        err = 'journalctl returned non-zero exit code'
                    return '', 'systemd journal', err

                text = result.stdout or ''
                if len(text.encode('utf-8', errors='ignore')) > max_bytes:
                    # Keep the tail end of the output
                    b = text.encode('utf-8', errors='replace')
                    text = b[-max_bytes:].decode('utf-8', errors='replace')
                    text = '[output truncated]\n' + text
                return text.strip('\n'), 'systemd journal', None
            except FileNotFoundError:
                return '', 'systemd journal', 'journalctl not found on this system'
            except subprocess.TimeoutExpired:
                return '', 'systemd journal', 'journalctl timed out'
            except Exception as e:
                return '', 'systemd journal', f'Failed to read journal: {e}'

        # file mode
        log_path = (ServerConfigManager.get_log_file_path() or '').strip()
        if not log_path:
            return '', 'log file', 'Log file path not configured'
        if not os.path.isabs(log_path):
            return '', 'log file', 'Log file path must be an absolute path'

        try:
            text = ServerConfigManager._tail_file(log_path, max_lines=max_lines, max_bytes=max_bytes)
            return text.strip('\n'), 'log file', None
        except Exception as e:
            return '', 'log file', str(e)

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
        """Write configuration to file atomically with secure permissions."""
        config_path = ServerConfigManager.get_config_path()
        config_dir = os.path.dirname(config_path)

        try:
            os.makedirs(config_dir, mode=0o755, exist_ok=True)

            # Write to temp file first, then rename for atomicity
            fd, tmp_path = tempfile.mkstemp(dir=config_dir, suffix='.json.tmp')
            try:
                # Set secure permissions (owner read/write only)
                os.chmod(tmp_path, 0o600)

                with os.fdopen(fd, 'w') as f:
                    json.dump(config, f, indent=4)

                # Atomically replace the old config
                os.replace(tmp_path, config_path)
                # Ensure final file has correct permissions
                os.chmod(config_path, 0o600)
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
        """Return default server configuration.

        Uses per-port token format (no global recognized_tokens).
        """
        return {
            "log": {"log_level": "info"},
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
    def sync_ports():
        """Sync all active tunnel ports to server config and trigger reload.

        Uses per-port token format where each port includes its owner's token.
        Automatically triggers SIGHUP reload if server is running.
        """
        return ServerConfigManager.sync_and_reload()

    @staticmethod
    def sync_and_reload():
        """Sync config and trigger hot reload if server is running.

        This is the preferred method for automated syncs (e.g., when users
        add/edit/delete tunnels) as it applies changes immediately.
        """
        sync_success = ServerConfigManager.sync_all()
        if not sync_success:
            return False

        # Attempt to reload - if server not running, that's OK
        reload_success = ServerConfigManager.trigger_reload()
        if reload_success:
            logger.info('Config synced and server reloaded')
        else:
            logger.debug('Config synced (server not running, reload skipped)')

        return True

    @staticmethod
    def sync_all():
        """Full sync: per-port tokens to server config.

        Uses the new per-port token format where each port is associated
        with the token(s) of users who own tunnels on that port.
        """
        config = ServerConfigManager.read_config()
        if config is None:
            logger.error('Cannot sync: failed to read server config')
            return False

        from models import Tunnel

        # Get all active tunnels with their user relationships
        active_tunnels = Tunnel.query.filter_by(is_active=True).all()

        # Build per-port token configs
        # Each tunnel's port gets its owner's token
        tcp_port_configs = []
        udp_port_configs = []

        for tunnel in active_tunnels:
            # Only include tunnels from active, verified users
            if not tunnel.user.is_active or not tunnel.user.is_verified:
                continue

            port_config = {
                "port": tunnel.server_port,
                "tokens": [tunnel.user.token]
            }

            if tunnel.protocol == 'tcp':
                tcp_port_configs.append(port_config)
            else:
                udp_port_configs.append(port_config)

        # Sort by port number for consistent output
        tcp_port_configs.sort(key=lambda x: x['port'])
        udp_port_configs.sort(key=lambda x: x['port'])

        if 'connections' not in config:
            config['connections'] = {}
        config['connections']['tcp_ports'] = tcp_port_configs
        config['connections']['udp_ports'] = udp_port_configs

        # Clear deprecated recognized_tokens if present (now per-port)
        config.pop('recognized_tokens', None)

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

    @staticmethod
    def get_server_pid():
        """Get the PID of the running neofrp-server systemd service.

        Uses systemctl to query the exact neofrp-server service status,
        avoiding confusion with other frps instances on the machine.
        Returns the PID if service is running, None otherwise.
        """
        import subprocess

        try:
            # Query systemd for the neofrp-server service
            result = subprocess.run(
                ['systemctl', 'show', 'neofrp-server',
                 '--property=MainPID', '--property=ActiveState'],
                capture_output=True,
                text=True,
                timeout=5
            )

            if result.returncode != 0:
                logger.debug('systemctl query failed, service may not exist')
                return None

            # Parse the output
            props = {}
            for line in result.stdout.strip().split('\n'):
                if '=' in line:
                    key, value = line.split('=', 1)
                    props[key] = value

            active_state = props.get('ActiveState', '')
            main_pid = props.get('MainPID', '0')

            # Service must be active and have a valid PID
            if active_state == 'active' and main_pid.isdigit() and int(main_pid) > 0:
                return int(main_pid)

            return None

        except subprocess.TimeoutExpired:
            logger.warning('systemctl query timed out')
            return None
        except FileNotFoundError:
            logger.debug('systemctl not found, not a systemd system')
            return None
        except Exception as e:
            logger.error(f'Error querying neofrp-server service: {e}')
            return None

    @staticmethod
    def trigger_reload():
        """Send SIGHUP to neofrp server to trigger config hot reload.

        Returns True if signal was sent successfully, False otherwise.
        """
        import signal

        pid = ServerConfigManager.get_server_pid()
        if pid is None:
            logger.warning('Cannot trigger reload: neofrp server process not found')
            return False

        try:
            os.kill(pid, signal.SIGHUP)
            logger.info(f'Sent SIGHUP to neofrp server (PID {pid})')
            return True
        except OSError as e:
            logger.error(f'Failed to send SIGHUP to PID {pid}: {e}')
            return False
