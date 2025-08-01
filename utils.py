"""Utility functions for the Neofrp admin panel."""

import os
import secrets
from functools import wraps
from flask import jsonify


def generate_secure_token(length=32):
    """Generate a secure random token."""
    return secrets.token_urlsafe(length)


def api_response(success=True, message="", data=None, status_code=200):
    """Standardized API response format."""
    response = {
        'success': success,
        'message': message
    }
    if data is not None:
        response['data'] = data
    
    return jsonify(response), status_code


def get_neofrp_executable(executable_name):
    """Get the path to neofrp executable."""
    # Look for the executable in common locations
    search_paths = [
        os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'bin'),
        '/usr/local/bin',
        '/usr/bin',
        os.path.expanduser('~/bin')
    ]
    
    for path in search_paths:
        full_path = os.path.join(path, executable_name)
        if os.path.isfile(full_path) and os.access(full_path, os.X_OK):
            return full_path
    
    # If not found, return the name and hope it's in PATH
    return executable_name


def format_port_range(start, end):
    """Format a port range for display."""
    if start == end:
        return str(start)
    return f"{start}-{end}"


def parse_port_range(port_range):
    """Parse a port range string into a list of ports."""
    ports = []
    parts = port_range.split(',')
    
    for part in parts:
        part = part.strip()
        if '-' in part:
            start, end = part.split('-')
            ports.extend(range(int(start), int(end) + 1))
        else:
            ports.append(int(part))
    
    return ports