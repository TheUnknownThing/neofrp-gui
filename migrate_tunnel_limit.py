#!/usr/bin/env python3
"""
Migration script to add tunnel_limit field to existing users.
Run this script after updating the models to add the tunnel_limit column.
"""

import sys
import os

# Add the project root to the Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from database import db
from models import User
from app import app

def migrate_tunnel_limit():
    """Add tunnel_limit to existing users who don't have it set."""
    with app.app_context():
        try:
            # Check if the column exists by trying to query it
            users_without_limit = User.query.filter(User.tunnel_limit.is_(None)).all()
            
            # Set default tunnel limit for users who don't have one
            for user in users_without_limit:
                user.tunnel_limit = 10  # Default limit
                print(f"Updated tunnel limit for user {user.username}")
            
            # Also ensure all users have a tunnel_limit value
            all_users = User.query.all()
            for user in all_users:
                if user.tunnel_limit is None:
                    user.tunnel_limit = 10
                    print(f"Set tunnel limit for user {user.username}")
            
            db.session.commit()
            print("Migration completed successfully!")
            
        except Exception as e:
            print(f"Migration failed: {e}")
            db.session.rollback()
            # If the column doesn't exist yet, the table needs to be recreated
            print("You may need to drop and recreate the database tables.")
            print("Or add the column manually: ALTER TABLE users ADD COLUMN tunnel_limit INTEGER DEFAULT 10;")

if __name__ == "__main__":
    migrate_tunnel_limit()