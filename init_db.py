#!/usr/bin/env python3
"""Initialize the database with tables and optional test data."""

import os
import sys
import secrets
from app import create_app
from database import db
from models import User, Tunnel, Configuration

def init_database():
    """Initialize the database."""
    # Respect FLASK_ENV environment variable
    env = os.environ.get('FLASK_ENV', 'development')
    app = create_app(env)
    
    with app.app_context():
        # Create all tables
        print("Creating database tables...")
        db.create_all()
        print("Database tables created successfully!")
        
        # Check if there are any users
        user_count = User.query.count()
        if user_count == 0:
            print("\nNo users found. Creating a default root user...")

            # Get or generate secure password
            admin_password = os.environ.get('ADMIN_DEFAULT_PASSWORD')
            if not admin_password:
                # Generate a secure random password
                admin_password = secrets.token_urlsafe(16)
                print("\n" + "="*70)
                print("  GENERATED ROOT ADMIN PASSWORD")
                print("="*70)
                print(f"\n  Username: admin")
                print(f"  Password: {admin_password}")
                print(f"\n  ⚠️  SAVE THIS PASSWORD - IT WILL NOT BE SHOWN AGAIN!")
                print("="*70 + "\n")

            # Create default root user
            admin = User(
                username='admin',
                email='admin@example.com',
                is_active=True,
                is_verified=True
            )
            admin.set_password(admin_password)
            admin.set_role('root_user')  # Set as root user
            admin.generate_token()

            db.session.add(admin)
            db.session.commit()

            if os.environ.get('ADMIN_DEFAULT_PASSWORD'):
                print("\nDefault root user created with password from ADMIN_DEFAULT_PASSWORD")
            else:
                print("\nDefault root user created with generated password (shown above)")
            print(f"  Email: admin@example.com")
            print(f"  Role: Root Administrator")
            print(f"  Token: {admin.token}")
            print("\n⚠️  IMPORTANT: Change the default password after first login!")
        else:
            print(f"\nDatabase already contains {user_count} user(s).")
        
        print("\nDatabase initialization complete!")

if __name__ == '__main__':
    init_database()