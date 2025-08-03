#!/usr/bin/env python3
"""Initialize the database with tables and optional test data."""

import os
import sys
from app import create_app
from database import db
from models import User, Tunnel, Configuration

def init_database():
    """Initialize the database."""
    app = create_app('development')
    
    with app.app_context():
        # Create all tables
        print("Creating database tables...")
        db.create_all()
        print("Database tables created successfully!")
        
        # Check if there are any users
        user_count = User.query.count()
        if user_count == 0:
            print("\nNo users found. Creating a default root user...")
            
            # Create default root user
            admin = User(
                username='admin',
                email='admin@example.com',
                is_active=True,
                is_verified=True
            )
            admin.set_password('admin123')  # Change this!
            admin.set_role('root_user')  # Set as root user
            admin.generate_token()
            
            db.session.add(admin)
            db.session.commit()
            
            print("\nDefault root user created:")
            print(f"  Username: admin")
            print(f"  Password: admin123")
            print(f"  Email: admin@example.com")
            print(f"  Role: Root Administrator")
            print(f"  Token: {admin.token}")
            print("\n⚠️  IMPORTANT: Change the default password immediately!")
        else:
            print(f"\nDatabase already contains {user_count} user(s).")
        
        print("\nDatabase initialization complete!")

if __name__ == '__main__':
    init_database()