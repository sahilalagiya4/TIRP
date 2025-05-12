"""
Database initialization script
This script creates the tables and adds a default admin user.
"""

import os
import sys
from getpass import getpass
from app import create_app
from database import db, User


def init_db():
    """Initialize the database and create admin user"""
    print("Initializing database...")

    # Create app context
    app = create_app()

    with app.app_context():
        # Create all tables
        db.create_all()
        print("Tables created successfully.")

        # Check if admin user already exists
        admin = User.query.filter_by(is_admin=True).first()

        if admin:
            print(f"Admin user already exists: {admin.username}")
            create_new = input("Create another admin user? (y/n): ").lower() == 'y'
        else:
            create_new = True

        if create_new:
            # Get admin details
            username = input("Enter admin username: ")
            email = input("Enter admin email: ")
            password = input("Enter admin password: ")
            confirm_password = input("Confirm admin password: ")

            # Validate input
            if not username or not email or not password:
                print("Error: All fields are required.")
                return False

            if password != confirm_password:
                print("Error: Passwords do not match.")
                return False

            # Check if username or email already exists
            if User.query.filter_by(username=username).first():
                print(f"Error: Username '{username}' already exists.")
                return False

            if User.query.filter_by(email=email).first():
                print(f"Error: Email '{email}' already exists.")
                return False

            # Create admin user
            admin = User(username=username, email=email, is_admin=True)
            admin.set_password(password)

            db.session.add(admin)
            db.session.commit()

            print(f"Admin user '{username}' created successfully.")

    return True


if __name__ == '__main__':
    if init_db():
        print("Database initialization complete.")
    else:
        print("Database initialization failed.")
        sys.exit(1)