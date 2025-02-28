from app import app, db, User

def create_admin():
    """Create admin user with default credentials."""
    with app.app_context():
        # Check if admin exists
        admin = User.query.filter_by(username='admin').first()
        if admin:
            # Update admin password
            admin.set_password('admin123')
            db.session.commit()
            print("Admin password reset to: admin123")
        else:
            # Create new admin
            admin = User(
                username='admin',
                email='admin@example.com',
                is_admin=True,
                credits=999999
            )
            admin.set_password('admin123')
            db.session.add(admin)
            db.session.commit()
            print("Admin user created with:")
            print("Username: admin")
            print("Password: admin123")

if __name__ == '__main__':
    create_admin()
