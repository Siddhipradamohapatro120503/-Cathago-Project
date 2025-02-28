from app import app, db, User, Document, CreditRequest, UserSession
import os

def init_db():
    """Initialize the database."""
    with app.app_context():
        # Create all tables
        db.create_all()
        
        # Check if admin user exists
        admin = User.query.filter_by(username='admin').first()
        if not admin:
            # Create admin user
            admin = User(
                username='admin',
                email='admin@example.com',
                is_admin=True,
                credits=999999  # Unlimited credits for admin
            )
            admin.set_password('admin123')  # Default password, should be changed
            db.session.add(admin)
            db.session.commit()
            print("Created admin user")
        
        print("Database initialized successfully")

if __name__ == '__main__':
    # Delete existing database
    if os.path.exists('instance/database.db'):
        os.remove('instance/database.db')
        print("Removed existing database")
    
    # Initialize new database
    init_db()
