# create_superadmin.py
# Updated to use MongoEngine syntax.
import getpass
from werkzeug.security import generate_password_hash
from app import create_app
from app.models import User

def create_superadmin():
    """Creates the superadmin user in MongoDB."""
    app = create_app()
    with app.app_context():
        print("Creating superadmin account...")
        username = input("Enter username: ")
        email = input("Enter email: ")

        if User.objects(email=email).first():
            print("Error: A user with this email already exists.")
            return

        if User.objects(username=username).first():
            print("Error: A user with this username already exists.")
            return
            
        password = getpass.getpass("Enter password: ")
        confirm_password = getpass.getpass("Confirm password: ")

        if password != confirm_password:
            print("Passwords do not match.")
            return

        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        
        new_superadmin = User(
            username=username,
            email=email,
            password=hashed_password,
            role='superadmin'
        )
        new_superadmin.save()
        print(f"Superadmin '{username}' created successfully!")

if __name__ == '__main__':
    create_superadmin()