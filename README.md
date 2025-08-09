Employee Work Diary - Flask & MongoDB
This is a complete web application for tracking employee work diaries, built with Python, Flask, and MongoDB, and secured with JWT authentication.

Features
User Roles: Three user roles are supported:

Employee: Can create, view, edit, and delete their own diary entries.

Admin: Can view all users and their diary entries. Cannot edit or delete other users or their content.

Super Admin: Has full control over the application, including assigning roles, resetting passwords, and deleting users.

JWT Authentication: Secure, stateless authentication using JSON Web Tokens stored in HttpOnly cookies.

Database: Uses MongoDB for flexible and scalable data storage.

Professional UI: A clean, responsive interface built with Tailwind CSS.

Project Structure
/employee-diary-app
|-- app/
|   |-- __init__.py
|   |-- auth.py
|   |-- main.py
|   |-- models.py
|   |-- forms.py
|   |-- static/
|   |   |-- css/
|   |   |   `-- style.css
|   |   `-- favicon.ico
|   `-- templates/
|       |-- admin.html
|       |-- base.html
|       |-- index.html
|       |-- login.html
|       |-- profile.html
|       |-- register.html
|       |-- edit_entry.html
|       |-- edit_user.html
|       `-- reset_password.html
|-- create_superadmin.py
|-- config.py
|-- run.py
`-- requirements.txt

Setup and Installation
1. Prerequisites
Python 3.6+

MongoDB installed and running locally, or a MongoDB Atlas account.

2. Clone the Repository
git clone <repository_url>
cd employee-diary-app

3. Create a Virtual Environment
python -m venv venv
source venv/bin/activate  # On Windows, use `venv\Scripts\activate`

4. Install Dependencies
pip install -r requirements.txt

5. Configure Environment Variables
Create a .env file in the root of the project and add the following:

# Generate a strong, random secret key.
SECRET_KEY='your-super-strong-random-secret-key'

# Your MongoDB connection string (local or from Atlas)
MONGODB_URI='mongodb://localhost:27017/employee_diary'

6. Create the Super Admin User
Run the create_superadmin.py script from your terminal:

python create_superadmin.py

7. Run the Application
python run.py

The application will be running at http://127.0.0.1:5000.
