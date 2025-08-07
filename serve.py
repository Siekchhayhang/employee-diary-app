# serve.py
from app import create_app
from waitress import serve

# Create the app for a production environment
app = create_app('prod')

if __name__ == '__main__':
    serve(app, host='0.0.0.0', port=8000)