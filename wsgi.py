"""
WSGI entry point for Gunicorn/Render deployment.
All initialization happens in app.py on import.
"""
import os
import subprocess
import sys

# Database initialization (first run only)
if not os.path.exists('dashboard.db'):
    print("[WSGI] Database does not exist - creating...")
    subprocess.run([sys.executable, 'createdb.py'], check=True)
    print("[WSGI] Database created. Run 'python skrypthasla.py' to set initial passwords.")

# Import app - this triggers all initialization in app.py
from app import app, socketio, bot, DatabaseManager

print("[WSGI] Initializing bot data...")
bot.initialize_data()

print("[WSGI] Application initialized successfully")

application = app
