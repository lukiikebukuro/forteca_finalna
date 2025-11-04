import eventlet
eventlet.monkey_patch()  # MUSI BYĆ JAKO PIERWSZE

# DODAJ INICJALIZACJĘ BAZY PRZED IMPORTEM APP
import os
import sqlite3
import subprocess
import sys

if not os.path.exists('dashboard.db'):
    print("[WSGI] Baza nie istnieje - tworzę...")
    subprocess.run([sys.executable, 'createdb.py'])
    subprocess.run([sys.executable, 'skrypthasla.py'])
    print("[WSGI] Baza utworzona!")

# TERAZ IMPORTUJ APP
from app import app, socketio, bot, DatabaseManager
from datetime import datetime, timedelta

# Initialize on module load
print("[WSGI] Initializing application...")

bot.initialize_data()
DatabaseManager.initialize_database()

try:
    conn = sqlite3.connect('dashboard.db')
    cursor = conn.cursor()
    cutoff_date = (datetime.now() - timedelta(days=30)).strftime('%Y-%m-%d')
    cursor.execute('DELETE FROM events WHERE date(timestamp) < ?', (cutoff_date,))
    conn.commit()
    conn.close()
    print("[WSGI] Database cleaned")
except Exception as e:
    print(f"[WSGI] Database error: {e}")

print("[WSGI] Application initialized")

application = app