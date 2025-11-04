import eventlet
eventlet.monkey_patch()  # MUSI BYĆ JAKO PIERWSZE

from app import app, socketio, bot, DatabaseManager
from datetime import datetime, timedelta
import sqlite3

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
