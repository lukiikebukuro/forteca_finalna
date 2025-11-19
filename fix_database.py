# fix_database.py
import sqlite3

DATABASE_NAME = 'dashboard.db'

conn = sqlite3.connect(DATABASE_NAME)
cursor = conn.cursor()

# Usuń starą tabelę
cursor.execute('DROP TABLE IF EXISTS visitor_sessions')
print("[FIX] Dropped old visitor_sessions table")

conn.commit()
conn.close()

print("[FIX] Database fixed! Run app.py again.")