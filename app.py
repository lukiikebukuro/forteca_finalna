"""
LDI - Lost Demand Intelligence System
Slim entry point. All logic lives in modules.
"""
import os
import sqlite3
from datetime import datetime, timedelta

# Core setup (creates app, socketio, limiter, bots)
from config import app, socketio, DATABASE_NAME, DEBUG
from config import bot, moto_bot, elektro_bot  # noqa: F401 - used by wsgi.py

# Database managers (imported so wsgi.py can access them)
from database import (  # noqa: F401
    DatabaseManager, AdminDashboardStateManager, QueryIntentManager,
    ensure_visitor_tables_exist, init_persistent_storage_tables,
    init_database
)
from privacy import cleanup_old_sessions
from auth_manager import ensure_tables_exist, setup_default_users

# Register all route blueprints
from routes import register_blueprints
register_blueprints(app)

# Register WebSocket handlers (imported for side effects)
import websocket_handlers  # noqa: F401

# ================================================================
# STARTUP INITIALIZATION (runs on import, including Gunicorn/Render)
# ================================================================

with app.app_context():
    # Initialize dashboard database
    DatabaseManager.initialize_database()

    # Initialize P3 QueryIntent table
    QueryIntentManager.init_table()

    # Initialize visitor tracking tables (RODO)
    ensure_visitor_tables_exist()

    # RODO: Cleanup old data (30 days retention)
    try:
        conn = sqlite3.connect(DATABASE_NAME)
        cursor = conn.cursor()
        cutoff_date = (datetime.now() - timedelta(days=30)).strftime('%Y-%m-%d')
        cursor.execute('DELETE FROM events WHERE date(timestamp) < ?', (cutoff_date,))
        deleted_events = cursor.rowcount
        conn.commit()
        conn.close()
        if deleted_events > 0:
            print(f"[RODO CLEANUP] Cleared {deleted_events} old events")
        cleanup_old_sessions()
    except Exception as e:
        print(f"[DATABASE] Error clearing old data: {e}")

    print("=" * 70)
    print("LDI - Lost Demand Intelligence System v5.1")
    print("=" * 70)

    ensure_tables_exist()

    print("[STARTUP] DB initialized")
    init_database()

# ================================================================
# LOCAL DEV SERVER
# ================================================================

if __name__ == '__main__':
    print("=" * 70)
    print("LDI - LOCAL DEV MODE")
    print("=" * 70)

    try:
        QueryIntentManager.init_table()
        print("[P3] QueryIntent table initialized")
    except Exception as e:
        print(f"[P3] Table init failed: {e}")

    socketio.run(app, debug=DEBUG, host='0.0.0.0', port=int(os.getenv('PORT', 5000)))
