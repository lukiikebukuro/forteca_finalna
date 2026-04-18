"""
WebSocket (SocketIO) event handlers.
connect, disconnect, visitor_typing, client_disconnected,
request_current_stats, visitor_event, client_connected (Passive Radar)
"""
import sqlite3
import random
from datetime import datetime
from flask import request as flask_request
from flask_socketio import emit, join_room, disconnect
from flask_login import current_user

from config import app, socketio, DATABASE_NAME
from database import DatabaseManager


@socketio.on('connect')
def handle_connect():
    """Client connected to WebSocket - with authentication"""
    print('[WEBSOCKET] Client connected')

    referer = flask_request.headers.get('Referer', '')
    is_demo_page = '/demo' in referer or '/motobot-prototype' in referer or '/elektrobot-prototype' in referer

    if not current_user.is_authenticated:
        if is_demo_page:
            join_room('client_demo')
            print('[WEBSOCKET] Anonymous user joined client_demo (public demo)')
            emit('connection_confirmed', {'message': 'Connected to Demo TCD', 'room': 'client'})
        else:
            print('[WEBSOCKET] UNAUTHORIZED connection attempt - disconnecting')
            app.logger.warning(f"Unauthorized WebSocket connection attempt from {flask_request.remote_addr}")
            disconnect()
            return
    else:
        if is_demo_page:
            join_room('client_demo')
            print(f'[WEBSOCKET] User {current_user.username} joined client_demo room (demo page)')
            emit('connection_confirmed', {'message': 'Connected to Demo TCD', 'room': 'client'})
        elif current_user.role in ['admin', 'debug']:
            join_room('admin_dashboard')
            print(f'[WEBSOCKET] Admin {current_user.username} joined admin_dashboard room')
            emit('connection_confirmed', {'message': 'Connected to Admin Dashboard', 'room': 'admin'})

            # Passive Radar: send recent visits from DB
            try:
                conn = sqlite3.connect(DATABASE_NAME)
                cursor = conn.cursor()
                cursor.execute('''
                    SELECT session_id, radar_company, city, country,
                           radar_status, entry_time, referrer
                    FROM visitor_sessions
                    WHERE radar_company IS NOT NULL
                    ORDER BY entry_time DESC LIMIT 5
                ''')
                recent_visits = []
                for row in cursor.fetchall():
                    sess_id, company, city, country, status, entry_time, referrer = row
                    try:
                        dt = datetime.strptime(entry_time, '%Y-%m-%d %H:%M:%S')
                        time_str = dt.strftime('%H:%M')
                    except:
                        time_str = entry_time[:5] if entry_time else '00:00'
                    recent_visits.append({
                        'session_id': sess_id, 'company': company,
                        'city': city, 'country': country,
                        'status': status or 'Przegląda', 'timestamp': time_str,
                        'referrer': referrer or 'direct', 'source': 'moto', 'anonymous': False
                    })
                conn.close()
                for visit in reversed(recent_visits):
                    emit('new_visitor', visit)
                print(f"PASSIVE RADAR: Sent {len(recent_visits)} visits from DB to {current_user.username}")
            except Exception as db_error:
                print(f"PASSIVE RADAR: Error loading visits from DB: {db_error}")
        else:
            join_room('client_demo')
            print(f'[WEBSOCKET] Client {current_user.username} joined client_demo room')
            emit('connection_confirmed', {'message': 'Connected to Demo TCD', 'room': 'client'})


@socketio.on('disconnect')
def handle_disconnect():
    print('[WEBSOCKET] Client disconnected')


@socketio.on('visitor_typing')
def handle_visitor_typing(data):
    """Passive Radar: Update status to 'Pisze' when client types"""
    try:
        session_id = data.get('session_id')
        if not session_id:
            return

        try:
            conn = sqlite3.connect(DATABASE_NAME)
            cursor = conn.cursor()
            cursor.execute('''
                UPDATE visitor_sessions SET radar_status = 'Pisze' WHERE session_id = ?
            ''', (session_id,))
            conn.commit()
            conn.close()
        except Exception as db_error:
            print(f"PASSIVE RADAR DB ERROR: {db_error}")

        typing_data = {
            'session_id': session_id,
            'status': 'Pisze',
            'timestamp': datetime.now().strftime('%H:%M')
        }
        emit('visitor_status_changed', typing_data, broadcast=True)
    except Exception as e:
        print(f"PASSIVE RADAR ERROR: {e}")


@socketio.on('client_disconnected')
def handle_client_disconnected(data):
    """Passive Radar: Handle client leaving page"""
    try:
        session_id = data.get('session_id')
        session_duration = data.get('session_duration', 0)
        message_count = data.get('message_count', 0)

        if not session_id:
            return

        print(f"PASSIVE RADAR: Client disconnected - Session: {session_id}, Duration: {session_duration}ms")

        try:
            conn = sqlite3.connect(DATABASE_NAME)
            cursor = conn.cursor()
            cursor.execute('''
                UPDATE visitor_sessions
                SET radar_status = 'Opuscil', exit_time = CURRENT_TIMESTAMP,
                    session_duration = ?, total_messages = ?, is_active = 0
                WHERE session_id = ?
            ''', (session_duration // 1000, message_count, session_id))
            conn.commit()
            conn.close()
        except Exception as db_error:
            print(f"PASSIVE RADAR DB ERROR: {db_error}")
            import traceback
            traceback.print_exc()

        disconnect_data = {
            'session_id': session_id,
            'status': 'Opuscil',
            'timestamp': datetime.now().strftime('%H:%M')
        }
        emit('visitor_disconnected', disconnect_data, broadcast=True)
    except Exception as e:
        print(f"PASSIVE RADAR ERROR: {e}")
        import traceback
        traceback.print_exc()


@socketio.on('request_current_stats')
def handle_stats_request():
    """Client requests current statistics"""
    try:
        stats = DatabaseManager.get_today_statistics()
        top_missing = DatabaseManager.get_top_missing_products(5)
        emit('stats_update', {
            'today_statistics': stats,
            'top_missing_products': top_missing
        })
    except Exception as e:
        print(f"[WEBSOCKET ERROR] {e}")
        emit('error', {'message': str(e)})


@socketio.on('visitor_event')
def handle_visitor_event_websocket(data):
    """DISABLED - duplicates events from /api/analyze_query"""
    pass


@socketio.on('client_connected')
def handle_client_connected(data):
    """Passive Radar: Handle new client connection, detect company"""
    try:
        session_id = data.get('session_id')
        city = data.get('city', 'Unknown')
        country = data.get('country', 'Unknown')
        organization = data.get('organization', 'Unknown')
        referrer = data.get('referrer', 'direct')
        user_agent = data.get('user_agent', 'Unknown')
        anonymous = data.get('anonymous', False)
        source = data.get('source', 'moto')
        timestamp = data.get('timestamp')

        print(f"PASSIVE RADAR: Client connected - Session: {session_id}")

        # Company detection (mock pool for demo)
        company_pool = [
            'PKN Orlen', 'Comarch', 'Budimex', 'PGE', 'Allegro',
            'CD Projekt', 'LPP', 'Dino Polska', 'Bank Pekao', 'mBank'
        ]
        if organization and organization != 'Unknown':
            detected_company = organization
        else:
            detected_company = random.choice(company_pool)

        # Format timestamp
        try:
            dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
            time_str = dt.strftime('%H:%M')
        except:
            time_str = datetime.now().strftime('%H:%M')

        # Save to DB
        try:
            conn = sqlite3.connect(DATABASE_NAME)
            cursor = conn.cursor()
            cursor.execute('SELECT id FROM visitor_sessions WHERE session_id = ?', (session_id,))
            existing = cursor.fetchone()

            if existing:
                cursor.execute('''
                    UPDATE visitor_sessions
                    SET radar_status = ?, radar_company = ?, last_activity = CURRENT_TIMESTAMP
                    WHERE session_id = ?
                ''', ('Przegląda', detected_company, session_id))
            else:
                cursor.execute('''
                    INSERT INTO visitor_sessions (
                        session_id, organization, city, country,
                        referrer, user_agent, radar_status, radar_company,
                        entry_time, last_activity, is_active
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, 1)
                ''', (session_id, organization, city, country, referrer, user_agent,
                      'Przegląda', detected_company))

            conn.commit()
            conn.close()
            print(f"PASSIVE RADAR: Saved - Session: {session_id}, Company: {detected_company}")
        except Exception as db_error:
            print(f"PASSIVE RADAR DB ERROR: {db_error}")
            import traceback
            traceback.print_exc()

        # Broadcast to dashboards
        visitor_data = {
            'session_id': session_id, 'timestamp': time_str,
            'company': detected_company, 'city': city, 'country': country,
            'status': 'Przegląda', 'referrer': referrer,
            'source': source, 'anonymous': anonymous
        }
        emit('new_visitor', visitor_data, broadcast=True)
        print(f"PASSIVE RADAR: Broadcast 'new_visitor' - {detected_company}")

    except Exception as e:
        print(f"PASSIVE RADAR ERROR: {e}")
        import traceback
        traceback.print_exc()
