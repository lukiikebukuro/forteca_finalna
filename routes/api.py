"""
API Routes Blueprint
Headless API v1, Dashboard data API, Admin API, Debug/P3 API, Visitor tracking.
"""
from flask import Blueprint, request, jsonify, Response
from flask_login import login_required, current_user
from auth_manager import require_admin_access, require_debug_access, require_client_access
from config import (
    app, limiter, socketio, moto_bot, elektro_bot,
    ELEKTRO_BOT_AVAILABLE, MOTO_DECISION_MAPPING, ELEKTRO_DECISION_MAPPING,
    DATABASE_NAME, MotoBot, api_sessions, reward_calc, ldi_reward_calc, UserSession
)
from database import (
    DatabaseManager, AdminDashboardStateManager, QueryIntentManager,
    get_all_companies, get_hot_leads, get_log_history, get_client_info,
    ensure_visitor_tables_exist, init_persistent_storage_tables
)
from privacy import scrub_pii, hash_ip_address, mask_ip_address
from utils import calculate_lost_value_internal, log_firehose
from dateutil import parser

import sqlite3
import json
import time
import uuid
from datetime import datetime, timedelta


api_bp = Blueprint('api', __name__)


# ========================================
# HEADLESS API v1 (LDI Pixel / Widget)
# ========================================

@api_bp.route('/api/v1/init', methods=['POST'])
@limiter.limit("60/minute")
def api_init():
    """
    Inicjalizuje sesje dla zewnetrznego widgetu (LDI Pixel).
    """
    data = request.get_json() or {}
    api_key = data.get('api_key')

    # Generate session ID
    session_id = str(uuid.uuid4())

    # Store session state
    api_sessions[session_id] = {
        'start_time': time.time(),
        'messages': [],
        'cart': [],
        'cart_value': 0.0,
        'events': [],
        'store_id': api_key or 'demo_store',
        'bot_instance': MotoBot()
    }

    # Initial greeting
    greeting = api_sessions[session_id]['bot_instance'].get_initial_greeting()

    return jsonify({
        'session_id': session_id,
        'greeting': greeting,
        'status': 'active'
    })


@api_bp.route('/api/v1/chat', methods=['POST'])
@limiter.limit("60/minute")
def api_chat():
    """
    Obsluguje wiadomosci czatu z zewnatrz.
    Zwraca odpowiedz bota + analize intencji.
    """
    data = request.get_json()
    session_id = data.get('session_id')
    user_message = data.get('message')

    if not session_id or session_id not in api_sessions:
        return jsonify({'error': 'Invalid session'}), 401

    sess = api_sessions[session_id]
    bot = sess['bot_instance']

    # 1. Process message
    response_data = bot.handle_message(user_message)
    bot_reply = response_data['text_message']

    # 2. Log interaction
    sess['messages'].append({'role': 'user', 'content': user_message})
    sess['messages'].append({'role': 'assistant', 'content': bot_reply})

    # 3. Check for "Vogal Shift" or specific signals in response

    return jsonify({
        'reply': bot_reply,
        'suggestions': response_data.get('buttons', [])
    })


@api_bp.route('/api/v1/event', methods=['POST'])
@limiter.limit("100/minute")
def api_event():
    """
    Zbiera sygnaly behawioralne (Pixel).
    Tu obliczamy REWARD SCORE w czasie rzeczywistym.
    """
    data = request.get_json()
    session_id = data.get('session_id')
    event_type = data.get('event_type')
    payload = data.get('payload', {})

    if not session_id or session_id not in api_sessions:
        return jsonify({'error': 'Invalid session'}), 401

    sess = api_sessions[session_id]

    # Update state
    if event_type == 'cart_add':
        sess['cart_value'] += float(payload.get('value', 0))
    elif event_type == 'purchase':
        sess['final_action'] = 'purchase'

    sess['events'].append({'type': event_type, 'timestamp': time.time(), 'data': payload})

    # CALCULATE REWARD SCORE
    duration = time.time() - sess['start_time']
    message_count = len(sess['messages'])

    # Map event to final_action for calculator
    final_action = 'none'
    if event_type == 'purchase':
        final_action = 'purchase'
    elif event_type == 'cart_add':
        final_action = 'cart_add'
    elif event_type == 'rage_quit':
        final_action = 'none'

    # Calculate Vogal Shift (Intent Pivot)
    vogal_shift = reward_calc.analyze_vogal_shift(sess.get('messages', []))

    user_session_obj = UserSession(
        session_id=session_id,
        duration_seconds=duration,
        total_messages=message_count,
        final_action=final_action,
        cart_value=sess['cart_value'],
        intent_shift_detected=vogal_shift
    )

    current_score = reward_calc.calculate_score(user_session_obj)

    # Log to "The Firehose" (JSONL)
    log_firehose(session_id, event_type, current_score, sess)

    return jsonify({
        'status': 'logged',
        'current_reward_score': current_score
    })


# ========================================
# DASHBOARD DATA API
# ========================================

@api_bp.route('/api/initial_data')
def get_initial_data():
    """API endpoint zwracajacy dane inicjalne dla dashboardu"""
    try:
        recent_events = DatabaseManager.get_recent_events(10)
        today_stats = DatabaseManager.get_today_statistics()
        top_missing = DatabaseManager.get_top_missing_products(5)

        return jsonify({
            'status': 'success',
            'data': {
                'recent_events': recent_events,
                'today_statistics': today_stats,
                'top_missing_products': top_missing
            }
        })
    except Exception as e:
        print(f"[API ERROR] {e}")
        return jsonify({'status': 'error', 'message': str(e)}), 500


@api_bp.route('/api/reset_demo', methods=['POST'])
def reset_demo():
    """Resetuje demo - czysci baze i restartuje symulacje"""
    try:
        conn = sqlite3.connect(DATABASE_NAME)
        cursor = conn.cursor()
        cursor.execute('DELETE FROM events')
        conn.commit()
        conn.close()

        return jsonify({'status': 'success', 'message': 'Demo reset successfully'})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500


@api_bp.route('/api/receive_event', methods=['POST'])
def receive_real_event():
    """Odbiera prawdziwe eventy z bota (dla integracji)"""
    try:
        data = request.get_json()

        # Dodaj do bazy
        event_id = DatabaseManager.add_event(
            data['query_text'],
            data['decision'],
            data['details'],
            data.get('category', 'unknown'),
            'standard',
            data.get('potential_value', 0),
            f"Prawdziwe zapytanie uzytkownika"
        )

        # Wyslij przez WebSocket
        event_data = {
            'id': event_id,
            'timestamp': datetime.now().strftime('%H:%M:%S'),
            'query_text': data['query_text'],
            'decision': data['decision'],
            'details': data['details'],
            'category': data.get('category', 'unknown'),
            'potential_value': data.get('potential_value', 0),
            'explanation': 'Prawdziwe zapytanie uzytkownika'
        }

        # WYSLIJ TYLKO DO DEMO TCD (nie do admin dashboard)
        server_ts_ms = int(time.time() * 1000)
        event_data['server_sent_at'] = server_ts_ms
        app.logger.info(f"[WS EMIT][RECEIVE_EVENT] new_event id={event_id} sent_at={server_ts_ms}")
        socketio.emit('new_event', event_data, room='client_demo')

        return jsonify({'status': 'success'})

    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500


# ========================================
# CLIENT API (Poziom 1)
# ========================================

@api_bp.route('/api/client/<int:client_id>/stats')
@require_client_access
def get_client_stats(client_id):
    """API - POZIOM 1: Statystyki tylko dla okreslonego klienta"""

    # Sprawdz czy user ma dostep do tego klienta
    if not current_user.has_access_to_client(client_id):
        return jsonify({'error': 'Brak dostepu'}), 403

    try:
        conn = sqlite3.connect(DATABASE_NAME)
        cursor = conn.cursor()

        # Pobierz statystyki tylko dla tego klienta
        today = datetime.now().strftime('%Y-%m-%d')

        # Podstawowe liczniki (real-time)
        cursor.execute('''
            SELECT
                COUNT(*) as total_queries,
                COUNT(CASE WHEN decision = 'UTRACONE OKAZJE' THEN 1 END) as lost_opportunities,
                COALESCE(SUM(CASE WHEN decision = 'UTRACONE OKAZJE' THEN potential_value ELSE 0 END), 0) as lost_value
            FROM business_events
            WHERE client_id = ? AND date(timestamp) = ?
        ''', (client_id, today))

        stats = cursor.fetchone()
        conn.close()

        return jsonify({
            'status': 'success',
            'client_id': client_id,
            'today_stats': {
                'total_queries': stats[0] if stats else 0,
                'lost_opportunities': stats[1] if stats else 0,
                'lost_value': int(stats[2]) if stats else 0
            },
            'last_update': datetime.now().isoformat()
        })

    except Exception as e:
        print(f"[API ERROR] Client stats failed: {e}")
        return jsonify({'status': 'error', 'message': str(e)}), 500


# ========================================
# ADMIN API (Poziom 2)
# ========================================

@api_bp.route('/api/admin/global-stats')
@require_admin_access
def get_global_stats():
    """API - POZIOM 2: Statystyki zagregowane ze wszystkich klientow"""

    try:
        conn = sqlite3.connect(DATABASE_NAME)
        cursor = conn.cursor()

        today = datetime.now().strftime('%Y-%m-%d')

        # Globalne statystyki (anonimowe)
        cursor.execute('''
            SELECT
                COUNT(*) as total_queries,
                COUNT(DISTINCT client_id) as active_clients,
                COUNT(CASE WHEN decision = 'UTRACONE OKAZJE' THEN 1 END) as total_lost_opportunities,
                COALESCE(SUM(CASE WHEN decision = 'UTRACONE OKAZJE' THEN potential_value ELSE 0 END), 0) as total_lost_value
            FROM business_events
            WHERE date(timestamp) = ?
        ''', (today,))

        global_stats = cursor.fetchone()

        # Top kategorie utraconych okazji
        cursor.execute('''
            SELECT category, COUNT(*) as frequency, SUM(potential_value) as total_value
            FROM business_events
            WHERE decision = 'UTRACONE OKAZJE'
            AND date(timestamp) >= date('now', '-7 days')
            GROUP BY category
            ORDER BY frequency DESC
            LIMIT 10
        ''')

        top_categories = cursor.fetchall()
        conn.close()

        return jsonify({
            'status': 'success',
            'global_stats': {
                'total_queries': global_stats[0] if global_stats else 0,
                'active_clients': global_stats[1] if global_stats else 0,
                'total_lost_opportunities': global_stats[2] if global_stats else 0,
                'total_lost_value': int(global_stats[3]) if global_stats else 0
            },
            'top_lost_categories': [
                {
                    'category': row[0],
                    'frequency': row[1],
                    'total_value': int(row[2]) if row[2] else 0
                }
                for row in top_categories
            ],
            'last_update': datetime.now().isoformat()
        })

    except Exception as e:
        print(f"[API ERROR] Global stats failed: {e}")
        return jsonify({'status': 'error', 'message': str(e)}), 500


# ========================================
# DEBUG API (Poziom 3)
# ========================================

@api_bp.route('/api/debug/raw-logs')
@require_debug_access
def get_raw_logs():
    """API - POZIOM 3: Surowe logi + telemetria"""

    limit = request.args.get('limit', 100, type=int)
    offset = request.args.get('offset', 0, type=int)

    try:
        conn = sqlite3.connect(DATABASE_NAME)
        cursor = conn.cursor()

        # Surowe logi wszystkich eventow
        cursor.execute('''
            SELECT
                be.id, be.timestamp, be.client_id, be.query_text,
                be.decision, be.details, be.potential_value, be.explanation,
                c.company_name
            FROM business_events be
            LEFT JOIN clients c ON be.client_id = c.id
            ORDER BY be.timestamp DESC
            LIMIT ? OFFSET ?
        ''', (limit, offset))

        raw_logs = cursor.fetchall()

        # Statystyki systemu
        cursor.execute('SELECT COUNT(*) FROM business_events')
        total_events = cursor.fetchone()[0]

        cursor.execute('SELECT COUNT(*) FROM clients WHERE is_active = TRUE')
        total_clients = cursor.fetchone()[0]

        conn.close()

        return jsonify({
            'status': 'success',
            'raw_logs': [
                {
                    'id': row[0],
                    'timestamp': row[1],
                    'client_id': row[2],
                    'query_text': row[3],
                    'decision': row[4],
                    'details': row[5],
                    'potential_value': row[6],
                    'explanation': row[7],
                    'company_name': row[8]
                }
                for row in raw_logs
            ],
            'pagination': {
                'limit': limit,
                'offset': offset,
                'total_events': total_events
            },
            'system_stats': {
                'total_events': total_events,
                'total_clients': total_clients
            },
            'last_update': datetime.now().isoformat()
        })

    except Exception as e:
        print(f"[API ERROR] Raw logs failed: {e}")
        return jsonify({'status': 'error', 'message': str(e)}), 500


# ========================================
# ADMIN DASHBOARD STATE API
# ========================================

@api_bp.route('/api/admin/save-state', methods=['POST'])
@require_admin_access
def save_admin_state():
    """
    Zapisuje stan admin dashboardu do bazy danych.

    Body:
    {
        "state_key": "hot_leads" | "companies" | "log_history",
        "data": <any JSON serializable data>
    }
    """
    try:
        payload = request.json
        state_key = payload.get('state_key')
        data = payload.get('data')

        if not state_key or data is None:
            return jsonify({
                'status': 'error',
                'message': 'Missing state_key or data'
            }), 400

        # Validacja state_key
        valid_keys = ['hot_leads', 'companies', 'log_history']
        if state_key not in valid_keys:
            return jsonify({
                'status': 'error',
                'message': f'Invalid state_key. Must be one of: {valid_keys}'
            }), 400

        # Zapisz do bazy
        AdminDashboardStateManager.save_state(state_key, data)

        return jsonify({
            'status': 'success',
            'message': f'Saved {state_key}',
            'data_size': len(json.dumps(data))
        })

    except Exception as e:
        app.logger.error(f"Error saving admin state: {e}")
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500


@api_bp.route('/api/admin/load-state/<state_key>')
@require_admin_access
def load_admin_state(state_key):
    """
    Laduje stan admin dashboardu z bazy danych.

    Params:
        state_key: "hot_leads" | "companies" | "log_history"
    """
    try:
        # Validacja state_key
        valid_keys = ['hot_leads', 'companies', 'log_history']
        if state_key not in valid_keys:
            return jsonify({
                'status': 'error',
                'message': f'Invalid state_key. Must be one of: {valid_keys}'
            }), 400

        # Pobierz z bazy
        data = AdminDashboardStateManager.get_state(state_key)

        if data is None:
            # Brak danych - zwroc pusta strukture
            default_data = {
                'hot_leads': [],
                'companies': [],
                'log_history': []
            }

            return jsonify({
                'status': 'success',
                'data': default_data.get(state_key, []),
                'message': 'No saved data, returning empty'
            })

        return jsonify({
            'status': 'success',
            'data': data
        })

    except Exception as e:
        app.logger.error(f"Error loading admin state: {e}")
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500


# ========================================
# ADMIN VISITOR STATS (Complex)
# ========================================

@api_bp.route('/api/admin/visitor-stats')
@require_admin_access
def get_visitor_stats():
    """
    Zwraca statystyki visitor tracking dla admin dashboardu.
    7 sekcji: active users, sessions today, avg duration, conversion rate,
    companies list, active sessions, classification breakdown.
    """
    try:
        conn = sqlite3.connect(DATABASE_NAME)
        cursor = conn.cursor()

        now = datetime.now()

        # === 1. AKTYWNI UZYTKOWNICY (ostatnie 15 min) ===
        fifteen_min_ago = (now - timedelta(minutes=15)).isoformat()
        cursor.execute('''
            SELECT COUNT(DISTINCT session_id)
            FROM visitor_sessions
            WHERE entry_time >= ?
        ''', (fifteen_min_ago,))
        active_now = cursor.fetchone()[0] or 0

        # === 2. SESJE DZIS ===
        today = now.strftime('%Y-%m-%d')
        cursor.execute('''
            SELECT COUNT(*)
            FROM visitor_sessions
            WHERE date(entry_time) = ?
        ''', (today,))
        sessions_today = cursor.fetchone()[0] or 0

        # === 3. SREDNI CZAS SESJI (w sekundach) ===
        cursor.execute('''
            SELECT AVG(
                (julianday('now') - julianday(entry_time)) * 86400
            )
            FROM visitor_sessions
            WHERE date(entry_time) = ?
            AND is_active = 1
        ''', (today,))
        avg_duration = cursor.fetchone()[0] or 0
        avg_duration = int(avg_duration) if avg_duration else 0

        # === 4. CONVERSION RATE (% sesji z high-intent queries) ===
        cursor.execute('''
            SELECT
                COUNT(DISTINCT vs.session_id) as total,
                COUNT(DISTINCT CASE WHEN e.decision = 'ZNALEZIONE PRODUKTY'
                    THEN vs.session_id END) as high_intent
            FROM visitor_sessions vs
            LEFT JOIN events e ON e.details LIKE '%' || substr(vs.session_id, 1, 8) || '%'
            WHERE date(vs.entry_time) = ?
        ''', (today,))
        conv_data = cursor.fetchone()
        total_sessions = conv_data[0] or 1
        high_intent_sessions = conv_data[1] or 0
        conversion_rate = int((high_intent_sessions / total_sessions) * 100) if total_sessions > 0 else 0

        # === 5. LISTA FIRM (z engagement scores i latest queries) ===
        cursor.execute('''
            SELECT
                organization,
                city,
                country,
                MIN(entry_time) as first_visit,
                MAX(entry_time) as last_visit,
                COUNT(*) as total_queries
            FROM visitor_sessions
            WHERE organization IS NOT NULL
            AND organization != 'Unknown'
            AND date(entry_time) >= date('now', '-7 days')
            GROUP BY organization, city, country
            ORDER BY total_queries DESC
            LIMIT 20
        ''')

        companies = []
        for row in cursor.fetchall():
            org, city, country, first_visit, last_visit, total_queries = row

            cursor.execute('''
                SELECT
                    COUNT(CASE WHEN decision = 'ZNALEZIONE PRODUKTY' THEN 1 END) as high_intent,
                    COUNT(CASE WHEN decision = 'UTRACONE OKAZJE' THEN 1 END) as lost_opp
                FROM events
                WHERE details LIKE ?
            ''', (f'%{org}%',))

            intent_data = cursor.fetchone()
            high_intent = intent_data[0] if intent_data else 0
            lost_opp = intent_data[1] if intent_data else 0

            engagement_score = min(
                (total_queries * 10) + (high_intent * 20) + (lost_opp * 10),
                100
            )

            cursor.execute('''
                SELECT query_text
                FROM events
                WHERE details LIKE ?
                ORDER BY timestamp DESC
                LIMIT 1
            ''', (f'%{org}%',))

            latest_query = cursor.fetchone()
            latest_query = latest_query[0] if latest_query else 'N/A'

            companies.append({
                'name': org,
                'city': city,
                'country': country,
                'firstVisit': first_visit,
                'lastVisit': last_visit,
                'totalQueries': total_queries,
                'highIntentQueries': high_intent,
                'lostOpportunities': lost_opp,
                'engagementScore': engagement_score,
                'queries': [latest_query]
            })

        # === 6. AKTYWNE SESJE (z intent data) ===
        cursor.execute('''
            SELECT
                vs.session_id,
                vs.organization,
                vs.city,
                vs.country,
                vs.entry_time,
                COUNT(e.id) as query_count
            FROM visitor_sessions vs
            LEFT JOIN events e ON e.details LIKE '%' || substr(vs.session_id, 1, 8) || '%'
            WHERE vs.entry_time >= ?
            AND vs.is_active = 1
            GROUP BY vs.session_id, vs.organization, vs.city, vs.country, vs.entry_time
            ORDER BY vs.entry_time DESC
            LIMIT 10
        ''', (fifteen_min_ago,))

        active_sessions = []
        for row in cursor.fetchall():
            sess_id, org, city, country, entry_time, query_count = row

            # Bezpieczne parsowanie datetime
            try:
                entry_dt = datetime.fromisoformat(entry_time.replace('Z', '+00:00'))
                if entry_dt.tzinfo:
                    entry_dt = entry_dt.replace(tzinfo=None)
                duration = int((now - entry_dt).total_seconds())
            except:
                duration = 0

            cursor.execute('''
                SELECT
                    MAX(CASE WHEN decision = 'ZNALEZIONE PRODUKTY' THEN 1 ELSE 0 END) as has_high_intent,
                    MAX(CASE WHEN decision = 'UTRACONE OKAZJE' THEN 1 ELSE 0 END) as has_lost_opp,
                    query_text
                FROM events
                WHERE details LIKE ?
                ORDER BY timestamp DESC
                LIMIT 1
            ''', (f'%{sess_id[:8]}%',))

            session_data = cursor.fetchone()
            has_high_intent = bool(session_data[0]) if session_data else False
            has_lost_opp = bool(session_data[1]) if session_data else False
            latest_query = session_data[2] if session_data else None

            active_sessions.append({
                'session_id': sess_id[:8],
                'company': org or None,
                'city': city,
                'country': country,
                'duration': duration,
                'queries': query_count,
                'has_high_intent': has_high_intent,
                'has_lost_opportunity': has_lost_opp,
                'latest_query': latest_query
            })

        # === 7. KLASYFIKACJA ZAPYTAN (breakdown) ===
        cursor.execute('''
            SELECT
                decision,
                COUNT(*) as count
            FROM events
            WHERE date(timestamp) = ?
            GROUP BY decision
        ''', (today,))

        classification = {
            'found': 0,
            'lost': 0,
            'filtered': 0
        }

        for row in cursor.fetchall():
            decision, count = row
            if decision == 'ZNALEZIONE PRODUKTY':
                classification['found'] = count
            elif decision == 'UTRACONE OKAZJE':
                classification['lost'] = count
            elif decision == 'ODFILTROWANE':
                classification['filtered'] = count

        conn.close()

        return jsonify({
            'status': 'success',
            'stats': {
                'active_now': active_now,
                'sessions_today': sessions_today,
                'avg_duration': avg_duration,
                'conversion_rate': conversion_rate
            },
            'companies': companies,
            'active_sessions': active_sessions,
            'classification': classification
        })

    except Exception as e:
        print(f"[ERROR] Admin visitor stats failed: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500


# ========================================
# ADMIN PERSISTENT STORAGE ENDPOINTS
# ========================================

@api_bp.route('/api/admin/companies', methods=['GET'])
@require_admin_access
def api_get_companies():
    try:
        companies = get_all_companies()
        return jsonify({'status': 'success', 'companies': companies, 'count': len(companies)})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500


@api_bp.route('/api/admin/hot-leads', methods=['GET'])
@require_admin_access
def api_get_hot_leads():
    try:
        limit = request.args.get('limit', 50, type=int)
        hot_leads = get_hot_leads(limit)
        return jsonify({'status': 'success', 'hot_leads': hot_leads, 'count': len(hot_leads)})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500


@api_bp.route('/api/admin/log-history', methods=['GET'])
@require_admin_access
def api_get_log_history():
    try:
        limit = request.args.get('limit', 100, type=int)
        logs = get_log_history(limit)
        return jsonify({'status': 'success', 'logs': logs, 'count': len(logs)})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500


# ========================================
# ADMIN DATABASE FIX
# ========================================

@api_bp.route('/api/admin/fix-database-now')
@require_admin_access
def fix_database_now():
    """Endpoint ratunkowy do stworzenia braokujacej tabeli"""
    try:
        conn = sqlite3.connect(DATABASE_NAME)
        cursor = conn.cursor()

        # 1. Stworz tabele admin_dashboard_state
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS admin_dashboard_state (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                state_key TEXT UNIQUE NOT NULL,
                state_data TEXT NOT NULL,
                updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ''')

        # 2. Stworz index
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_state_key ON admin_dashboard_state(state_key)')

        conn.commit()
        conn.close()

        return jsonify({
            'status': 'success',
            'message': 'Tabela admin_dashboard_state zostala stworzona pomyslnie!'
        })
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500


# ========================================
# P3 - DEBUG DASHBOARD & EXPORT
# ========================================

@api_bp.route('/api/export-training-data')
@login_required
def export_training_data():
    """
    [P3] Export JSONL for Scale AI / LLM fine-tuning.
    Format: one JSON object per line (newline-delimited JSON).
    """
    if not hasattr(current_user, 'role') or current_user.role != 'debug':
        return jsonify({'error': 'Unauthorized'}), 403

    try:
        limit = request.args.get('limit', 1000, type=int)
        training_data = QueryIntentManager.get_training_data(limit)

        # Convert to JSONL format
        jsonl_lines = [json.dumps(entry, ensure_ascii=False) for entry in training_data]
        jsonl_content = '\n'.join(jsonl_lines)

        return Response(
            jsonl_content,
            mimetype='application/x-ndjson',
            headers={
                'Content-Disposition': f'attachment; filename=ldi_training_data_{limit}.jsonl',
                'Content-Type': 'application/x-ndjson; charset=utf-8'
            }
        )
    except Exception as e:
        app.logger.error(f"[P3] Export failed: {e}")
        return jsonify({'error': str(e)}), 500


@api_bp.route('/api/p3/query-intents', methods=['GET'])
@login_required
def api_get_query_intents():
    """
    [P3] API endpoint to fetch QueryIntent records for dashboard.
    """
    if not hasattr(current_user, 'role') or current_user.role != 'debug':
        return jsonify({'error': 'Unauthorized'}), 403

    try:
        limit = request.args.get('limit', 100, type=int)
        data = QueryIntentManager.get_training_data(limit)
        return jsonify({'status': 'success', 'data': data, 'count': len(data)})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500


# ========================================
# VISITOR TRACKING (RODO/GDPR Compliant)
# ========================================

@api_bp.route('/api/visitor-tracking', methods=['POST'])
@limiter.limit("100/minute")
def visitor_tracking():
    """API endpoint do odbierania danych visitor tracking - RODO COMPLIANT"""
    try:
        # FORCE JSON parsing z lepszym error handling
        if not request.is_json:
            print(f"[WARNING] Request without JSON content-type: {request.content_type}")
            try:
                data = request.get_json(force=True)
            except:
                return jsonify({'error': 'Content-Type must be application/json'}), 415
        else:
            data = request.get_json()

        if not data or 'session_id' not in data:
            return jsonify({'error': 'Missing session_id'}), 400

        session_id = data['session_id']
        event_type = data.get('event_type', 'unknown')

        print(f"[VISITOR TRACKING] {event_type} from session {session_id[:8]}...")

        if event_type == 'session_start':
            result = handle_session_start(session_id, data)
            print(f"[VISITOR TRACKING] Session start result: {result}")
        elif event_type == 'bot_query':
            result = handle_bot_query(session_id, data)
        else:
            result = {'status': 'success'}

        return jsonify(result)

    except Exception as e:
        print(f"[ERROR] Visitor tracking failed: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'error': 'Internal server error'}), 500


# ========================================
# VISITOR TRACKING HELPER FUNCTIONS
# ========================================

def handle_session_start(session_id, data):
    """Obsluguje rozpoczecie sesji odwiedzajacego - RODO COMPLIANT"""
    try:
        conn = sqlite3.connect(DATABASE_NAME)
        cursor = conn.cursor()

        # Parsuj entry_time i usun timezone
        entry_time = data.get('entry_time')
        if isinstance(entry_time, str):
            try:
                entry_time_dt = parser.parse(entry_time)
                entry_time = entry_time_dt.replace(tzinfo=None).isoformat()
            except Exception as e_parser:
                print(f"[WARNING] Dateutil parse error: {e_parser}. Falling back to now.")
                app.logger.warning(f"Dateutil parse error for entry_time '{entry_time}': {e_parser}")
                entry_time = datetime.now().isoformat()
        else:
            entry_time = datetime.now().isoformat()

        # === RODO: Pobierz raw IP TYLKO dla geolokalizacji ===
        raw_ip = data.get('ip_address')

        # Po geolokalizacji - ZAHASZUJ i ZAMASKUJ
        ip_hash = hash_ip_address(raw_ip) if raw_ip else 'hash_unknown'
        ip_masked = mask_ip_address(raw_ip) if raw_ip else 'masked'

        # RODO: NIE LOGUJ RAW IP - tylko masked
        print(f"[RODO] IP processed: masked={ip_masked}, hash={ip_hash[:20]}...")

        # Sprawdz Do Not Track
        anonymous_mode = data.get('anonymous_mode', False)

        # === ZAPISZ SESJE (BEZ raw IP!) ===
        cursor.execute('''
            INSERT OR REPLACE INTO visitor_sessions (
                session_id, ip_hash, ip_masked, user_agent, referrer, page_url,
                entry_time, country, city, organization,
                utm_source, utm_medium, device_type, os, browser, language,
                anonymous_mode
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            session_id,
            ip_hash,
            ip_masked,
            data.get('user_agent'),
            data.get('referrer'),
            data.get('page_url'),
            entry_time,
            data.get('country'),
            data.get('city'),
            data.get('org'),
            data.get('utm_source'),
            data.get('utm_medium'),
            data.get('device_type', 'Desktop'),
            data.get('os', 'Unknown'),
            data.get('browser', 'Unknown'),
            data.get('language'),
            anonymous_mode
        ))

        conn.commit()
        conn.close()

        org_name = data.get('org', 'Unknown')
        print(f"[VISITOR TRACKING] Session saved: {session_id[:8]}... from {org_name} (RODO compliant)")
        app.logger.info(f"Visitor session started: {session_id[:8]}... from {org_name}")

        return {'status': 'success', 'message': 'Session started (GDPR compliant)'}

    except Exception as e:
        print(f"[ERROR] Session start failed: {e}")
        import traceback
        traceback.print_exc()
        app.logger.error(f"Handle session start failed: {e}", exc_info=True)
        return {'status': 'error', 'message': str(e)}


def handle_bot_query(session_id, data):
    """Obsluguje zapytanie do bota - KLUCZOWY event dla TCD - RODO COMPLIANT"""
    try:
        # === RODO: SANITYZUJ QUERY PRZED ZAPISEM (BACKEND DEFENSE) ===
        raw_query = data.get('query', '')
        sanitized_query = scrub_pii(raw_query)
        source = data.get('source', 'moto')

        # WYBIERZ WLASCIWEGO BOTA
        if source == 'elektro' and ELEKTRO_BOT_AVAILABLE:
            active_bot = elektro_bot
            decision_mapping = ELEKTRO_DECISION_MAPPING
            print(f"[BOT_QUERY] Using ELEKTRO bot for analysis")
        else:
            active_bot = moto_bot
            decision_mapping = MOTO_DECISION_MAPPING
            print(f"[BOT_QUERY] Using MOTO bot for analysis")

        # Check if PII was detected
        if sanitized_query != raw_query:
            print(f"[RODO WARNING] PII detected and scrubbed in query (BACKEND)")
            print(f"  Original length: {len(raw_query)}")
            print(f"  Scrubbed length: {len(sanitized_query)}")
            app.logger.warning(f"PII scrubbed from query (backend) - session {session_id[:8]}")

        # Analizuj SANITIZED query przez wlasciwego bota
        analysis = active_bot.analyze_query_intent(sanitized_query)

        # Uzyj decision_mapping wybranego na podstawie zrodla
        decision = decision_mapping.get(analysis['confidence_level'], 'ODFILTROWANE')
        potential_value = calculate_lost_value_internal(sanitized_query) if decision == 'UTRACONE OKAZJE' else 0

        return {
            'status': 'success',
            'classification': decision,
            'confidence': analysis['confidence_level'],
            'potential_value': potential_value,
            'pii_detected': sanitized_query != raw_query
        }

    except Exception as e:
        print(f"[ERROR] Bot query tracking failed: {e}")
        app.logger.error(f"Handle bot query failed: {e}", exc_info=True)
        return {'status': 'error', 'message': str(e)}
