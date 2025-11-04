from flask_socketio import SocketIO, emit
from flask_login import login_user, logout_user, login_required, current_user
from auth_manager import init_login_manager, User, require_client_access, require_admin_access, require_debug_access, get_user_dashboard_route, setup_default_users, ensure_tables_exist
from flask import Flask, render_template, request, jsonify, session, redirect, url_for, flash, make_response
from datetime import datetime, timezone, timedelta
from ecommerce_bot import EcommerceBot
from dateutil import parser
import sqlite3
import json
import time
import random
import threading
import os
import requests
import uuid
import csv
import user_agents
import logging
from logging.handlers import RotatingFileHandler
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address  # Po linii 13



# Flask app configuration
app = Flask(__name__)
# === KONFIGURACJA LIMITERA ===
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["1000 per day", "100 per hour"],
    storage_uri="memory://",
    strategy="fixed-window"
)
login_manager = init_login_manager(app)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'dev-secret-key-change-in-production')
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=24)

# Session configuration
app.config['SESSION_COOKIE_SECURE'] = False
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['SESSION_PERMANENT'] = False

# === KONFIGURACJA LOGGINGU ===
if not app.debug:
    log_file = 'adept_ai_app.log'
    
    # Handler rotacyjny: 10MB na plik, 5 backupów
    file_handler = RotatingFileHandler(
        log_file,
        maxBytes=10*1024*1024,  # 10 MB
        backupCount=5
    )
    
    # Formatter logów (z czasem, poziomem, wiadomością i numerem linii)
    formatter = logging.Formatter(
        '%(asctime)s %(levelname)s: %(message)s '
        '[in %(pathname)s:%(lineno)d]'
    )
    file_handler.setFormatter(formatter)
    
    # Ustaw poziom logowania dla handlera
    file_handler.setLevel(logging.INFO)
    
    # Dodaj handler do loggera aplikacji Flask
    app.logger.addHandler(file_handler)
    app.logger.setLevel(logging.INFO)
    
    # Log startu aplikacji (Krok 2.4 - część 1)
    app.logger.info('Adept AI Application startup')
# ===============================

# Initialize SocketIO for dashboard
socketio = SocketIO(app, 
    cors_allowed_origins="*", 
    async_mode='eventlet',
    logger=True,
    engineio_logger=True,
    ping_timeout=120,  # Zwiększone z 60 → 120
    ping_interval=25,
    allow_upgrades=True,  # DODANE: pozwól upgrade do WebSocket
    transports=['polling', 'websocket']  # DODANE: oba transporty
)

# Initialize bot
bot = EcommerceBot()

# Lost demand log file
LOST_DEMAND_LOG = 'lost_demand_log.csv'

# Dashboard database configuration
DATABASE_NAME = 'dashboard.db'

# === DASHBOARD CLASSES ===

class DatabaseManager:
    """Zarządza bazą danych SQLite dla dashboardu"""
    
    @staticmethod
    def initialize_database():
        """Tworzy tabelę events jeśli nie istnieje"""
        conn = sqlite3.connect(DATABASE_NAME)
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                query_text TEXT NOT NULL,
                decision TEXT NOT NULL,
                details TEXT,
                category TEXT,
                brand_type TEXT,
                potential_value INTEGER,
                explanation TEXT
            )
        ''')
        
        # Dodaj indeksy dla wydajności
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_timestamp ON events(timestamp)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_decision ON events(decision)')
        
        conn.commit()
        conn.close()
        print("[DATABASE] Events table initialized")
    
    @staticmethod
    def add_event(query_text, decision, details, category, brand_type, potential_value, explanation):
        """Dodaje nowe zdarzenie do bazy"""
        conn = sqlite3.connect(DATABASE_NAME)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO events (query_text, decision, details, category, brand_type, potential_value, explanation)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (query_text, decision, details, category, brand_type, potential_value, explanation))
        
        event_id = cursor.lastrowid
        conn.commit()
        conn.close()
        
        return event_id
    
    @staticmethod
    def get_recent_events(limit=10):
        """Pobiera ostatnie wydarzenia"""
        conn = sqlite3.connect(DATABASE_NAME)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT id, timestamp, query_text, decision, details, category, 
                   brand_type, potential_value, explanation
            FROM events 
            ORDER BY timestamp DESC 
            LIMIT ?
        ''', (limit,))
        
        events = cursor.fetchall()
        conn.close()
        
        return [
            {
                'id': row[0],
                'timestamp': row[1],
                'query_text': row[2], 
                'decision': row[3],
                'details': row[4],
                'category': row[5],
                'brand_type': row[6],
                'potential_value': row[7],
                'explanation': row[8]
            }
            for row in events
        ]
    @staticmethod
    def get_today_statistics():
        """Pobiera statystyki z dzisiejszego dnia"""
        conn = sqlite3.connect(DATABASE_NAME)
        cursor = conn.cursor()
        
        today = datetime.now().strftime('%Y-%m-%d')
        
        # Zlicz wydarzenia według typu decyzji
        cursor.execute('''
            SELECT decision, COUNT(*) as count, COALESCE(SUM(potential_value), 0) as total_value
            FROM events 
            WHERE date(timestamp) = ?
            GROUP BY decision
        ''', (today,))
        
        results = cursor.fetchall()
        conn.close()
        
        stats = {
            'UTRACONE OKAZJE': {'count': 0, 'value': 0},
            'ODFILTROWANE': {'count': 0, 'value': 0}, 
            'ZNALEZIONE PRODUKTY': {'count': 0, 'value': 0}
        }
        
        for decision, count, value in results:
            if decision in stats:
                stats[decision]['count'] = count
                stats[decision]['value'] = int(value)
        
        return stats
    
    @staticmethod
    def get_top_missing_products(limit=5):
        """Pobiera najczęściej poszukiwane brakujące produkty"""
        conn = sqlite3.connect(DATABASE_NAME)
        cursor = conn.cursor()
        
        # Ostatnie 7 dni, tylko UTRACONY POPYT
        week_ago = (datetime.now() - timedelta(days=7)).strftime('%Y-%m-%d')
        
        cursor.execute('''
            SELECT category, COUNT(*) as frequency, SUM(potential_value) as total_value
            FROM events 
            WHERE decision = 'UTRACONE OKAZJE' 
            AND date(timestamp) >= ?
            GROUP BY category
            ORDER BY frequency DESC, total_value DESC
            LIMIT ?
        ''', (week_ago, limit))
        
        results = cursor.fetchall()
        conn.close()
        
        return [
            {
                'category': row[0],
                'frequency': row[1],
                'total_value': int(row[2]) if row[2] else 0
            }
            for row in results
        ]


# === FLASK ROUTES ===
# === WIZYTÓWKA ROUTES ===
@app.route('/')
def home():
    """Main landing page - wizytówka"""
    return render_template('index.html')
    
@app.route('/demo-motobot.html')
def demo_motobot():
    """Demo page with iframe to motobot"""
    return render_template('demo-motobot.html')

# === BOT E-COMMERCE ROUTES ===
@app.route('/motobot-prototype')
def motobot_index():
    """Main page of motobot with bot interface"""
    return render_template('demo_page.html')

@app.route('/demo')
def demo_page():
    """Demo page with bot and dashboard split screen"""
    return render_template('demo_page.html')

@app.route('/motobot-prototype/bot/start', methods=['POST'])
@limiter.limit("20/minute")
def bot_start():
    """Initialize bot session"""
    try:
        session.permanent = True
        session['cart'] = []
        session['context'] = None
        session['machine_filter'] = None
        
        # Get initial greeting
        initial_response = bot.get_initial_greeting()
        
        return jsonify({'reply': initial_response})
    
    except Exception as e:
        print(f"[ERROR] Bot start error: {e}")
        app.logger.error(f"Bot start error: {e}", exc_info=True)
        return jsonify({
            'reply': {
                'text_message': f'Wystąpił błąd podczas inicjalizacji: {str(e)}',
                'buttons': [
                    {'text': 'Spróbuj ponownie', 'action': 'restart'}
                ]
            }
        }), 500

@app.route('/motobot-prototype/bot/send', methods=['POST'])
@limiter.limit("100/minute")
def bot_send():
    """Handle user messages - BEZ integracji z TCD"""
    try:
        data = request.get_json()
        user_message = data.get('message', '')
        button_action = data.get('button_action', '')
        
        print(f"[DEBUG] Message: {user_message}, Action: {button_action}")
        app.logger.info(f"Received message: '{user_message}', Action: '{button_action}'")
        
        # Process button action or text message
        if button_action:
            reply = bot.handle_button_action(button_action)
        elif user_message:
            # USUNIĘTA integracja z TCD - tylko odpowiedź bota
            reply = bot.process_message(user_message)
        else:
            return jsonify({'error': 'No message or action provided'}), 400
        
        return jsonify({'reply': reply})
    
    except Exception as e:
        print(f"[ERROR] Bot send error: {e}")
        app.logger.error(f"Bot send error: {e}", exc_info=True)
        import traceback
        traceback.print_exc()
        return jsonify({
            'reply': {
                'text_message': 'Wystąpił błąd podczas przetwarzania żądania.',
                'buttons': [
                    {'text': 'Powrót do menu', 'action': 'main_menu'}
                ]
            }
        }), 500

@app.route('/motobot-prototype/search-suggestions', methods=['POST'])
@limiter.limit("100/minute")
def search_suggestions():
    """Real-time search suggestions - BEZ integracji z TCD (tylko sugestie)"""
    try:
        data = request.get_json()
        query = data.get('query', '').strip()
        search_type = data.get('type', 'products')
        
        # Minimum 2 characters to search
        if len(query) < 2:
            return jsonify({'suggestions': [], 'confidence_level': 'NONE'})
        
        suggestions = []
        confidence_level = 'HIGH'
        ga4_event = None
        
        if search_type == 'faq':
            # FAQ search
            faq_results = bot.get_fuzzy_faq_matches(query, limit=5)
            for faq, score in faq_results:
                suggestions.append({
                    'id': faq['id'],
                    'text': faq['question'],
                    'type': 'faq',
                    'score': int(score),
                    'category': faq.get('category', 'FAQ'),
                    'question': faq['question'],
                    'answer': faq['answer']
                })
            
            confidence_level = 'HIGH' if suggestions else 'NO_MATCH'
            
        else:
            # Search products with intent analysis
            machine_filter = session.get('machine_filter')
            
            result = bot.get_fuzzy_product_matches(
                query, machine_filter, limit=6, analyze_intent=True
            )
            
            if isinstance(result, tuple) and len(result) == 4:
                # New format with analysis
                products, confidence_level, suggestion_type, analysis = result
                
                # USUNIĘTA integracja z TCD - nie wysyłamy eventów
                
                # Determine GA4 event
                ga4_event_data = bot.determine_ga4_event(analysis)
                if ga4_event_data:
                    ga4_event = ga4_event_data['event']
                    bot.send_ga4_event(ga4_event_data)
                
                # Prepare suggestions
                for product, score in products:
                    stock_status = 'available' if product['stock'] > 10 else 'limited' if product['stock'] > 0 else 'out'
                    suggestions.append({
                        'id': product['id'],
                        'text': product['name'],
                        'type': 'product',
                        'score': int(score),
                        'price': f"{product['price']:.2f} zł",
                        'stock': product['stock'],
                        'stock_status': stock_status,
                        'brand': product['brand']
                    })
                
                # Log lost demand if needed (optional - można zostawić dla GA4)
                if confidence_level == 'NO_MATCH':
                    log_lost_demand(query, analysis)
        
        print(f"[SUGGESTIONS] Query: '{query}' | Type: {search_type} | Confidence: {confidence_level} | GA4: {ga4_event}")
        
        return jsonify({
            'suggestions': suggestions,
            'query': query,
            'confidence_level': confidence_level,
            'ga4_event': ga4_event
        })
    
    except Exception as e:
        print(f"[ERROR] Search suggestions error: {e}")
        app.logger.error(f"Search suggestions error: {e}", exc_info=True)
        import traceback
        traceback.print_exc()
        return jsonify({'suggestions': [], 'error': str(e)}), 200

# === NOWY ENDPOINT - FINALNA ANALIZA DLA TCD ===
@app.route('/motobot-prototype/api/analyze_query', methods=['POST'])
@limiter.limit("100/minute")
def analyze_query():
    """
    NOWY ENDPOINT - Doktryna Cierpliwego Nasłuchu
    Wywołany tylko po 800ms pauzy - wysyła JEDEN event do TCD
    """
    try:
        data = request.get_json()
        query = data.get('query', '').strip()
        search_type = data.get('type', 'products')
        
        print(f"[FINAL ANALYSIS] Query: '{query}' | Type: {search_type}")
        
        if len(query) < 2:
            return jsonify({
                'status': 'success',
                'message': 'Query too short'
            })
        
        # Analiza zapytania
        machine_filter = session.get('machine_filter')
        
        if search_type == 'faq':
            # FAQ - zazwyczaj HIGH confidence
            confidence_level = 'HIGH'
            category = 'faq'
        else:
            # Products - pełna analiza
            result = bot.get_fuzzy_product_matches(
                query, machine_filter, limit=6, analyze_intent=True
            )
            
            if isinstance(result, tuple) and len(result) == 4:
                products, confidence_level, suggestion_type, analysis = result
                category = extract_category_from_query(query)
            else:
                confidence_level = 'HIGH'
                category = 'unknown'
        
        # Mapowanie confidence → decision
        decision_mapping = {
            'HIGH': 'ZNALEZIONE PRODUKTY',
            'MEDIUM': 'ODFILTROWANE', 
            'NO_MATCH': 'UTRACONE OKAZJE',
            'LOW': 'ODFILTROWANE'
        }
        
        decision = decision_mapping.get(confidence_level, 'ZNALEZIONE PRODUKTY')
        
        # Oblicz wartość tylko dla utraconych okazji
        potential_value = 0
        if decision == 'UTRACONE OKAZJE':
            potential_value = calculate_lost_value_internal(query)
        
        # ZAPISZ DO BAZY DANYCH
        event_id = DatabaseManager.add_event(
            query,
            decision,
            'Finalne zapytanie użytkownika',
            category,
            'standard',
            potential_value,
            f'Analiza po 800ms pauzy - confidence: {confidence_level}'
        )
        
        # WYŚLIJ PRZEZ WEBSOCKET DO TCD
        event_data = {
            'id': event_id,
            'timestamp': datetime.now().strftime('%H:%M:%S'),
            'query_text': query,
            'decision': decision,
            'details': 'Finalne zapytanie użytkownika',
            'category': category,
            'potential_value': potential_value,
            'explanation': f'Analiza po 800ms pauzy - confidence: {confidence_level}'
        }
        
        # WYŚLIJ TYLKO DO DEMO TCD (nie do admin dashboard)
        socketio.emit('new_event', event_data, room='client_demo')
        
        print(f"[FINAL ANALYSIS] Saved to TCD: {query} -> {decision} (value: {potential_value})")
        
        return jsonify({
            'status': 'success',
            'decision': decision,
            'confidence_level': confidence_level,
            'event_id': event_id
        })
        
    except Exception as e:
        print(f"[ERROR] Final analysis error: {e}")
        app.logger.error(f"Final analysis error: {e}", exc_info=True)
        import traceback
        traceback.print_exc()
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

# === ADMIN DASHBOARD API ===
@app.route('/api/admin/visitor-stats')
@require_admin_access
def get_visitor_stats():
    """
    Zwraca statystyki visitor tracking dla admin dashboardu
    """
    try:
        conn = sqlite3.connect(DATABASE_NAME)
        cursor = conn.cursor()
        
        # FIX: Użyj datetime bez timezone
        now = datetime.now()
        
        # === 1. AKTYWNI UŻYTKOWNICY (ostatnie 15 min) ===
        fifteen_min_ago = (now - timedelta(minutes=15)).isoformat()
        cursor.execute('''
            SELECT COUNT(DISTINCT session_id)
            FROM visitor_sessions
            WHERE entry_time >= ?
        ''', (fifteen_min_ago,))
        active_now = cursor.fetchone()[0] or 0
        
        # === 2. SESJE DZIŚ ===
        today = now.strftime('%Y-%m-%d')
        cursor.execute('''
            SELECT COUNT(*)
            FROM visitor_sessions
            WHERE date(entry_time) = ?
        ''', (today,))
        sessions_today = cursor.fetchone()[0] or 0
        
        # === 3. ŚREDNI CZAS SESJI (w sekundach) ===
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
        
        # === 5. LISTA FIRM ===
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
        
        # === 6. AKTYWNE SESJE ===
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
            
            # FIX: Bezpieczne parsowanie datetime
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
        
        # === 7. KLASYFIKACJA ZAPYTAŃ ===
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

# === DASHBOARD API ROUTES ===
@app.route('/dashboard')
def dashboard():
    """Główna strona dashboardu"""
    return render_template('dashboard.html')

@app.route('/api/initial_data')
def get_initial_data():
    """API endpoint zwracający dane inicjalne dla dashboardu"""
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

@app.route('/api/reset_demo', methods=['POST'])  # DODAJ TO
def reset_demo():
    """Resetuje demo - czyści bazę i restartuje symulację"""
    try:
        conn = sqlite3.connect(DATABASE_NAME)
        cursor = conn.cursor()
        cursor.execute('DELETE FROM events')
        conn.commit()
        conn.close()
        
        return jsonify({'status': 'success', 'message': 'Demo reset successfully'})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500
@app.route('/api/receive_event', methods=['POST'])
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
            'standard',  # brand_type
            data.get('potential_value', 0),
            f"Prawdziwe zapytanie użytkownika"
        )
        
        # Wyślij przez WebSocket
        event_data = {
            'id': event_id,
            'timestamp': datetime.now().strftime('%H:%M:%S'),
            'query_text': data['query_text'],
            'decision': data['decision'],
            'details': data['details'],
            'category': data.get('category', 'unknown'),
            'potential_value': data.get('potential_value', 0),
            'explanation': 'Prawdziwe zapytanie użytkownika'
        }
        
        # WYŚLIJ TYLKO DO DEMO TCD (nie do admin dashboard)
        socketio.emit('new_event', event_data, room='client_demo')
        
        return jsonify({'status': 'success'})
        
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

# === POZOSTAŁE ROUTES ===
@app.route('/motobot-prototype/report-lost-demand', methods=['POST'])
def report_lost_demand():
    """Endpoint to collect and save lost demand reports"""
    try:
        data = request.get_json()
        query = data.get('query', '')
        email = data.get('email', '')
        notify = data.get('notify', False)
        
        # Initialize CSV with headers if needed
        if not os.path.exists(LOST_DEMAND_LOG) or os.path.getsize(LOST_DEMAND_LOG) == 0:
            with open(LOST_DEMAND_LOG, 'w', newline='', encoding='utf-8') as csvfile:
                writer = csv.writer(csvfile)
                writer.writerow(['timestamp', 'query', 'email', 'notify', 'machine_filter'])
        
        # Log to CSV file
        with open(LOST_DEMAND_LOG, 'a', newline='', encoding='utf-8') as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow([
                datetime.now().isoformat(),
                query,
                email,
                notify,
                session.get('machine_filter', 'all')
            ])
        
        # Send special GA4 event
        ga4_event_data = {
            'event': 'search_lost_demand_confirmed',
            'params': {
                'query': query,
                'email_provided': bool(email),
                'notification_requested': notify,
                'priority': 'CRITICAL'
            }
        }
        bot.send_ga4_event(ga4_event_data)
        
        print(f"[LOST DEMAND] User confirmed: '{query}' | Email: {bool(email)}")
        
        return jsonify({
            'status': 'success',
            'message': 'Dziękujemy! Twoje zgłoszenie pomoże nam ulepszyć ofertę.'
        })
    
    except Exception as e:
        print(f"[ERROR] Report lost demand error: {e}")
        return jsonify({
            'status': 'error',
            'message': 'Wystąpił błąd podczas zapisywania zgłoszenia.'
        }), 500

@app.route('/motobot-prototype/track-analytics', methods=['POST'])
def track_analytics():
    """Universal endpoint for tracking various analytics events"""
    try:
        data = request.get_json()
        event_type = data.get('event_type', '')
        event_data = data.get('event_data', {})
        
        ga4_event = {
            'event': event_type,
            'params': event_data
        }
        
        success = bot.send_ga4_event(ga4_event)
        
        return jsonify({
            'status': 'success' if success else 'failed',
            'event_type': event_type
        })
    
    except Exception as e:
        print(f"[ERROR] Track analytics error: {e}")
        return jsonify({'status': 'error', 'error': str(e)}), 500

@app.route('/motobot-prototype/health')
def health_check():
    """Health check endpoint with system status"""
    return jsonify({
        'status': 'OK',
        'service': 'Universal Soldier E-commerce Bot v5.0 - Doktryna Cierpliwego Nasłuchu',
        'version': '5.1-patient-listening',
        'features': {
            'intent_analysis': True,
            'lost_demand_tracking': True,
            'typo_correction': True,
            'confidence_scoring': True,
            'luxury_brand_detection': True,
            'precision_reward': True,
            'dashboard_integration': True,
            'real_time_websocket': True,
            'debounce_800ms': True
        },
        'session_active': 'cart' in session
    })
# ================================================================
# ROUTES AUTORYZACJI - DODAJ DO app.py PO ISTNIEJĄCYCH ROUTES
# Importy wymagane na górze pliku
# ================================================================

# DODAJ TE IMPORTY NA GÓRZE PLIKU app.py:
# from flask_login import login_user, logout_user, login_required, current_user
# from auth_manager import init_login_manager, User, require_client_access, require_admin_access, require_debug_access, get_user_dashboard_route, create_default_admin

# INICJALIZACJA FLASK-LOGIN (dodaj po 'app = Flask(__name__)'):
# login_manager = init_login_manager(app)

# ================================================================
# ROUTES AUTORYZACJI
# ================================================================

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Strona logowania - obsługuje GET (formularz) i POST (uwierzytelnienie)"""
    if request.method == 'GET':
        # Jeśli użytkownik już zalogowany, przekieruj do dashboardu
        if current_user.is_authenticated:
            dashboard_route = get_user_dashboard_route()
            return redirect(url_for(dashboard_route))
        
        return render_template('login.html')
    
    elif request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        
        # Walidacja podstawowa
        if not username or not password:
            flash('Wprowadź nazwę użytkownika i hasło', 'error')
            return render_template('login.html')
        
        # Uwierzytelnienie
        user = User.authenticate(username, password)
        
        if user:
            login_user(user, remember=True)
            flash(f'Zalogowano pomyślnie jako {user.username}', 'success')
            
            # Przekieruj do odpowiedniego dashboardu
            dashboard_route = get_user_dashboard_route()
            next_page = request.args.get('next')
            
            if next_page:
                return redirect(next_page)
            else:
                return redirect(url_for(dashboard_route))
        else:
            flash('Nieprawidłowa nazwa użytkownika lub hasło', 'error')
            return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    """Wylogowanie użytkownika"""
    username = current_user.username
    logout_user()
    flash(f'Zostałeś wylogowany', 'info')
    return redirect(url_for('login'))

@app.route('/unauthorized')
def unauthorized():
    """Strona błędu dostępu"""
    return render_template('unauthorized.html'), 403

# ================================================================
# DASHBOARDY - 3 POZIOMY DOSTĘPU
# ================================================================

@app.route('/client-dashboard')
@login_required
def client_dashboard():
    """POZIOM 1 - Kokpit Klienta (tylko własne dane)"""
    client_info = get_client_info(current_user.client_id)
    
    return render_template('client-dashboard.html', 
                         user=current_user,
                         client=client_info)

@app.route('/admin-dashboard')
@require_admin_access  
def admin_dashboard():
    """POZIOM 2 - Centrum Strategiczne (dane zagregowane + moduł sprzedażowy)"""
    return render_template('admin-dashboard.html', 
                         user=current_user)

@app.route('/debug-dashboard')
@require_debug_access
def debug_dashboard():
    """POZIOM 3 - Tryb Debug (surowe logi + telemetria)"""
    return render_template('debug-dashboard.html', 
                         user=current_user)

# ================================================================
# API ENDPOINTS - ROLE-BASED ACCESS
# ================================================================

@app.route('/api/auth/session-info')
def get_session_info():
    """Zwraca informacje o aktualnej sesji"""
    if current_user.is_authenticated:
        return jsonify({
            'authenticated': True,
            'username': current_user.username,
            'role': current_user.role,
            'client_id': current_user.client_id
        })
    else:
        return jsonify({
            'authenticated': False
        })

@app.route('/api/client/<int:client_id>/stats')
@require_client_access
def get_client_stats(client_id):
    """API - POZIOM 1: Statystyki tylko dla określonego klienta"""
    
    # Sprawdź czy user ma dostęp do tego klienta
    if not current_user.has_access_to_client(client_id):
        return jsonify({'error': 'Brak dostępu'}), 403
    
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

@app.route('/api/admin/global-stats')
@require_admin_access
def get_global_stats():
    """API - POZIOM 2: Statystyki zagregowane ze wszystkich klientów"""
    
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

@app.route('/api/debug/raw-logs')
@require_debug_access  
def get_raw_logs():
    """API - POZIOM 3: Surowe logi + telemetria"""
    
    limit = request.args.get('limit', 100, type=int)
    offset = request.args.get('offset', 0, type=int)
    
    try:
        conn = sqlite3.connect(DATABASE_NAME)
        cursor = conn.cursor()
        
        # Surowe logi wszystkich eventów
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
    
# DODAJ TO DO app.py W SEKCJI API ENDPOINTS

@app.route('/api/client/<int:client_id>/weekly-report.pdf')
@require_client_access
def get_weekly_pdf_report(client_id):
    """API - POZIOM 1: Pobierz cotygodniowy raport PDF dla klienta"""
    
    # Sprawdź czy user ma dostęp do tego klienta
    if not current_user.has_access_to_client(client_id):
        return jsonify({'error': 'Brak dostępu'}), 403
    
    try:
        # Pobierz dane klienta
        client_info = get_client_info(client_id)
        if not client_info:
            return jsonify({'error': 'Klient nie znaleziony'}), 404
        
        # DEMO DATA - w prawdziwej aplikacji pobierane z bazy
        # Po Twojej kuracji cotygodniowej
        demo_data = {
            'client': client_info,
            'report_date': '13.10.2025',
            'total_lost_value': 12450,
            'total_products': 47,
            'lost_products': [
                {'name': 'Klocki Ferrari F40', 'category': 'klocki', 'value': 1250, 'frequency': 8},
                {'name': 'Filtry Porsche 911', 'category': 'filtry', 'value': 890, 'frequency': 6},
                {'name': 'Opony Michelin 19"', 'category': 'opony', 'value': 760, 'frequency': 5},
                {'name': 'Amortyzatory Bentley', 'category': 'amortyzatory', 'value': 650, 'frequency': 4},
                {'name': 'Felgi BMW M3', 'category': 'felgi', 'value': 580, 'frequency': 4},
                {'name': 'Filtry sportowe K&N', 'category': 'filtry', 'value': 520, 'frequency': 3},
                {'name': 'Klocki Brembo Racing', 'category': 'klocki', 'value': 480, 'frequency': 3},
                # ... reszta 40 produktów
            ],
            'recommendations': [
                'Rozszerz ofertę klocków premium - potencjał 3,250 zł miesięcznie',
                'Dodaj filtry sportowe - popyt na 12 różnych modeli',
                'Współpraca z dystrybutorem opon - segment premium wykryty',
                'Części do supersamochodów - niszowy ale wartościowy segment'
            ]
        }
        
        # Generuj PDF (prosty HTML → PDF lub używaj biblioteki jak ReportLab)
        html_content = generate_pdf_html(demo_data)
        
        # OPCJA 1: Zwróć HTML (tymczasowo na test)
        from flask import make_response
        response = make_response(html_content)
        response.headers['Content-Type'] = 'text/html'
        response.headers['Content-Disposition'] = f'inline; filename="raport_utraconych_okazji_{client_id}.html"'
        
        # OPCJA 2: Prawdziwy PDF (wymaga biblioteki)
        # from weasyprint import HTML
        # pdf = HTML(string=html_content).write_pdf()
        # response = make_response(pdf)
        # response.headers['Content-Type'] = 'application/pdf'
        # response.headers['Content-Disposition'] = f'attachment; filename="raport_{client_id}.pdf"'
        
        return response
        
    except Exception as e:
        print(f"[API ERROR] PDF generation failed: {e}")
        return jsonify({'status': 'error', 'message': str(e)}), 500

def generate_pdf_html(data):
    """Generuje HTML dla raportu PDF"""
    html = f"""
    <!DOCTYPE html>
    <html lang="pl">
    <head>
        <meta charset="UTF-8">
        <title>Raport Utraconych Okazji - {data['client']['company_name']}</title>
        <style>
            body {{ font-family: Arial, sans-serif; margin: 40px; color: #333; }}
            .header {{ text-align: center; border-bottom: 2px solid #4fc3f7; padding-bottom: 20px; margin-bottom: 30px; }}
            .summary {{ background: #f5f5f5; padding: 20px; margin: 20px 0; border-radius: 8px; }}
            .products-table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
            .products-table th, .products-table td {{ border: 1px solid #ddd; padding: 10px; text-align: left; }}
            .products-table th {{ background: #4fc3f7; color: white; }}
            .value {{ color: #ff6b6b; font-weight: bold; }}
            .category {{ background: #e3f2fd; padding: 2px 8px; border-radius: 4px; font-size: 12px; }}
        </style>
    </head>
    <body>
        <div class="header">
            <h1>Centrum Analityczne Utraconych Okazji</h1>
            <h2>Cotygodniowy Raport Zweryfikowany</h2>
            <p><strong>{data['client']['company_name']}</strong> | {data['report_date']}</p>
        </div>
        
        <div class="summary">
            <h3>Podsumowanie wykonawcze</h3>
            <p><strong>Łączna wartość wykrytych okazji:</strong> <span class="value">{data['total_lost_value']:,} zł</span></p>
            <p><strong>Liczba zidentyfikowanych produktów:</strong> {data['total_products']}</p>
            <p><strong>Status:</strong> Zweryfikowany przez analityka Studio Adept AI</p>
        </div>
        
        <h3>Szczegółowa lista utraconych produktów</h3>
        <table class="products-table">
            <thead>
                <tr>
                    <th>Lp.</th>
                    <th>Produkt</th>
                    <th>Kategoria</th>
                    <th>Szacowana wartość</th>
                    <th>Częstotliwość zapytań</th>
                </tr>
            </thead>
            <tbody>
    """
    
    # Dodaj produkty do tabeli
    for i, product in enumerate(data['lost_products'], 1):
        html += f"""
            <tr>
                <td>{i}</td>
                <td>{product['name']}</td>
                <td><span class="category">{product['category']}</span></td>
                <td class="value">{product['value']} zł</td>
                <td>{product['frequency']}x</td>
            </tr>
        """
    
    html += """
            </tbody>
        </table>
        
        <div style="margin-top: 40px;">
            <h3>Rekomendacje implementacji</h3>
            <ol>
    """
    
    # Dodaj rekomendacje
    for rec in data['recommendations']:
        html += f"<li>{rec}</li>"
    
    html += """
            </ol>
        </div>
        
        <div style="margin-top: 40px; text-align: center; color: #666; font-size: 12px;">
            <p>Raport wygenerowany przez Centrum Analityczne Utraconych Okazji</p>
            <p>Studio Adept AI | {data['report_date']}</p>
        </div>
    </body>
    </html>
    """
    
    return html
    

# ================================================================
# FUNKCJE POMOCNICZE (dodaj na koniec pliku)
# ================================================================

def get_client_info(client_id):
    """Pobiera informacje o kliencie z bazy danych"""
    if not client_id:
        return None
        
    try:
        conn = sqlite3.connect(DATABASE_NAME)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT id, company_name, domain, subscription_tier, contact_email
            FROM clients 
            WHERE id = ? AND is_active = TRUE
        ''', (client_id,))
        
        row = cursor.fetchone()
        conn.close()
        
        if row:
            return {
                'id': row[0],
                'company_name': row[1],
                'domain': row[2], 
                'subscription_tier': row[3],
                'contact_email': row[4]
            }
        return None
        
    except Exception as e:
        print(f"[ERROR] Failed to get client info: {e}")
        return None

# ================================================================
# INICJALIZACJA ADMIN USER (wywołaj w main lub przy starcie)
# ================================================================
    


# === HELPER FUNCTIONS ===
def extract_category_from_query(query):
    """Wyciąga kategorię z zapytania"""
    query_lower = query.lower()
    categories = ['klocki', 'filtry', 'amortyzatory', 'świece', 'akumulatory', 'oleje', 'tarcze']
    for category in categories:
        if category in query_lower:
            return category
    return 'inne'

def calculate_lost_value_internal(query):
    """Szacuje wartość utraconego popytu - NAPRAWIONA wersja z losowymi wartościami 500-1000"""
    import random
    
    category = extract_category_from_query(query)
    
    # Nowe zakresy 500-1000 z bonusami dla kategorii
    base_ranges = {
        'klocki': (600, 1000),      # Popularna kategoria
        'filtry': (500, 800),       # Tańsze części  
        'amortyzatory': (800, 1200), # Drogie części
        'świece': (500, 700),       # Małe części
        'akumulatory': (700, 1100), # Średnio drogie
        'oleje': (600, 900),        # Płyny
        'tarcze': (700, 1000),      # Duże części
        'łańcuchy': (600, 900)      # Motocykle
    }
    
    # Pobierz zakres dla kategorii lub użyj domyślny
    min_val, max_val = base_ranges.get(category, (500, 1000))
    
    # Sprawdź czy to marka luksusowa (bonus +200-400)
    query_lower = query.lower()
    luxury_brands = ['ferrari', 'lamborghini', 'porsche', 'bentley', 'maserati', 'aston martin']
    
    if any(brand in query_lower for brand in luxury_brands):
        min_val += 300
        max_val += 500
    
    # Zwróć losową wartość z zakresu
    return random.randint(min_val, max_val)

def log_lost_demand(query, analysis):
    """Helper function to log lost demand"""
    try:
        if not os.path.exists(LOST_DEMAND_LOG) or os.path.getsize(LOST_DEMAND_LOG) == 0:
            with open(LOST_DEMAND_LOG, 'w', newline='', encoding='utf-8') as csvfile:
                writer = csv.writer(csvfile)
                writer.writerow(['timestamp', 'query', 'email', 'notify', 'machine_filter'])
        
        with open(LOST_DEMAND_LOG, 'a', newline='', encoding='utf-8') as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow([
                datetime.now().isoformat(),
                query,
                '',
                False,
                session.get('machine_filter', 'all')
            ])
        print(f"[LOST DEMAND AUTO] Logged: '{query}'")
    except Exception as e:
        print(f"[ERROR] Failed to log lost demand: {e}")

# === DEBUG ROUTES (only for development) ===
@app.route('/motobot-prototype/debug/test-intent-analysis')
def test_intent_analysis():
    """Debug endpoint for testing intent analysis"""
    if app.debug:
        test_queries = [
            "klocki golf",
            "kloki glof", 
            "klocki xyzz",
            "xyza123",
            "opony zimowe",
            "amortyzator ferrari",
            "filtr mann bmw",
            "amortyztor bilsten"
        ]
        
        results = {}
        for query in test_queries:
            analysis = bot.analyze_query_intent(query)
            results[query] = {
                'confidence_level': analysis['confidence_level'],
                'suggestion_type': analysis['suggestion_type'],
                'token_validity': analysis['token_validity'],
                'best_match_score': analysis['best_match_score'],
                'ga4_event': analysis['ga4_event'],
                'has_luxury': analysis.get('has_luxury_brand', False)
            }
        
        return jsonify({
            'test': 'Intent Analysis Test - Patient Listening v5.1',
            'results': results,
            'interpretation': {
                'HIGH': 'Show normal results',
                'MEDIUM': 'Show "Did you mean..." (typo)',
                'LOW': 'Show "We don\'t understand" (nonsense)',
                'NO_MATCH': 'Show "Product not in catalog" (LOST DEMAND!)'
            }
        })
    return jsonify({'error': 'Available only in debug mode'}), 403

@app.route('/motobot-prototype/debug/lost-demand-report')
def lost_demand_report():
    """Debug endpoint to view lost demand log"""
    if app.debug:
        try:
            lost_demands = []
            if os.path.exists(LOST_DEMAND_LOG):
                with open(LOST_DEMAND_LOG, 'r', encoding='utf-8') as csvfile:
                    reader = csv.reader(csvfile)
                    next(reader, None)
                    for row in reader:
                        if len(row) >= 5:
                            lost_demands.append({
                                'timestamp': row[0],
                                'query': row[1],
                                'email': row[2],
                                'notify': row[3],
                                'machine_filter': row[4]
                            })
            
            # Group by query for summary
            query_counts = {}
            for demand in lost_demands:
                query = demand['query'].lower()
                query_counts[query] = query_counts.get(query, 0) + 1
            
            top_queries = sorted(query_counts.items(), key=lambda x: x[1], reverse=True)[:10]
            
            return jsonify({
                'total_lost_demands': len(lost_demands),
                'unique_queries': len(query_counts),
                'recent_demands': lost_demands[-10:] if lost_demands else [],
                'top_missing_products': top_queries
            })
        except Exception as e:
            return jsonify({'error': str(e)}), 500
    return jsonify({'error': 'Available only in debug mode'}), 403

# === WEBSOCKET EVENTS FOR DASHBOARD ===
@socketio.on('connect')
def handle_connect():
    """Klient podłączył się do WebSocket"""
    from flask_socketio import join_room
    from flask import request as flask_request
    
    print('[WEBSOCKET] Client connected')
    
    # Sprawdź czy to admin czy demo TCD (client)
    # Sprawdzamy przez referer URL lub user role
    user_agent = flask_request.headers.get('User-Agent', '')
    referer = flask_request.headers.get('Referer', '')
    
    # Jeśli zalogowany - sprawdź rolę
    if current_user.is_authenticated:
        if current_user.role in ['admin', 'debug']:
            join_room('admin_dashboard')
            print(f'[WEBSOCKET] Admin {current_user.username} joined admin_dashboard room')
            emit('connection_confirmed', {'message': 'Connected to Admin Dashboard', 'room': 'admin'})
        else:
            join_room('client_demo')
            print(f'[WEBSOCKET] Client {current_user.username} joined client_demo room')
            emit('connection_confirmed', {'message': 'Connected to Demo TCD', 'room': 'client'})
    else:
        # Niezalogowany - domyślnie demo TCD
        join_room('client_demo')
        print('[WEBSOCKET] Anonymous user joined client_demo room')
        emit('connection_confirmed', {'message': 'Connected to Demo TCD', 'room': 'client'})

@socketio.on('disconnect')
def handle_disconnect():
    """Klient rozłączył się z WebSocket""" 
    print('[WEBSOCKET] Client disconnected')

@socketio.on('request_current_stats')
def handle_stats_request():
    """Klient prosi o aktualne statystyki"""
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

# WYŁĄCZONE - simulator nie jest używany (martwy kod)
# @socketio.on('pause_simulator')
# def handle_pause_simulator():
#     """Pauzuje symulator na żądanie klienta"""
#     simulator.pause_simulator()
#     emit('simulator_paused', {'status': 'paused'})

# @socketio.on('resume_simulator') 
# def handle_resume_simulator():
#     """Wznawia symulator na żądanie klienta"""
#     simulator.resume_simulator()
#     emit('simulator_resumed', {'status': 'resumed'})

# === BATTLE SIMULATOR FUNCTION ===



def get_client_info(client_id):
    """Pobiera informacje o kliencie z bazy danych"""
    if not client_id:
        return None
        
    try:
        conn = sqlite3.connect(DATABASE_NAME)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT id, company_name, domain, subscription_tier, contact_email
            FROM clients 
            WHERE id = ? AND is_active = TRUE
        ''', (client_id,))
        
        row = cursor.fetchone()
        conn.close()
        
        if row:
            return {
                'id': row[0],
                'company_name': row[1],
                'domain': row[2], 
                'subscription_tier': row[3],
                'contact_email': row[4]
            }
        return None
        
    except Exception as e:
        print(f"[ERROR] Failed to get client info: {e}")
        return None


# === VISITOR TRACKING SYSTEM ===

def ensure_visitor_tables_exist():
    """Tworzy tabele dla visitor tracking jeśli nie istnieją"""
    conn = sqlite3.connect(DATABASE_NAME)
    cursor = conn.cursor()
    
    # Tabela sesji odwiedzających
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS visitor_sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id TEXT UNIQUE NOT NULL,
            
            -- Podstawowe dane
            ip_address TEXT,
            user_agent TEXT,
            referrer TEXT,
            page_url TEXT,
            
            -- Dane czasowe
            entry_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            exit_time TIMESTAMP,
            last_activity TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            session_duration INTEGER DEFAULT 0,
            
            -- Dane geograficzne
            country TEXT,
            country_code TEXT,
            city TEXT,
            region TEXT,
            latitude REAL,
            longitude REAL,
            timezone TEXT,
            
            -- Dane organizacji (reverse IP lookup)
            organization TEXT,
            isp TEXT,
            
            -- Aktywność użytkownika
            total_messages INTEGER DEFAULT 0,
            max_scroll_depth INTEGER DEFAULT 0,
            clicks_count INTEGER DEFAULT 0,
            
            -- UTM tracking
            utm_source TEXT,
            utm_medium TEXT,
            utm_campaign TEXT,
            utm_content TEXT,
            utm_term TEXT,
            
            -- Dane techniczne
            platform TEXT,
            language TEXT,
            viewport TEXT,
            screen TEXT,
            
            -- Status
            is_active BOOLEAN DEFAULT TRUE,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Indeksy
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_visitor_sessions_entry_time ON visitor_sessions(entry_time)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_visitor_sessions_ip ON visitor_sessions(ip_address)')
    
    conn.commit()
    conn.close()
    print("[DATABASE] Visitor tracking tables initialized")

# ==== ZADANIE 2.2: WEBSOCKET HANDLER DLA VISITOR_EVENT ====
@socketio.on('visitor_event')
def handle_visitor_event_websocket(data):
    """
    Handler WebSocket dla visitor_event
    Odbiera dane z visitor_tracking.js i retransmituje jako live_feed_update
    """
    try:
        print(f"[WEBSOCKET] Received visitor_event: {data.get('query', 'N/A')[:50]}...")
        
        # Wyciągnij dane
        query = data.get('query', '')
        session_id = data.get('sessionId', 'unknown')
        
        # Analizuj zapytanie przez istniejący system AI
        analysis = bot.analyze_query_intent(query)
        
        # Mapowanie na decisions
        decision_mapping = {
            'HIGH': 'ZNALEZIONE PRODUKTY',
            'MEDIUM': 'ODFILTROWANE', 
            'LOW': 'ODFILTROWANE',
            'NO_MATCH': 'UTRACONE OKAZJE'
        }
        
        decision = decision_mapping.get(analysis['confidence_level'], 'ODFILTROWANE')
        potential_value = calculate_lost_value_internal(query) if decision == 'UTRACONE OKAZJE' else 0
        
        # Dodaj do głównego systemu TCD
        event_id = DatabaseManager.add_event(
            query,
            decision,
            f'{data.get("organization", "Unknown")}',  # FIXED: organizacja zamiast Visitor
            extract_category_from_query(query),
            'visitor',
            potential_value,
            f"Live visitor query - {analysis['confidence_level']} confidence"
        )
        
        # ==== KLUCZOWE: Retransmituj jako live_feed_update z pełnymi danymi ====
        live_feed_data = {
            'id': event_id,
            'timestamp': datetime.now().strftime('%H:%M:%S'),
            'query': query,
            'classification': decision,
            'estimatedValue': potential_value,
            'city': data.get('city', 'Unknown'),
            'country': data.get('country', 'Unknown'),
            'organization': data.get('organization', 'Unknown'),
            'sessionId': session_id
        }
        
        print(f"[WEBSOCKET] Broadcasting live_feed_update ONLY to admin_dashboard")
        emit('live_feed_update', live_feed_data, room='admin_dashboard')
        
        # WYŁĄCZONE - TCD dostaje event z /api/analyze_query ("Finalne zapytanie")
        # Nie wysyłamy tu new_event bo to powoduje duplikaty!
        # tcd_event_data = { ... }
        # socketio.emit('new_event', tcd_event_data, room='client_demo')
        
        print(f"[WEBSOCKET] Event processed successfully: {decision}")
        
    except Exception as e:
        print(f"[ERROR] Failed to handle visitor_event: {e}")
        import traceback
        traceback.print_exc()


@app.route('/api/visitor-tracking', methods=['POST'])
def visitor_tracking():
    """API endpoint do odbierania danych visitor tracking"""
    try:
        # FORCE JSON parsing z lepszym error handling
        if not request.is_json:
            print(f"[WARNING] Request without JSON content-type: {request.content_type}")
            # Try to parse anyway
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

def handle_session_start(session_id, data):
    """Obsługuje rozpoczęcie sesji odwiedzającego"""
    try:
        conn = sqlite3.connect(DATABASE_NAME)
        cursor = conn.cursor()
        
        # FIX: Parsuj entry_time i usuń timezone
        entry_time = data.get('entry_time')
        if isinstance(entry_time, str):
            # Parse ISO datetime i usuń timezone info
            try:
                # 'from dateutil import parser' ZOSTAŁO PRZENIESIONE NA GÓRĘ PLIKU
                entry_time_dt = parser.parse(entry_time)
                entry_time = entry_time_dt.replace(tzinfo=None).isoformat()
            except Exception as e_parser:
                # Log błędu parsowania i użyj fallback
                print(f"[WARNING] Dateutil parse error: {e_parser}. Falling back to now.")
                app.logger.warning(f"Dateutil parse error for entry_time '{entry_time}': {e_parser}")
                entry_time = datetime.now().isoformat()
        else:
            # Fallback dla braku daty
            entry_time = datetime.now().isoformat()
            
        # Zapisz sesję
        cursor.execute('''
            INSERT OR REPLACE INTO visitor_sessions (
                session_id, ip_address, user_agent, referrer, page_url,
                entry_time, country, city, organization, 
                utm_source, utm_medium, platform, language
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            session_id,
            data.get('ip_address'),
            data.get('user_agent'),
            data.get('referrer'),
            data.get('page_url'),
            entry_time,  # ← FIXED: bez timezone
            data.get('country'),
            data.get('city'),
            data.get('org'),
            data.get('utm_source'),
            data.get('utm_medium'),
            data.get('platform'),
            data.get('language')
        ))
        
        conn.commit()
        conn.close()
        
        print(f"[VISITOR TRACKING] Session saved: {session_id[:8]}... from {data.get('org', 'Unknown')}")
        app.logger.info(f"Visitor session started: {session_id[:8]}... from {data.get('org', 'Unknown')}")
        return {'status': 'success', 'message': 'Session started'}
        
    except Exception as e:
        print(f"[ERROR] Session start failed: {e}")
        import traceback
        traceback.print_exc()
        app.logger.error(f"Handle session start failed: {e}", exc_info=True) # Dodany logging błędu
        return {'status': 'error', 'message': str(e)}

def handle_bot_query(session_id, data):
    """Obsługuje zapytanie do bota - KLUCZOWY event dla TCD"""
    try:
        query = data.get('query', '')
        
        # Analizuj zapytanie przez istniejący system AI
        analysis = bot.analyze_query_intent(query)
        
        # Mapowanie na decisions
        decision_mapping = {
            'HIGH': 'ZNALEZIONE PRODUKTY',
            'MEDIUM': 'ODFILTROWANE', 
            'LOW': 'ODFILTROWANE',
            'NO_MATCH': 'UTRACONE OKAZJE'
        }
        
        decision = decision_mapping.get(analysis['confidence_level'], 'ODFILTROWANE')
        potential_value = calculate_lost_value_internal(query) if decision == 'UTRACONE OKAZJE' else 0
        
        # WYŁĄCZONE - duplikat z WebSocket handler (@socketio.on('visitor_event'))
        # event_id = DatabaseManager.add_event(
        #     query,
        #     decision,
        #     f'Visitor query from session {session_id[:8]}',
        #     extract_category_from_query(query),
        #     'visitor',
        #     potential_value,
        #     f"Visitor tracking: {analysis['confidence_level']} confidence"
        # )
        
        # Zwróć tylko status - WebSocket handler zajmuje się dodawaniem do bazy
        
        # WYŁĄCZONE - duplikat z WebSocket handler (linia 1455)
        # event_data = {
        #     'id': event_id,
        #     'timestamp': datetime.now().strftime('%H:%M:%S'),
        #     'query_text': query,
        #     'decision': decision,
        #     'details': f'Visitor: {get_visitor_context(session_id)}',
        #     'category': extract_category_from_query(query),
        #     'potential_value': potential_value,
        #     'explanation': f'Visitor query - confidence: {analysis["confidence_level"]}',
        #     'session_id': session_id[:8]
        # }
        # 
        # socketio.emit('new_event', event_data)  # WYŁĄCZONE - używamy live_feed_update
        
        # === POPRAWIONY RETURN ===
        # Usunięto odwołanie do 'event_id', które nie jest już tutaj definiowane.
        return {
            'status': 'success',
            'classification': decision,
            'confidence': analysis['confidence_level'],
            'potential_value': potential_value
        }
        
    except Exception as e:
        print(f"[ERROR] Bot query tracking failed: {e}")
        app.logger.error(f"Handle bot query failed: {e}", exc_info=True) # Dodany logging błędu
        return {'status': 'error', 'message': str(e)}

def get_visitor_context(session_id):
    """Pobiera kontekst odwiedzającego dla Live Feed"""
    try:
        conn = sqlite3.connect(DATABASE_NAME)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT city, organization, country 
            FROM visitor_sessions 
            WHERE session_id = ?
        ''', (session_id,))
        
        row = cursor.fetchone()
        conn.close()
        
        if row:
            city, org, country = row
            parts = []
            if org: parts.append(org)
            if city: parts.append(city)
            if country and not city: parts.append(country)
            
            return ', '.join(parts) if parts else 'Unknown'
        
        return 'Unknown'
        
    except Exception as e:
        print(f"[ERROR] Failed to get visitor context: {e}")
        return 'Unknown'

# app.py (Wklej to np. po linii 1598)





# === MAIN APPLICATION STARTUP ===
if __name__ == '__main__':
    with app.app_context():
        # Initialize bot data
        bot.initialize_data()
        
        # Initialize dashboard database
        DatabaseManager.initialize_database()
        # Initialize visitor tracking tables
        ensure_visitor_tables_exist()
        
        # Clear old events (older than 30 days)
        try:
            conn = sqlite3.connect(DATABASE_NAME)
            cursor = conn.cursor()
            cutoff_date = (datetime.now() - timedelta(days=30)).strftime('%Y-%m-%d')
            cursor.execute('DELETE FROM events WHERE date(timestamp) < ?', (cutoff_date,))
            deleted_count = cursor.rowcount
            conn.commit()
            conn.close()
            if deleted_count > 0:
                print(f"[DATABASE] Cleared {deleted_count} old events")
        except Exception as e:
            print(f"[DATABASE] Error clearing old events: {e}")
        
        # Start battle simulator
        
        
        print("=" * 70)
        print("🎯 STUDIO ADEPT AI - DOKTRYNA CIERPLIWEGO NASŁUCHU v5.1")
        print("=" * 70)
        print("🏢 Features enabled:")
        print("   🌐 Wizytówka: /")
        print("   🤖 Motobot: /motobot-prototype")
        print("   📊 Dashboard: /dashboard")
        print("   🎮 Demo (Bot + Dashboard): /demo")
        print("=" * 70)
        print("✅ Unified system started!")
        print("   ⏱️  Debounce: 800ms for TCD updates")
        print("   🎯 Live Feed: Real-time user feedback")
        print("   📊 Metrics: Only final queries counted")
        print("=" * 70)
        ensure_tables_exist()

        # Inicjalizuj hasła przy pierwszym uruchomieniu
        try:
            conn = sqlite3.connect('dashboard.db')
            cursor = conn.cursor()
            cursor.execute('SELECT COUNT(*) FROM users')
            user_count = cursor.fetchone()[0]
            conn.close()
            
            if user_count == 0:
                print("[STARTUP] Baza pusta - tworzę użytkowników...")
                import subprocess
                subprocess.run(['python', 'skrypthasla.py'])
        except:
            print("[STARTUP] Tabela users nie istnieje - tworzę...")
            import subprocess
            subprocess.run(['python', 'skrypthasla.py'])
        
        print("🔐 Sistema Autoryzacji aktywny")
        print("👤 Default admin: admin / admin123")
        
        socketio.run(app, debug=True, host='0.0.0.0', port=5000)
