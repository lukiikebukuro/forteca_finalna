import eventlet
eventlet.monkey_patch()
from flask_socketio import SocketIO, emit
from flask_login import login_user, logout_user, login_required, current_user
from auth_manager import init_login_manager, User, require_client_access, require_admin_access, require_debug_access, get_user_dashboard_route, setup_default_users, ensure_tables_exist
from flask import Flask, render_template, request, jsonify, session, redirect, url_for, flash, make_response
from datetime import datetime, timezone, timedelta

# 🔥 DUAL BOT IMPORT - MOTO + ELEKTRO
from ecommerce_bot import EcommerceBot as MotoBot
try:
    from elektro_bot import EcommerceBot as ElektroBot
    ELEKTRO_BOT_AVAILABLE = True
    print("✅ Elektro bot imported successfully")
except ImportError as e:
    print(f"⚠️ Elektro bot not available: {e}")
    ELEKTRO_BOT_AVAILABLE = False
    ElektroBot = None

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
from flask_limiter.util import get_remote_address
import hashlib
import re

# ========================================
# DODAJ TO DO app.py TUŻ PRZED init_database()
# ========================================

def auto_update_admin_password():
    """Automatyczna migracja hasła admin przy starcie"""
    import sqlite3
    from werkzeug.security import generate_password_hash, check_password_hash
    
    try:
        conn = sqlite3.connect('dashboard.db')
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT id, password_hash 
            FROM users 
            WHERE username = 'admin' AND is_active = TRUE
        """)
        
        user = cursor.fetchone()
        
        if not user:
            conn.close()
            return
        
        user_id, current_hash = user
        
        # Sprawdź czy hasło to już 'admin123'
        if check_password_hash(current_hash, 'admin123'):
            print("[AUTO-UPDATE] ✅ Hasło admin/admin123 OK")
            conn.close()
            return
        
        # Zaktualizuj hasło
        print("[AUTO-UPDATE] 🔄 Aktualizuję hasło admin...")
        new_hash = generate_password_hash('admin123', method='pbkdf2:sha256')
        
        cursor.execute("""
            UPDATE users 
            SET password_hash = ?, salt = ''
            WHERE username = 'admin'
        """, (new_hash,))
        
        conn.commit()
        conn.close()
        
        print("[AUTO-UPDATE] ✅ Hasło zmienione: admin/admin123")
        
    except Exception as e:
        print(f"[AUTO-UPDATE] ⚠️ Błąd: {e}")

# ========================================
# ZMODYFIKUJ init_database() - DODAJ NA KOŃCU
# ========================================

def init_database():
    """Inicjalizuje bazę danych przy starcie"""
    print("[STARTUP] Sprawdzam integralność bazy danych...")
    
    # 1. GWARANTOWANA NAPRAWA: Zawsze próbuj stworzyć tabelę admin_dashboard_state
    try:
        AdminDashboardStateManager.init_table()
        init_persistent_storage_tables()
        print("[STARTUP] ✅ Wymuszono weryfikację tabeli admin_dashboard_state")
    except Exception as e:
        print(f"[STARTUP] ⚠️ Warning przy weryfikacji tabeli admin: {e}")

    # 2. Standardowa procedura dla nowej bazy
    conn = sqlite3.connect('dashboard.db')
    cursor = conn.cursor()
    
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='users'")
    if not cursor.fetchone():
        print("[STARTUP] Baza pusta (brak users) - Tworzę resztę tabel...")
        conn.close()
        
        from auth_manager import ensure_tables_exist
        ensure_tables_exist()
        
        DatabaseManager.init_events_table()
        DatabaseManager.init_visitor_tables()
        
        print("[STARTUP] Ustawiam hasła...")
        import subprocess
        import sys
        try:
            subprocess.run([sys.executable, 'skrypthasla.py'], check=True)
        except Exception as e:
            print(f"[STARTUP] Błąd skryptu haseł: {e}")
    else:
        conn.close()
        print("[STARTUP] Baza users już istnieje - pomijam tworzenie podstawowe.")
    
    # ========================================
    # 3. DODAJ TO NA KOŃCU (PO if/else)
    # ========================================
    auto_update_admin_password()
    # ========================================


# ========== KONIEC INICJALIZACJI ==========

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
    
    # Log startu aplikacji
    app.logger.info('Adept AI Application startup')
# ===============================

# Initialize SocketIO for dashboard
socketio = SocketIO(app, 
    cors_allowed_origins="*", 
    async_mode='eventlet',
    logger=True,
    engineio_logger=True,
    ping_timeout=120,
    ping_interval=25,
    allow_upgrades=True,
    transports=['polling', 'websocket']
)

# 🔥 DUAL BOT INITIALIZATION - MOTO + ELEKTRO
print("🚀 Initializing DUAL BOT system...")
moto_bot = MotoBot()
print("✅ Moto bot initialized")

if ELEKTRO_BOT_AVAILABLE:
    elektro_bot = ElektroBot()
    print("✅ Elektro bot initialized")
else:
    elektro_bot = None
    print("⚠️ Elektro bot disabled - using moto only")

# Backward compatibility - 'bot' defaults to moto_bot
bot = moto_bot

# 🎯 DECISION MAPPINGS - RÓŻNE DLA KAŻDEJ BRANŻY!
# MOTORYZACJA: Krótkie nazwy produktów → MEDIUM = niepewne → ODFILTROWANE
MOTO_DECISION_MAPPING = {
    'HIGH': 'ZNALEZIONE PRODUKTY',
    'MEDIUM': 'ODFILTROWANE',  # ❌ dla motoryzacji
    'LOW': 'ODFILTROWANE',
    'NO_MATCH': 'UTRACONE OKAZJE'
}

# ELEKTRONIKA: Długie nazwy produktów → MEDIUM = dobre dopasowanie → FOUND!
ELEKTRO_DECISION_MAPPING = {
    'HIGH': 'ZNALEZIONE PRODUKTY',
    'MEDIUM': 'ZNALEZIONE PRODUKTY',  # ✅ dla elektroniki!
    'LOW': 'ODFILTROWANE',
    'NO_MATCH': 'UTRACONE OKAZJE'
}

# Lost demand log file
LOST_DEMAND_LOG = 'lost_demand_log.csv'

# Dashboard database configuration
DATABASE_NAME = 'dashboard.db'

# ================================================================
# RODO COMPLIANCE FUNCTIONS - DODANE DLA BEZPIECZEŃSTWA
# ================================================================

def hash_ip_address(ip):
    """
    RODO: Haszuje adres IP używając SHA-256
    Zwraca skrócony hash (16 znaków) dla oszczędności miejsca
    """
    if not ip:
        return 'hash_unknown'
    
    try:
        hash_object = hashlib.sha256(ip.encode('utf-8'))
        hash_hex = hash_object.hexdigest()
        return f'hash_{hash_hex[:16]}'
    except Exception as e:
        print(f"[ERROR] IP hashing failed: {e}")
        app.logger.error(f"IP hashing failed: {e}")
        return 'hash_error'

def mask_ip_address(ip):
    """
    RODO: Maskuje ostatni oktet IPv4 lub końcówkę IPv6
    Przykład: 192.168.1.123 -> 192.168.1.xxx
    """
    if not ip:
        return 'masked'
    
    try:
        # IPv4: 192.168.1.123 -> 192.168.1.xxx
        if '.' in ip and ip.count('.') == 3:
            parts = ip.split('.')
            return f"{parts[0]}.{parts[1]}.{parts[2]}.xxx"
        
        # IPv6: 2001:0db8:85a3::8a2e:0370:7334 -> 2001:0db8:85a3::xxxx
        elif ':' in ip:
            parts = ip.split(':')
            return ':'.join(parts[:-2]) + '::xxxx'
        
        return 'masked'
    except Exception as e:
        print(f"[ERROR] IP masking failed: {e}")
        app.logger.error(f"IP masking failed: {e}")
        return 'masked'

def scrub_pii(text):
    """
    RODO: Sanityzacja danych osobowych (PII)
    Usuwa: Email, Telefon, PESEL, Karty Kredytowe, IBAN, NIP
    
    KRYTYCZNE: Ta funkcja MUSI działać zarówno na frontend jak i backend!
    """
    if not text or not isinstance(text, str):
        return text
    
    scrubbed = text
    pii_detected = False
    
    # Email: user@domain.com
    original = scrubbed
    scrubbed = re.sub(
        r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
        '[REDACTED_EMAIL]',
        scrubbed
    )
    if scrubbed != original:
        pii_detected = True
        app.logger.warning("PII DETECTED: Email address scrubbed")
    
    # Polski telefon: +48 123 456 789, 123-456-789, 123456789
    original = scrubbed
    scrubbed = re.sub(
        r'(\+48\s?)?(\d{3}[\s\-]?\d{3}[\s\-]?\d{3})',
        '[REDACTED_PHONE]',
        scrubbed
    )
    if scrubbed != original:
        pii_detected = True
        app.logger.warning("PII DETECTED: Phone number scrubbed")
    
    # PESEL: 11 cyfr
    original = scrubbed
    scrubbed = re.sub(
        r'\b\d{11}\b',
        '[REDACTED_PESEL]',
        scrubbed
    )
    if scrubbed != original:
        pii_detected = True
        app.logger.warning("PII DETECTED: PESEL scrubbed")
    
    # Karta kredytowa: 16 cyfr (z opcjonalnymi spacjami/myślnikami)
    original = scrubbed
    scrubbed = re.sub(
        r'\b\d{4}[\s\-]?\d{4}[\s\-]?\d{4}[\s\-]?\d{4}\b',
        '[REDACTED_CARD]',
        scrubbed
    )
    if scrubbed != original:
        pii_detected = True
        app.logger.warning("PII DETECTED: Credit card scrubbed")
    
    # IBAN: PL followed by 26 digits
    original = scrubbed
    scrubbed = re.sub(
        r'\bPL\d{26}\b',
        '[REDACTED_IBAN]',
        scrubbed,
        flags=re.IGNORECASE
    )
    if scrubbed != original:
        pii_detected = True
        app.logger.warning("PII DETECTED: IBAN scrubbed")
    
    # NIP: 10 cyfr (opcjonalnie z myślnikami)
    original = scrubbed
    scrubbed = re.sub(
        r'\b\d{3}[\-]?\d{3}[\-]?\d{2}[\-]?\d{2}\b',
        '[REDACTED_NIP]',
        scrubbed
    )
    if scrubbed != original:
        pii_detected = True
        app.logger.warning("PII DETECTED: NIP scrubbed")
    
    if pii_detected:
        print(f"[RODO WARNING] PII detected and scrubbed - original length: {len(text)}, scrubbed: {len(scrubbed)}")
    
    return scrubbed

def cleanup_old_sessions():
    """
    RODO: Data Retention Policy
    Usuwa sesje starsze niż 30 dni
    Wywołanie: Cron job lub przy starcie aplikacji
    """
    try:
        conn = sqlite3.connect(DATABASE_NAME)
        cursor = conn.cursor()
        
        # Oblicz datę graniczną (30 dni temu)
        cutoff_date = (datetime.now() - timedelta(days=30)).isoformat()
        
        # Usuń stare sesje
        cursor.execute('''
            DELETE FROM visitor_sessions
            WHERE entry_time < ?
        ''', (cutoff_date,))
        
        deleted_count = cursor.rowcount
        conn.commit()
        conn.close()
        
        if deleted_count > 0:
            print(f"[RODO CLEANUP] Removed {deleted_count} sessions older than 30 days")
            app.logger.info(f"RODO cleanup: Removed {deleted_count} old sessions")
        
        return deleted_count
        
    except Exception as e:
        print(f"[ERROR] Session cleanup failed: {e}")
        app.logger.error(f"Session cleanup failed: {e}", exc_info=True)
        return 0

def check_do_not_track(request):
    """
    RODO: Sprawdza czy użytkownik ma włączone Do Not Track
    """
    dnt_header = request.headers.get('DNT') or request.headers.get('dnt')
    return dnt_header == '1'

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
        """Dodaje nowe zdarzenie do bazy - z RODO scrubbing i silniejszą deduplikacją"""
        sanitized_query = scrub_pii(query_text)
        conn = sqlite3.connect(DATABASE_NAME)
        cursor = conn.cursor()
        # WZMOCNIONA DEDUPE: sprawdź, czy podobne zdarzenie nie zostało dodane w ostatnich 5 sekundach,
        # oraz czy nie istnieje event o tym samym query/decision/potential_value w ±2s (timestamp)
        try:
            cursor.execute('''
                SELECT id, timestamp FROM events
                WHERE query_text = ? AND decision = ? AND potential_value = ?
                AND timestamp >= datetime('now', '-5 seconds')
                ORDER BY timestamp DESC LIMIT 1
            ''', (sanitized_query, decision, potential_value))
            row = cursor.fetchone()
            if row:
                existing_id = row[0]
                conn.close()
                app.logger.info(f"[DEDUP] Skipping duplicate event (id={existing_id}) [5s window]")
                return existing_id
            
            # Dodatkowa deduplikacja: ±2s względem aktualnego czasu
            cursor.execute('''
                SELECT id, timestamp FROM events
                WHERE query_text = ? AND decision = ? AND potential_value = ?
                AND ABS(strftime('%s', timestamp) - strftime('%s', 'now')) <= 2
                ORDER BY timestamp DESC LIMIT 1
            ''', (sanitized_query, decision, potential_value))
            row2 = cursor.fetchone()
            if row2:
                existing_id = row2[0]
                conn.close()
                app.logger.info(f"[DEDUP] Skipping duplicate event (id={existing_id}) [±2s window]")
                return existing_id
        except Exception as e:
            app.logger.warning(f"[DEDUP] Duplicate check failed: {e}")
        
        cursor.execute('''
            INSERT INTO events (query_text, decision, details, category, brand_type, potential_value, explanation)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (sanitized_query, decision, details, category, brand_type, potential_value, explanation))
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

class AdminDashboardStateManager:
    """
    Zarządza persystencją danych admin dashboardu w bazie danych.
    Zastępuje localStorage server-side storage.
    """
    
    @staticmethod
    def init_table():
        """Tworzy tabelę admin_dashboard_state jeśli nie istnieje"""
        conn = sqlite3.connect(DATABASE_NAME)
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS admin_dashboard_state (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                state_key TEXT UNIQUE NOT NULL,
                state_data TEXT NOT NULL,
                updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Index dla szybkiego lookup
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_state_key ON admin_dashboard_state(state_key)')
        
        conn.commit()
        conn.close()
        print("[DATABASE] Admin dashboard state table initialized")
    
    @staticmethod
    def save_state(state_key, data):
        """
        Zapisuje stan dashboardu dla danego klucza
        
        Args:
            state_key: 'hot_leads', 'companies', lub 'log_history'
            data: dict/list do zapisania (będzie JSON-owany)
        """
        conn = sqlite3.connect(DATABASE_NAME)
        cursor = conn.cursor()
        
        json_data = json.dumps(data, ensure_ascii=False, default=str)
        
        cursor.execute('''
            INSERT INTO admin_dashboard_state (state_key, state_data, updated_at)
            VALUES (?, ?, CURRENT_TIMESTAMP)
            ON CONFLICT(state_key) 
            DO UPDATE SET 
                state_data = excluded.state_data,
                updated_at = CURRENT_TIMESTAMP
        ''', (state_key, json_data))
        
        conn.commit()
        conn.close()
        
        print(f"[ADMIN_STATE] Saved {state_key}: {len(json_data)} bytes")
    
    @staticmethod
    def get_state(state_key):
        """
        Pobiera stan dashboardu dla danego klucza
        
        Args:
            state_key: 'hot_leads', 'companies', lub 'log_history'
            
        Returns:
            dict/list lub None jeśli nie istnieje
        """
        conn = sqlite3.connect(DATABASE_NAME)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT state_data, updated_at
            FROM admin_dashboard_state
            WHERE state_key = ?
        ''', (state_key,))
        
        row = cursor.fetchone()
        conn.close()
        
        if row:
            try:
                data = json.loads(row[0])
                print(f"[ADMIN_STATE] Loaded {state_key}: {len(row[0])} bytes (updated: {row[1]})")
                return data
            except json.JSONDecodeError as e:
                print(f"[ADMIN_STATE] ERROR loading {state_key}: {e}")
                return None
        
        print(f"[ADMIN_STATE] No data found for {state_key}")
        return None
    
    @staticmethod
    def delete_state(state_key):
        """Usuwa stan dla danego klucza"""
        conn = sqlite3.connect(DATABASE_NAME)
        cursor = conn.cursor()
        
        cursor.execute('DELETE FROM admin_dashboard_state WHERE state_key = ?', (state_key,))
        
        conn.commit()
        conn.close()
        
        print(f"[ADMIN_STATE] Deleted {state_key}")


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

# 🔥 ELEKTRO BOT ROUTES - NEW!
@app.route('/elektrobot-prototype')
def elektrobot_index():
    """Main page of elektrobot with bot interface"""
    if not ELEKTRO_BOT_AVAILABLE:
        flash('Elektro bot is not available', 'error')
        return redirect(url_for('motobot_index'))
    return render_template('demo_page_elektro.html')

@app.route('/live-demo')
def elektro_demo_page():
    """Elektro demo page with bot and dashboard split screen"""
    if not ELEKTRO_BOT_AVAILABLE:
        flash('Elektro bot is not available', 'error')
        return redirect(url_for('demo_page'))
    return render_template('demo_page_elektro.html')

@app.route('/motobot-prototype/bot/start', methods=['POST'])
@limiter.limit("20/minute")
def bot_start():
    """Initialize bot session - MOTO"""
    try:
        session.permanent = True
        session['cart'] = []
        session['context'] = None
        session['machine_filter'] = None
        
        # Get initial greeting
        initial_response = moto_bot.get_initial_greeting()
        
        return jsonify({'reply': initial_response})
    
    except Exception as e:
        print(f"[ERROR] Moto bot start error: {e}")
        app.logger.error(f"Bot start error: {e}", exc_info=True)
        return jsonify({
            'reply': {
                'text_message': f'Wystąpił błąd podczas inicjalizacji: {str(e)}',
                'buttons': [
                    {'text': 'Spróbuj ponownie', 'action': 'restart'}
                ]
            }
        }), 500

# 🔥 ELEKTRO BOT START - NEW!
@app.route('/elektrobot-prototype/bot/start', methods=['POST'])
@limiter.limit("20/minute")
def elektro_bot_start():
    """Initialize bot session - ELEKTRO"""
    if not ELEKTRO_BOT_AVAILABLE:
        return jsonify({'error': 'Elektro bot not available'}), 503
        
    try:
        session.permanent = True
        session['cart'] = []
        session['context'] = None
        session['machine_filter'] = None
        
        # Get initial greeting
        initial_response = elektro_bot.get_initial_greeting()
        
        return jsonify({'reply': initial_response})
    
    except Exception as e:
        print(f"[ERROR] Elektro bot start error: {e}")
        app.logger.error(f"Elektro bot start error: {e}", exc_info=True)
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
    """Handle user messages - MOTO"""
    try:
        data = request.get_json()
        user_message = data.get('message', '')
        button_action = data.get('button_action', '')
        
        print(f"[DEBUG] Moto Message: {user_message}, Action: {button_action}")
        app.logger.info(f"Moto received: '{user_message}', Action: '{button_action}'")
        
        # Process button action or text message
        if button_action:
            reply = moto_bot.handle_button_action(button_action)
        elif user_message:
            reply = moto_bot.process_message(user_message)
        else:
            return jsonify({'error': 'No message or action provided'}), 400
        
        return jsonify({'reply': reply})
    
    except Exception as e:
        print(f"[ERROR] Moto bot send error: {e}")
        app.logger.error(f"Moto bot send error: {e}", exc_info=True)
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

# 🔥 ELEKTRO BOT SEND - NEW!
@app.route('/elektrobot-prototype/bot/send', methods=['POST'])
@limiter.limit("100/minute")
def elektro_bot_send():
    """Handle user messages - ELEKTRO"""
    if not ELEKTRO_BOT_AVAILABLE:
        return jsonify({'error': 'Elektro bot not available'}), 503
        
    try:
        data = request.get_json()
        user_message = data.get('message', '')
        button_action = data.get('button_action', '')
        
        print(f"[DEBUG] Elektro Message: {user_message}, Action: {button_action}")
        app.logger.info(f"Elektro received: '{user_message}', Action: '{button_action}'")
        
        # Process button action or text message
        if button_action:
            reply = elektro_bot.handle_button_action(button_action)
        elif user_message:
            reply = elektro_bot.process_message(user_message)
        else:
            return jsonify({'error': 'No message or action provided'}), 400
        
        return jsonify({'reply': reply})
    
    except Exception as e:
        print(f"[ERROR] Elektro bot send error: {e}")
        app.logger.error(f"Elektro bot send error: {e}", exc_info=True)
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
    """Real-time search suggestions - MOTO"""
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
            faq_results = moto_bot.get_fuzzy_faq_matches(query, limit=5)
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
            
            result = moto_bot.get_fuzzy_product_matches(
                query, machine_filter, limit=6, analyze_intent=True
            )
            
            if isinstance(result, tuple) and len(result) == 4:
                # New format with analysis
                products, confidence_level, suggestion_type, analysis = result
                
                # Determine GA4 event
                ga4_event_data = moto_bot.determine_ga4_event(analysis)
                if ga4_event_data:
                    ga4_event = ga4_event_data['event']
                    moto_bot.send_ga4_event(ga4_event_data)
                
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
                
                # Log lost demand if needed (optional)
                if confidence_level == 'NO_MATCH':
                    log_lost_demand(query, analysis)
        
        print(f"[MOTO SUGGESTIONS] Query: '{query}' | Type: {search_type} | Confidence: {confidence_level} | GA4: {ga4_event}")
        
        return jsonify({
            'suggestions': suggestions,
            'query': query,
            'confidence_level': confidence_level,
            'ga4_event': ga4_event
        })
    
    except Exception as e:
        print(f"[ERROR] Moto search suggestions error: {e}")
        app.logger.error(f"Moto search suggestions error: {e}", exc_info=True)
        import traceback
        traceback.print_exc()
        return jsonify({'suggestions': [], 'error': str(e)}), 200
# 🔥 ELEKTRO SEARCH SUGGESTIONS - NEW!
@app.route('/elektrobot-prototype/search-suggestions', methods=['POST'])
@limiter.limit("100/minute")
def elektro_search_suggestions():
    """Real-time search suggestions - ELEKTRO"""
    if not ELEKTRO_BOT_AVAILABLE:
        return jsonify({'suggestions': [], 'error': 'Elektro bot not available'}), 503
        
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
            faq_results = elektro_bot.get_fuzzy_faq_matches(query, limit=5)
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
            
            result = elektro_bot.get_fuzzy_product_matches(
                query, machine_filter, limit=6, analyze_intent=True
            )
            
            if isinstance(result, tuple) and len(result) == 4:
                # New format with analysis
                products, confidence_level, suggestion_type, analysis = result
                
                # Determine GA4 event
                ga4_event_data = elektro_bot.determine_ga4_event(analysis)
                if ga4_event_data:
                    ga4_event = ga4_event_data['event']
                    elektro_bot.send_ga4_event(ga4_event_data)
                
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
                
                # Log lost demand if needed (optional)
                if confidence_level == 'NO_MATCH':
                    log_lost_demand(query, analysis)
        
        print(f"[ELEKTRO SUGGESTIONS] Query: '{query}' | Type: {search_type} | Confidence: {confidence_level} | GA4: {ga4_event}")
        
        return jsonify({
            'suggestions': suggestions,
            'query': query,
            'confidence_level': confidence_level,
            'ga4_event': ga4_event
        })
    
    except Exception as e:
        print(f"[ERROR] Elektro search suggestions error: {e}")
        app.logger.error(f"Elektro search suggestions error: {e}", exc_info=True)
        import traceback
        traceback.print_exc()
        return jsonify({'suggestions': [], 'error': str(e)}), 200
    
    

# === NOWY ENDPOINT - FINALNA ANALIZA DLA TCD ===
@app.route('/motobot-prototype/api/analyze_query', methods=['POST'])
@limiter.limit("100/minute")
def analyze_query():
    """
    MOTO VERSION - Doktryna Cierpliwego Nasłuchu
    Wywołany po 800ms pauzy - wysyła event do TCD
    """
    import uuid
    request_id = str(uuid.uuid4())[:8]
    
    try:
        data = request.get_json()
        query = data.get('query', '').strip()
        search_type = data.get('type', 'products')
        
        # Odbierz dane geolokalizacji z frontendu (jeśli dostępne)
        visitor_city = data.get('city', 'Unknown')
        visitor_country = data.get('country', 'Unknown')
        visitor_org = data.get('org', 'Unknown')
        
        # 🎯 PASSIVE RADAR: Odbierz session_id
        session_id = data.get('session_id', None)
        
        print(f"[MOTO FINAL ANALYSIS][REQ:{request_id}] Query: '{query}' | Type: {search_type} | Geo: {visitor_city}, {visitor_country} | Session: {session_id}")
        
        # === RODO: SANITYZUJ QUERY ===
        sanitized_query = scrub_pii(query)
        if sanitized_query != query:
            print(f"[RODO] PII scrubbed in analyze_query")
            app.logger.warning(f"PII scrubbed in analyze_query")
        
        if len(sanitized_query) < 2:
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
                sanitized_query, machine_filter, limit=6, analyze_intent=True
            )
            
            if isinstance(result, tuple) and len(result) == 4:
                products, confidence_level, suggestion_type, analysis = result
                category = extract_category_from_query(sanitized_query)
            else:
                confidence_level = 'HIGH'
                category = 'unknown'
        
        # Mapowanie confidence → decision (MOTO rules)
        decision_mapping = MOTO_DECISION_MAPPING  # Użyj mappingu dla MOTO!
        decision = decision_mapping.get(confidence_level, 'ODFILTROWANE')
        
        # Oblicz wartość tylko dla utraconych okazji
        potential_value = 0
        if decision == 'UTRACONE OKAZJE':
            potential_value = calculate_lost_value_internal(sanitized_query, source='moto')
        
        # ZAPISZ DO BAZY DANYCH
        event_id = DatabaseManager.add_event(
            sanitized_query,
            decision,
            'Finalne zapytanie użytkownika (MOTO)',
            category,
            'moto',
            potential_value,
            f'Analiza po 800ms pauzy - confidence: {confidence_level}'
        )
        
        # === PERSISTENT STORAGE (MOTO) ===
        session_id = request.cookies.get('visitor_session_id')
        organization = 'Unknown Visitor'
        city = country = 'Unknown'
        if session_id:
            visitor_ctx = get_visitor_context(session_id)
            if visitor_ctx and visitor_ctx != 'Unknown':
                parts = visitor_ctx.split(', ')
                organization = parts[0] if len(parts) >= 1 else organization
                city = parts[1] if len(parts) >= 2 else city
                country = parts[2] if len(parts) >= 3 else country
        company_data = save_company_data(organization, city, country, sanitized_query, decision)
        if company_data and company_data['engagement_score'] >= 30 and decision == 'ZNALEZIONE PRODUKTY':
            save_hot_lead(organization, sanitized_query, company_data['engagement_score'])
        save_log_entry(decision, organization, sanitized_query)
        
        # WYŚLIJ PRZEZ WEBSOCKET DO TCD
        server_ts_ms = int(time.time() * 1000)
        event_data = {
            'id': event_id,
            'timestamp': datetime.now().strftime('%H:%M:%S'),
            'query_text': sanitized_query,
            'decision': decision,
            'details': 'Finalne zapytanie użytkownika (MOTO)',
            'category': category,
            'potential_value': potential_value,
            'explanation': f'Analiza po 800ms pauzy - confidence: {confidence_level}',
            'server_sent_at': server_ts_ms
        }
        
        # Dane geolokalizacji już odebrane z frontendu (visitor_city, visitor_country, visitor_org)
        # Nie trzeba ponownie odpytywać ipinfo.io
        
        # Sformatuj dane dla live_feed_update
        feed_data = {
            'timestamp': datetime.now().strftime('%H:%M:%S'),
            'query': sanitized_query,
            'classification': decision,
            'estimatedValue': potential_value,
            'city': visitor_city,
            'country': visitor_country,
            'organization': visitor_org,
            'sessionId': session_id,  # 🎯 PASSIVE RADAR: Dodane!
            'anonymous': True,
            'source': 'moto'
        }
        
        # 🎯 PASSIVE RADAR FIX 2: UPDATE STATUS W BAZIE
        if session_id:
            try:
                conn = sqlite3.connect(DATABASE_NAME)
                cursor = conn.cursor()
                
                cursor.execute('''
                    UPDATE visitor_sessions 
                    SET radar_status = 'Pisze',
                        last_activity = CURRENT_TIMESTAMP
                    WHERE session_id = ?
                ''', (session_id,))
                
                conn.commit()
                conn.close()
                print(f"🎯 PASSIVE RADAR: Status updated to 'Pisze' for session {session_id}")
                
            except Exception as db_error:
                print(f"🎯 PASSIVE RADAR: Błąd update statusu: {db_error}")
        
        # WYŚLIJ DO DASHBOARDU (broadcast do obu roomów)
        print(f"[WS EMIT][MOTO][REQ:{request_id}] live_feed_update id={event_id} sent_at={server_ts_ms} city={visitor_city}")
        print(f"🔍 SESSION DEBUG: Sending feed_data with sessionId = {session_id}")  # 🔧 DEBUG
        app.logger.info(f"[WS EMIT][MOTO] live_feed_update id={event_id} sent_at={server_ts_ms}")
        
        socketio.emit('live_feed_update', feed_data, room='client_demo')
        socketio.emit('live_feed_update', feed_data, room='admin_dashboard')
        
        print(f"[MOTO FINAL ANALYSIS][REQ:{request_id}] Saved to TCD: {sanitized_query} -> {decision} (value: {potential_value})")
        
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
    

"""
============================================================
🚨 KRYTYCZNY FIX - WKLEJ DO app.py 🚨
============================================================

PROBLEM: Konsola pokazuje błąd 404:
    POST /elektrobot-prototype/api/analyze_query 404 (NOT FOUND)
    
ROZWIĄZANIE: Dodaj poniższy endpoint do app.py
(najlepiej zaraz po istniejącym /motobot-prototype/api/analyze_query)

============================================================
"""

# === NOWY ENDPOINT DLA ELEKTRO - BRAKUJĄCY ROUTE! ===
@app.route('/elektrobot-prototype/api/analyze_query', methods=['POST'])
@limiter.limit("100/minute")
def elektro_analyze_query():
    """
    ELEKTRO VERSION - Doktryna Cierpliwego Nasłuchu
    Wywołany po 800ms pauzy - wysyła event do TCD
    """
    import uuid
    request_id = str(uuid.uuid4())[:8]
    
    try:
        data = request.get_json()
        query = data.get('query', '').strip()
        search_type = data.get('type', 'products')
        
        # Odbierz dane geolokalizacji z frontendu (jeśli dostępne)
        visitor_city = data.get('city', 'Unknown')
        visitor_country = data.get('country', 'Unknown')
        visitor_org = data.get('org', 'Unknown')
        
        # 🎯 PASSIVE RADAR: Odbierz session_id
        session_id = data.get('session_id', None)
        
        print(f"[ELEKTRO FINAL ANALYSIS][REQ:{request_id}] Query: '{query}' | Type: {search_type} | Geo: {visitor_city}, {visitor_country} | Session: {session_id}")
        
        # RODO: Sanityzuj query
        sanitized_query = scrub_pii(query)
        if sanitized_query != query:
            print(f"[RODO][REQ:{request_id}] PII scrubbed in elektro_analyze_query")
            app.logger.warning(f"PII scrubbed in elektro_analyze_query")
        
        if len(sanitized_query) < 2:
            return jsonify({
                'status': 'success',
                'message': 'Query too short'
            })
        
        # Analiza przez ELEKTRO bota
        if ELEKTRO_BOT_AVAILABLE and elektro_bot:
            result = elektro_bot.get_fuzzy_product_matches(
                sanitized_query, None, limit=6, analyze_intent=True
            )
            
            if isinstance(result, tuple) and len(result) == 4:
                products, confidence_level, suggestion_type, analysis = result
                category = 'elektronika'
            else:
                confidence_level = 'HIGH'
                category = 'elektronika'
        else:
            # Fallback do moto
            confidence_level = 'HIGH'
            category = 'unknown'
        
        # Mapowanie confidence → decision (ELEKTRO rules)
        decision_mapping = ELEKTRO_DECISION_MAPPING  # Użyj mappingu dla ELEKTRO!
        decision = decision_mapping.get(confidence_level, 'ZNALEZIONE PRODUKTY')
        
        # Oblicz wartość dla utraconych okazji
        potential_value = 0
        if decision == 'UTRACONE OKAZJE':
            potential_value = calculate_lost_value_internal(sanitized_query, source='elektro')
        
        # ZAPISZ DO BAZY
        event_id = DatabaseManager.add_event(
            sanitized_query,
            decision,
            'Finalne zapytanie użytkownika (ELEKTRO)',
            category,
            'elektro',
            potential_value,
            f'Analiza po 800ms pauzy - confidence: {confidence_level}'
        )
        
        # === PERSISTENT STORAGE (ELEKTRO) ===
        session_id = request.cookies.get('visitor_session_id')
        organization = visitor_org if visitor_org != 'Unknown' else 'Unknown Visitor'
        city = visitor_city if visitor_city != 'Unknown' else 'Unknown'
        country = visitor_country if visitor_country != 'Unknown' else 'Unknown'
        if session_id:
            visitor_ctx = get_visitor_context(session_id)
            if visitor_ctx and visitor_ctx != 'Unknown':
                parts = visitor_ctx.split(', ')
                organization = parts[0] if len(parts) >= 1 else organization
                city = parts[1] if len(parts) >= 2 else city
                country = parts[2] if len(parts) >= 3 else country
        company_data = save_company_data(organization, city, country, sanitized_query, decision)
        if company_data and company_data['engagement_score'] >= 30 and decision == 'ZNALEZIONE PRODUKTY':
            save_hot_lead(organization, sanitized_query, company_data['engagement_score'])
        save_log_entry(decision, organization, sanitized_query)
        
        # WYŚLIJ PRZEZ WEBSOCKET DO TCD
        event_data = {
            'id': event_id,
            'timestamp': datetime.now().strftime('%H:%M:%S'),
            'query_text': sanitized_query,
            'decision': decision,
            'details': 'Finalne zapytanie użytkownika (ELEKTRO)',
            'category': category,
            'potential_value': potential_value,
            'explanation': f'Analiza po 800ms pauzy - confidence: {confidence_level}'
        }
        
        # Dane geolokalizacji już odebrane z frontendu (visitor_city, visitor_country, visitor_org)
        # Nie trzeba ponownie odpytywać ipinfo.io
        
        # Sformatuj dane dla live_feed_update
        feed_data = {
            'timestamp': datetime.now().strftime('%H:%M:%S'),
            'query': sanitized_query,
            'classification': decision,
            'estimatedValue': potential_value,
            'city': visitor_city,
            'country': visitor_country,
            'organization': visitor_org,
            'sessionId': session_id,  # 🎯 PASSIVE RADAR: Dodane!
            'anonymous': True,
            'source': 'elektro'
        }
        
        # 🎯 PASSIVE RADAR FIX 2: UPDATE STATUS W BAZIE (ELEKTRO)
        if session_id:
            try:
                conn = sqlite3.connect(DATABASE_NAME)
                cursor = conn.cursor()
                
                cursor.execute('''
                    UPDATE visitor_sessions 
                    SET radar_status = 'Pisze',
                        last_activity = CURRENT_TIMESTAMP
                    WHERE session_id = ?
                ''', (session_id,))
                
                conn.commit()
                conn.close()
                print(f"🎯 PASSIVE RADAR [ELEKTRO]: Status updated to 'Pisze' for session {session_id}")
                
            except Exception as db_error:
                print(f"🎯 PASSIVE RADAR [ELEKTRO]: Błąd update statusu: {db_error}")
        
        # WRESZCIE: WYŚLIJ DO DASHBOARDU (broadcast do obu roomów)
        server_ts_ms = int(time.time() * 1000)
        event_data['server_sent_at'] = server_ts_ms
        print(f"[WS EMIT][ELEKTRO][REQ:{request_id}] live_feed_update id={event_id} sent_at={server_ts_ms} city={visitor_city}")
        app.logger.info(f"[WS EMIT][ELEKTRO] live_feed_update id={event_id} sent_at={server_ts_ms}")
        
        socketio.emit('live_feed_update', feed_data, room='client_demo')
        socketio.emit('live_feed_update', feed_data, room='admin_dashboard')
        
        print(f"[ELEKTRO FINAL ANALYSIS][REQ:{request_id}] Saved to TCD: {sanitized_query} -> {decision} (value: {potential_value})")
        
        return jsonify({
            'status': 'success',
            'decision': decision,
            'confidence_level': confidence_level,
            'event_id': event_id
        })
        
    except Exception as e:
        print(f"[ERROR] Elektro final analysis error: {e}")
        app.logger.error(f"Elektro final analysis error: {e}", exc_info=True)
        import traceback
        traceback.print_exc()
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500


"""
============================================================
⚠️ WAŻNE: Upewnij się że funkcja calculate_lost_value_internal
           przyjmuje parametr source='elektro' !
           
Jeśli nie, zamień jej definicję na wersję z app_patch.py
============================================================
"""    


@app.route('/api/admin/save-state', methods=['POST'])
@require_admin_access
def save_admin_state():
    """
    Zapisuje stan admin dashboardu do bazy danych
    
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


@app.route('/api/admin/load-state/<state_key>')
@require_admin_access
def load_admin_state(state_key):
    """
    Ładuje stan admin dashboardu z bazy danych
    
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
            # Brak danych - zwróć pustą strukturę
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
    
@app.route('/tech')
def tech_docs():
    return render_template('tech.html')    

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

@app.route('/api/reset_demo', methods=['POST'])
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
            'standard',
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
        server_ts_ms = int(time.time() * 1000)
        event_data['server_sent_at'] = server_ts_ms
        app.logger.info(f"[WS EMIT][RECEIVE_EVENT] new_event id={event_id} sent_at={server_ts_ms}")
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
        'version': '5.1-patient-listening-RODO',
        'features': {
            'intent_analysis': True,
            'lost_demand_tracking': True,
            'typo_correction': True,
            'confidence_scoring': True,
            'luxury_brand_detection': True,
            'precision_reward': True,
            'dashboard_integration': True,
            'real_time_websocket': True,
            'debounce_800ms': True,
            'rodo_compliant': True,
            'pii_scrubbing': True,
            'ip_hashing': True
        },
        'session_active': 'cart' in session
    })

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

# === PDF REPORT FUNCTIONS ===
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
        
        # DEMO DATA - Elektronika Premium (High Volume)
        demo_data = {
            'client': client_info,
            'report_date': '13.10.2025',
            'total_lost_value': 82450,
            'total_products': 47,
            'total_volume_gross': 251150,
            'lost_products': [
                {'name': 'iPhone 15 Pro 256GB Natural', 'category': 'Smartfony', 'value': 97200, 'frequency': 18, 'unit_price': 5400},
                {'name': 'Laptop Dell XPS 15 (64GB RAM)', 'category': 'Laptopy', 'value': 64400, 'frequency': 7, 'unit_price': 9200},
                {'name': 'Dron DJI Mini 4 Pro', 'category': 'Drony', 'value': 38250, 'frequency': 9, 'unit_price': 4250},
                {'name': 'Samsung S24 Ultra (Kremowy)', 'category': 'Smartfony', 'value': 30500, 'frequency': 5, 'unit_price': 6100},
                {'name': 'Karta RTX 4080 Super', 'category': 'Komponenty PC', 'value': 20800, 'frequency': 4, 'unit_price': 5200},
            ],
            'recommendations': [
                'KRYTYCZNE: Natychmiastowe domówienie Apple - trend wzrostowy na iPhone 15 Pro (18 zapytań/tydzień)',
                'Wprowadzenie konfiguracji B2B dla Dell XPS (64GB RAM) - segment biznesowy wysokomarżowy',
                'Rozszerzenie oferty Dronów - sezonowy wzrost zainteresowania (Q4)',
            ]
        }
        
        # Generuj PDF HTML
        html_content = generate_pdf_html(demo_data)
        
        response = make_response(html_content)
        response.headers['Content-Type'] = 'text/html'
        response.headers['Content-Disposition'] = f'inline; filename="raport_utraconych_okazji_{client_id}.html"'
        
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
            <p><strong>Szacowana utracona marża (tygodniowo):</strong> <span class="value">{data['total_lost_value']:,} zł</span></p>
            <p><strong>Całkowity wolumen popytu brutto:</strong> {data.get('total_volume_gross', 0):,} zł</p>
            <p><strong>Liczba zidentyfikowanych produktów:</strong> {data['total_products']}</p>
            <p><strong>Status:</strong> Zweryfikowany przez Lost Demand Intelligence</p>
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
                <td>{product['category']}</td>
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
    
    html += f"""
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

# === RODO: PRIVACY POLICY ENDPOINT ===
@app.route('/privacy')
def privacy_policy():
    """Polityka Prywatności - zgodność z RODO"""
    return render_template('privacy.html', now=datetime.now())

@app.route('/api/opt-out', methods=['POST'])
def api_opt_out():
    """API endpoint dla opt-out użytkowników"""
    try:
        # W przyszłości: zapisz opt-out w bazie per IP/session
        # Na razie: obsługiwane przez localStorage w JS
        return jsonify({
            'status': 'success',
            'message': 'Tracking disabled successfully'
        })
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

# === HELPER FUNCTIONS ===
def extract_category_from_query(query):
    """Wyciąga kategorię z zapytania"""
    query_lower = query.lower()
    categories = ['klocki', 'filtry', 'amortyzatory', 'świece', 'akumulatory', 'oleje', 'tarcze']
    for category in categories:
        if category in query_lower:
            return category
    return 'inne'

def calculate_lost_value_internal(query, source='unknown'):
    """
    NAPRAWIONA v2.0: Szacuje REALISTYCZNĄ wartość utraconego popytu
    Drabina cenowa oparta na rzeczywistych cenach rynkowych Polski 2024
    
    Zakresy cenowe:
    MOTO: Ferrari/Porsche (2500-9000), Turbo/Skrzynia (1500-4000), Olej/Filtr (50-200)
    ELEKTRO: RTX 4090/Macbook (8000-22000), iPhone/Flagowce (3500-7500), Kable (50-300)
    """
    import random
    query_lower = query.lower()
    
    # ============================================
    # MOTORYZACJA - DRABINA CENOWA
    # ============================================
    
    # PREMIUM (2500 - 9000 PLN) - Luksusowe marki i drogie części
    moto_premium = [
        'ferrari', 'lamborghini', 'porsche', 'bentley', 'maserati', 'aston martin',
        'mclaren', 'bugatti', 'rolls-royce', 'maybach', 'koenigsegg',
        'turbo', 'turbosprężarka', 'skrzynia biegów', 'automatyczna', 'dsg', 'tiptronic',
        'silnik', 'głowica', 'blok silnika', 'wał korbowy', 'tłok'
    ]
    
    # HIGH (1500 - 4000 PLN) - Większe części zamienne
    moto_high = [
        'amortyzator', 'amortyzatory', 'zawieszenie', 'sprężyna', 'sprężyny',
        'sprzęgło', 'komplet sprzęgła', 'koło dwumasowe', 'docisk',
        'rozrząd', 'zestaw rozrządu', 'łańcuch rozrządu', 'pasek rozrządu',
        'alternator', 'rozrusznik', 'pompa wtryskowa', 'wtryskiwacz',
        'chłodnica', 'intercooler', 'katalizator', 'dpf', 'fap'
    ]
    
    # MEDIUM (300 - 1000 PLN) - Standardowe części
    moto_medium = [
        'klocki', 'tarcze', 'hamulcowe', 'tarcza hamulcowa', 'bęben',
        'wahacz', 'drążek', 'stabilizator', 'łożysko', 'piasta', 'przegub',
        'akumulator', 'akumulatory', 'świece', 'cewka zapłonowa', 'moduł zapłonu',
        'pompa wody', 'termostat', 'czujnik', 'sonda lambda'
    ]
    
    # LOW (50 - 200 PLN) - Drobne części i eksploatacja
    moto_low = [
        'filtr', 'filtry', 'oleju', 'powietrza', 'paliwa', 'kabinowy',
        'olej', 'oleje', 'płyn', 'płyny', 'antyfriz', 'hamulcowy',
        'uszczelka', 'oring', 'simering', 'żarówka', 'bezpiecznik', 'przekaźnik'
    ]
    
    # ============================================
    # ELEKTRONIKA - DRABINA CENOWA
    # ============================================
    
    # PREMIUM (8000 - 22000 PLN) - Topowe produkty
    elektro_premium = [
        'rtx 4090', 'rtx 4080', 'rtx 5090', 'rtx 5080', 'rtx 4090 ti',
        'macbook pro', 'macbook 16', 'm3 max', 'm3 pro', 'm4 pro', 'm4 max',
        'iphone 15 pro max', 'iphone 16 pro max', 'iphone 16 ultra',
        'oled 77', 'oled 83', 'oled 88', 'neo qled 85', '8k samsung', '8k lg',
        'sony a1', 'sony a7r', 'sony a9', 'leica q3', 'hasselblad'
    ]
    
    # HIGH (3500 - 7500 PLN) - Flagowce
    elektro_high = [
        'iphone 14', 'iphone 15', 'iphone 16', 'iphone pro',
        'galaxy s24', 'galaxy s23', 'samsung ultra', 'galaxy z fold', 'galaxy z flip',
        'pixel 8', 'pixel 9', 'pixel pro',
        'macbook air', 'macbook m2', 'macbook m3', 'dell xps', 'thinkpad x1',
        'rtx 4070', 'rtx 4060', 'rtx 3080', 'rtx 3090',
        'ps5', 'playstation 5', 'xbox series x', 'ps5 pro',
        'sony wh-1000', 'airpods max', 'bose 700', 'bose qc ultra'
    ]
    
    # MEDIUM (500 - 2000 PLN) - Mid-range
    elektro_medium = [
        'laptop', 'notebook', 'komputer', 'desktop', 'all-in-one',
        'telewizor', 'tv', 'smart tv', '55 cali', '65 cali', '50 cali',
        'monitor', 'monitor gaming', '27 cali', '32 cali', '34 cali',
        'tablet', 'ipad', 'ipad air', 'galaxy tab', 'tab s9',
        'słuchawki', 'headphones', 'airpods', 'airpods pro', 'earbuds', 'buds',
        'głośnik', 'soundbar', 'jbl', 'marshall', 'bose soundlink',
        'konsola', 'nintendo switch', 'switch oled', 'xbox series s', 'ps4',
        'aparat', 'canon', 'nikon', 'sony alpha', 'fujifilm'
    ]
    
    # LOW (50 - 300 PLN) - Akcesoria
    elektro_low = [
        'kabel', 'ładowarka', 'charger', 'powerbank', 'adapter', 'zasilacz',
        'etui', 'case', 'pokrowiec', 'folia', 'szkło', 'hartowane',
        'myszka', 'mysz', 'klawiatura', 'keyboard', 'mata', 'podkładka',
        'pendrive', 'karta pamięci', 'sd card', 'microsd',
        'hub', 'przejściówka', 'usb', 'usb-c', 'hdmi', 'splitter'
    ]
    
    # ============================================
    # LOGIKA WYKRYWANIA BRANŻY
    # ============================================
    
    # Słowa kluczowe wykrywające elektronikę
    elektro_indicators = [
        'iphone', 'samsung', 'galaxy', 'macbook', 'laptop', 'rtx', 'nvidia', 'geforce',
        'słuchawki', 'telewizor', 'tv', 'monitor', 'tablet', 'ipad', 'konsola', 
        'ps5', 'ps4', 'xbox', 'nintendo', 'switch', 'pixel', 'xiaomi', 'redmi',
        'airpods', 'bluetooth', 'smartwatch', 'apple watch', 'garmin',
        'klawiatura', 'myszka', 'głośnik', 'soundbar', 'projektor'
    ]
    
    # Słowa kluczowe wykrywające motoryzację
    moto_indicators = [
        'klocki', 'filtr', 'olej', 'amortyzator', 'świece', 'rozrząd', 'sprzęgło',
        'hamulce', 'tarcze', 'zawieszenie', 'wahacz', 'bmw', 'audi', 'mercedes',
        'volkswagen', 'vw', 'toyota', 'ford', 'opel', 'skoda', 'seat', 'renault',
        'ferrari', 'porsche', 'turbo', 'silnik', 'skrzynia', 'akumulator',
        'czujnik', 'lambda', 'katalizator', 'dpf', 'egr'
    ]
    
    is_elektro = any(kw in query_lower for kw in elektro_indicators)
    is_moto = any(kw in query_lower for kw in moto_indicators)
    
    # ============================================
    # OBLICZANIE WARTOŚCI
    # ============================================
    
    # ELEKTRONIKA
    if is_elektro or source == 'elektro':
        if any(kw in query_lower for kw in elektro_premium):
            return random.randint(8000, 22000)
        if any(kw in query_lower for kw in elektro_high):
            return random.randint(3500, 7500)
        if any(kw in query_lower for kw in elektro_medium):
            return random.randint(500, 2000)
        if any(kw in query_lower for kw in elektro_low):
            return random.randint(50, 300)
        # Default dla elektroniki - mid-range
        return random.randint(800, 2500)
    
    # MOTORYZACJA (lub nieznana branża)
    if is_moto or source == 'moto' or True:  # True = fallback
        if any(kw in query_lower for kw in moto_premium):
            return random.randint(2500, 9000)
        if any(kw in query_lower for kw in moto_high):
            return random.randint(1500, 4000)
        if any(kw in query_lower for kw in moto_medium):
            return random.randint(300, 1000)
        if any(kw in query_lower for kw in moto_low):
            return random.randint(50, 200)
        # Default dla motoryzacji - medium
        return random.randint(300, 800)

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
    """Klient podłączył się do WebSocket - Z AUTENTYKACJĄ"""
    from flask_socketio import join_room, disconnect
    from flask import request as flask_request
    
    print('[WEBSOCKET] Client connected')
    
    # === SPRAWDŹ REFERER - demo page zawsze do client_demo ===
    referer = flask_request.headers.get('Referer', '')
    is_demo_page = '/demo' in referer or '/motobot-prototype' in referer or '/elektrobot-prototype' in referer
    
    # === RODO: ZABEZPIECZENIE WEBSOCKET ===
    if not current_user.is_authenticated:
        # Niezalogowany - sprawdź czy to demo page (dozwolone)
        if is_demo_page:
            # OK - publiczne demo
            join_room('client_demo')
            print('[WEBSOCKET] Anonymous user joined client_demo (public demo)')
            emit('connection_confirmed', {'message': 'Connected to Demo TCD', 'room': 'client'})
        else:
            # BLOKUJ - próba dostępu do admin dashboard bez logowania
            print('[WEBSOCKET] ⚠️ UNAUTHORIZED connection attempt - disconnecting')
            app.logger.warning(f"Unauthorized WebSocket connection attempt from {flask_request.remote_addr}")
            disconnect()
            return
    else:
        # Zalogowany - DEMO PAGE zawsze idzie do client_demo, nawet dla admina
        if is_demo_page:
            join_room('client_demo')
            print(f'[WEBSOCKET] User {current_user.username} (admin={current_user.role in ["admin","debug"]}) joined client_demo room (demo page)')
            emit('connection_confirmed', {'message': 'Connected to Demo TCD', 'room': 'client'})
        elif current_user.role in ['admin', 'debug']:
            join_room('admin_dashboard')
            print(f'[WEBSOCKET] Admin {current_user.username} joined admin_dashboard room')
            emit('connection_confirmed', {'message': 'Connected to Admin Dashboard', 'room': 'admin'})
            
            # 🎯 PASSIVE RADAR FIX 1C: Wyślij ostatnie wizyty z bazy
            try:
                conn = sqlite3.connect(DATABASE_NAME)
                cursor = conn.cursor()
                
                cursor.execute('''
                    SELECT session_id, radar_company, city, country, 
                           radar_status, entry_time, referrer
                    FROM visitor_sessions
                    WHERE radar_company IS NOT NULL
                    ORDER BY entry_time DESC
                    LIMIT 5
                ''')
                
                recent_visits = []
                for row in cursor.fetchall():
                    sess_id, company, city, country, status, entry_time, referrer = row
                    
                    # Format timestamp
                    try:
                        dt = datetime.strptime(entry_time, '%Y-%m-%d %H:%M:%S')
                        time_str = dt.strftime('%H:%M')
                    except:
                        time_str = entry_time[:5] if entry_time else '00:00'
                    
                    recent_visits.append({
                        'session_id': sess_id,
                        'company': company,
                        'city': city,
                        'country': country,
                        'status': status or 'Przegląda',
                        'timestamp': time_str,
                        'referrer': referrer or 'direct',
                        'source': 'moto',
                        'anonymous': False
                    })
                
                conn.close()
                
                # Wyślij każdą wizytę jako separate event
                for visit in reversed(recent_visits):  # Oldest first
                    emit('new_visitor', visit)
                
                print(f"🎯 PASSIVE RADAR: Wysłano {len(recent_visits)} wizyt z bazy do {current_user.username}")
                
            except Exception as db_error:
                print(f"🎯 PASSIVE RADAR: Błąd ładowania wizyt z bazy: {db_error}")
        else:
            join_room('client_demo')
            print(f'[WEBSOCKET] Client {current_user.username} joined client_demo room')
            emit('connection_confirmed', {'message': 'Connected to Demo TCD', 'room': 'client'})

@socketio.on('disconnect')
def handle_disconnect():
    """Klient rozłączył się z WebSocket""" 
    print('[WEBSOCKET] Client disconnected')

# 🟢 PASSIVE RADAR: Handler dla statusu "Pisze"
@socketio.on('visitor_typing')
def handle_visitor_typing(data):
    """
    🟢 PASSIVE RADAR: Update status na "Pisze" gdy klient wpisuje tekst
    """
    try:
        session_id = data.get('session_id')
        
        if not session_id:
            return
        
        # Update status w bazie
        try:
            conn = sqlite3.connect(DATABASE_NAME)
            cursor = conn.cursor()
            
            cursor.execute('''
                UPDATE visitor_sessions 
                SET radar_status = 'Pisze'
                WHERE session_id = ?
            ''', (session_id,))
            
            conn.commit()
            conn.close()
            
        except Exception as db_error:
            print(f"🟢 PASSIVE RADAR DB ERROR: {db_error}")
        
        # Broadcast event do dashboardów
        typing_data = {
            'session_id': session_id,
            'status': 'Pisze',
            'timestamp': datetime.now().strftime('%H:%M')
        }
        
        emit('visitor_status_changed', typing_data, broadcast=True)
        
    except Exception as e:
        print(f"🟢 PASSIVE RADAR ERROR: {e}")

# 🔴 PASSIVE RADAR FIX 2: Handler dla client_disconnected
@socketio.on('client_disconnected')
def handle_client_disconnected(data):
    """
    🔴 PASSIVE RADAR: Obsługa wyjścia klienta ze strony
    Update status na "Opuścił stronę" w bazie i dashboardzie
    """
    try:
        session_id = data.get('session_id')
        timestamp = data.get('timestamp')
        session_duration = data.get('session_duration', 0)
        message_count = data.get('message_count', 0)
        
        if not session_id:
            print("🔴 PASSIVE RADAR: No session_id in disconnect event")
            return
        
        print(f"🔴 PASSIVE RADAR: Client disconnected - Session: {session_id}, Duration: {session_duration}ms")
        
        # Update status w bazie
        try:
            conn = sqlite3.connect(DATABASE_NAME)
            cursor = conn.cursor()
            
            cursor.execute('''
                UPDATE visitor_sessions 
                SET radar_status = 'Opuścił',
                    exit_time = CURRENT_TIMESTAMP,
                    session_duration = ?,
                    total_messages = ?,
                    is_active = 0
                WHERE session_id = ?
            ''', (session_duration // 1000, message_count, session_id))  # Convert ms to seconds
            
            conn.commit()
            conn.close()
            print(f"🔴 PASSIVE RADAR: Status updated to 'Opuścił' for session {session_id}")
            
        except Exception as db_error:
            print(f"🔴 PASSIVE RADAR DB ERROR: {db_error}")
            import traceback
            traceback.print_exc()
        
        # Broadcast event do dashboardów
        disconnect_data = {
            'session_id': session_id,
            'status': 'Opuścił',
            'timestamp': datetime.now().strftime('%H:%M')
        }
        
        emit('visitor_disconnected', disconnect_data, broadcast=True)
        print(f"🔴 PASSIVE RADAR: Broadcast 'visitor_disconnected' - {session_id}")
        
    except Exception as e:
        print(f"🔴 PASSIVE RADAR ERROR: {e}")
        import traceback
        traceback.print_exc()

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



# ==== ZADANIE 2.2: WEBSOCKET HANDLER DLA VISITOR_EVENT ====
@socketio.on('visitor_event')
def handle_visitor_event_websocket(data):
    """
    Handler WebSocket dla visitor_event
    WYŁĄCZONY - duplikuje eventy z /api/analyze_query
    """
    # Cała funkcjonalność przeniesiona do /api/analyze_query
    # Ten handler nie jest już używany aby uniknąć duplikacji eventów
    pass

# ==== 🎯 PASSIVE RADAR: HANDLER DLA CLIENT_CONNECTED ====
@socketio.on('client_connected')
def handle_client_connected(data):
    """
    🎯 PASSIVE RADAR: Obsługa wejścia klienta na stronę
    Wykrywa firmę i wysyła event 'new_visitor' do dashboardu
    """
    try:
        session_id = data.get('session_id')
        timestamp = data.get('timestamp')
        city = data.get('city', 'Unknown')
        country = data.get('country', 'Unknown')
        organization = data.get('organization', 'Unknown')
        referrer = data.get('referrer', 'direct')
        user_agent = data.get('user_agent', 'Unknown')
        anonymous = data.get('anonymous', False)
        source = data.get('source', 'moto')
        
        print(f"🎯 PASSIVE RADAR: Client connected - Session: {session_id}")
        
        # Mockowana detekcja firmy (w produkcji możesz użyć prawdziwego IP lookup)
        company_pool = [
            'PKN Orlen', 'Comarch', 'Budimex', 'PGE', 'Allegro', 
            'CD Projekt', 'LPP', 'Dino Polska', 'Bank Pekao', 'mBank'
        ]
        
        # Jeśli mamy organization z IP lookup, użyj go
        # W przeciwnym wypadku losuj z puli (mockowanie)
        if organization and organization != 'Unknown':
            detected_company = organization
        else:
            import random
            detected_company = random.choice(company_pool)
        
        # Timestamp w formacie HH:MM
        from datetime import datetime
        dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
        time_str = dt.strftime('%H:%M')
        
        # 🎯 PASSIVE RADAR FIX 1: ZAPISZ W BAZIE NAJPIERW!
        try:
            conn = sqlite3.connect(DATABASE_NAME)
            cursor = conn.cursor()
            
            # Sprawdź czy sesja już istnieje
            cursor.execute('SELECT id FROM visitor_sessions WHERE session_id = ?', (session_id,))
            existing = cursor.fetchone()
            
            if existing:
                # Aktualizuj istniejącą sesję
                cursor.execute('''
                    UPDATE visitor_sessions 
                    SET radar_status = ?, 
                        radar_company = ?,
                        last_activity = CURRENT_TIMESTAMP
                    WHERE session_id = ?
                ''', ('Przegląda', detected_company, session_id))
            else:
                # Nowa sesja - INSERT
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
            print(f"🎯 PASSIVE RADAR: Zapisano w bazie - Session: {session_id}, Company: {detected_company}")
            
        except Exception as db_error:
            print(f"🎯 PASSIVE RADAR DB ERROR: {db_error}")
            import traceback
            traceback.print_exc()
        
        # Wyślij event 'new_visitor' do wszystkich dashboardów
        visitor_data = {
            'session_id': session_id,
            'timestamp': time_str,
            'company': detected_company,
            'city': city,
            'country': country,
            'status': 'Przegląda',
            'referrer': referrer,
            'source': source,
            'anonymous': anonymous
        }
        
        emit('new_visitor', visitor_data, broadcast=True)
        print(f"🎯 PASSIVE RADAR: Broadcast 'new_visitor' - {detected_company}")
        
    except Exception as e:
        print(f"🎯 PASSIVE RADAR ERROR: {e}")
        import traceback
        traceback.print_exc()

# === VISITOR TRACKING SYSTEM ===

def ensure_visitor_tables_exist():
    """Tworzy tabele dla visitor tracking jeśli nie istnieją - RODO COMPLIANT"""
    conn = sqlite3.connect(DATABASE_NAME)
    cursor = conn.cursor()
    
    # Check if table exists
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='visitor_sessions'")
    table_exists = cursor.fetchone() is not None
    
    if table_exists:
        # Table exists - check columns and add missing ones
        cursor.execute("PRAGMA table_info(visitor_sessions)")
        columns = [col[1] for col in cursor.fetchall()]
        
        # Add new columns if missing
        new_columns = {
            'ip_hash': 'TEXT',
            'ip_masked': 'TEXT',
            'device_type': 'TEXT',
            'os': 'TEXT',
            'browser': 'TEXT',
            'viewport_category': 'TEXT',
            'anonymous_mode': 'BOOLEAN DEFAULT FALSE',
            'asn': 'TEXT',
            'radar_status': 'TEXT DEFAULT "Przegląda"',  # 🎯 PASSIVE RADAR
            'radar_company': 'TEXT'  # 🎯 PASSIVE RADAR - mockowana lub prawdziwa firma
        }
        
        for col_name, col_type in new_columns.items():
            if col_name not in columns:
                try:
                    cursor.execute(f'ALTER TABLE visitor_sessions ADD COLUMN {col_name} {col_type}')
                    print(f"[DATABASE] Added column: {col_name}")
                except Exception as e:
                    print(f"[DATABASE] Column {col_name} error: {e}")
        
        # Create indexes (with error handling)
        indexes = [
            ('idx_visitor_sessions_entry_time', 'entry_time'),
            ('idx_visitor_sessions_org', 'organization'),
            ('idx_visitor_sessions_hash', 'ip_hash')
        ]
        
        for idx_name, idx_column in indexes:
            try:
                cursor.execute(f'CREATE INDEX IF NOT EXISTS {idx_name} ON visitor_sessions({idx_column})')
            except Exception as e:
                print(f"[DATABASE] Index {idx_name} warning: {e}")
        
    else:
        # Table doesn't exist - create new RODO-compliant table
        cursor.execute('''
            CREATE TABLE visitor_sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT UNIQUE NOT NULL,
                
                -- RODO: Anonimizowane IP
                ip_hash TEXT,
                ip_masked TEXT,
                
                -- Podstawowe dane
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
                timezone TEXT,
                
                -- Dane organizacji
                organization TEXT,
                isp TEXT,
                asn TEXT,
                
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
                device_type TEXT,
                os TEXT,
                browser TEXT,
                viewport_category TEXT,
                language TEXT,
                
                -- RODO flags
                anonymous_mode BOOLEAN DEFAULT FALSE,
                
                -- Status
                is_active BOOLEAN DEFAULT TRUE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Create indexes
        cursor.execute('CREATE INDEX idx_visitor_sessions_entry_time ON visitor_sessions(entry_time)')
        cursor.execute('CREATE INDEX idx_visitor_sessions_org ON visitor_sessions(organization)')
        cursor.execute('CREATE INDEX idx_visitor_sessions_hash ON visitor_sessions(ip_hash)')
        
        print("[DATABASE] Created new visitor_sessions table (GDPR Compliant)")
    
    conn.commit()
    conn.close()
    print("[DATABASE] Visitor tracking tables initialized (GDPR Compliant)")

@app.route('/api/visitor-tracking', methods=['POST'])
@limiter.limit("100/minute")  # RODO: Rate limiting przeciw spam
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

def handle_session_start(session_id, data):
    """Obsługuje rozpoczęcie sesji odwiedzającego - RODO COMPLIANT"""
    try:
        conn = sqlite3.connect(DATABASE_NAME)
        cursor = conn.cursor()
        
        # FIX: Parsuj entry_time i usuń timezone
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
        
        # Sprawdź Do Not Track
        anonymous_mode = data.get('anonymous_mode', False)
        
        # === ZAPISZ SESJĘ (BEZ raw IP!) ===
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
    """Obsługuje zapytanie do bota - KLUCZOWY event dla TCD - RODO COMPLIANT"""
    try:
        # === RODO: SANITYZUJ QUERY PRZED ZAPISEM (BACKEND DEFENSE) ===
        raw_query = data.get('query', '')
        sanitized_query = scrub_pii(raw_query)
        source = data.get('source', 'moto')  # 🔥 NEW: detect source
        
        # 🔥 WYBIERZ WŁAŚCIWEGO BOTA
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
        
        # Analizuj SANITIZED query przez właściwego bota
        analysis = active_bot.analyze_query_intent(sanitized_query)
        
        # Użyj decision_mapping wybranego na podstawie źródła
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


# ============================================
# PERSISTENT STORAGE - COMPANIES, HOT_LEADS, LOG_HISTORY
# ============================================

def init_persistent_storage_tables():
    """Tworzy tabele dla persistent storage"""
    try:
        conn = sqlite3.connect(DATABASE_NAME)
        cursor = conn.cursor()
        
        cursor.execute('''CREATE TABLE IF NOT EXISTS companies (
            id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT UNIQUE NOT NULL,
            city TEXT, country TEXT, first_visit TIMESTAMP NOT NULL, last_visit TIMESTAMP NOT NULL,
            total_queries INTEGER DEFAULT 0, high_intent_queries INTEGER DEFAULT 0,
            lost_opportunities INTEGER DEFAULT 0, engagement_score INTEGER DEFAULT 0,
            queries_json TEXT, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_companies_name ON companies(name)')
        
        cursor.execute('''CREATE TABLE IF NOT EXISTS hot_leads (
            id INTEGER PRIMARY KEY AUTOINCREMENT, company TEXT NOT NULL, query TEXT NOT NULL,
            score INTEGER NOT NULL, timestamp TIMESTAMP NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_hot_leads_timestamp ON hot_leads(timestamp)')
        
        cursor.execute('''CREATE TABLE IF NOT EXISTS log_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT, log_type TEXT NOT NULL, company TEXT NOT NULL,
            query TEXT NOT NULL, timestamp TIMESTAMP NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_log_history_timestamp ON log_history(timestamp)')
        
        conn.commit()
        conn.close()
        print("[DATABASE] ✅ Persistent storage tables OK")
    except Exception as e:
        print(f"[DATABASE] ⚠️ Persistent storage error: {e}")

def save_company_data(organization, city, country, query, decision):
    """Zapisuje/aktualizuje firmę"""
    try:
        conn = sqlite3.connect(DATABASE_NAME)
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM companies WHERE name = ?', (organization,))
        existing = cursor.fetchone()
        
        if existing:
            queries_json = existing[10] or '[]'
            queries = json.loads(queries_json)
            queries.append({'text': query, 'timestamp': datetime.now().isoformat(), 'decision': decision})
            total_queries = existing[6] + 1
            high_intent = existing[7] + (1 if decision == 'ZNALEZIONE PRODUKTY' else 0)
            lost_opp = existing[8] + (1 if decision == 'UTRACONE OKAZJE' else 0)
            engagement_score = min((total_queries * 10) + (high_intent * 20) + (lost_opp * 10), 100)
            
            cursor.execute('''UPDATE companies SET last_visit = ?, total_queries = ?, 
                high_intent_queries = ?, lost_opportunities = ?, engagement_score = ?, 
                queries_json = ?, updated_at = ? WHERE name = ?''',
                (datetime.now(), total_queries, high_intent, lost_opp, engagement_score, 
                json.dumps(queries), datetime.now(), organization))
            conn.commit()
            conn.close()
            print(f"[COMPANIES] ✅ Updated: {organization} (score: {engagement_score})")
            return {'name': organization, 'engagement_score': engagement_score, 'is_new': False}
        else:
            now = datetime.now()
            queries = [{'text': query, 'timestamp': now.isoformat(), 'decision': decision}]
            high_intent = 1 if decision == 'ZNALEZIONE PRODUKTY' else 0
            lost_opp = 1 if decision == 'UTRACONE OKAZJE' else 0
            engagement_score = 10
            
            cursor.execute('''INSERT INTO companies (name, city, country, first_visit, last_visit,
                total_queries, high_intent_queries, lost_opportunities, engagement_score, queries_json)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                (organization, city, country, now, now, 1, high_intent, lost_opp, engagement_score, json.dumps(queries)))
            conn.commit()
            conn.close()
            print(f"[COMPANIES] ✅ NEW: {organization}")
            return {'name': organization, 'engagement_score': engagement_score, 'is_new': True}
    except Exception as e:
        print(f"[ERROR] save_company_data: {e}")
        return None

def save_hot_lead(company, query, score):
    """Zapisuje hot lead"""
    try:
        conn = sqlite3.connect(DATABASE_NAME)
        cursor = conn.cursor()
        cursor.execute('INSERT INTO hot_leads (company, query, score, timestamp) VALUES (?, ?, ?, ?)',
                      (company, query, score, datetime.now()))
        conn.commit()
        conn.close()
        print(f"[HOT_LEADS] 🔥 {company} (score: {score})")
        return True
    except Exception as e:
        print(f"[ERROR] save_hot_lead: {e}")
        return False

def save_log_entry(log_type, company, query):
    """Zapisuje log"""
    try:
        conn = sqlite3.connect(DATABASE_NAME)
        cursor = conn.cursor()
        cursor.execute('INSERT INTO log_history (log_type, company, query, timestamp) VALUES (?, ?, ?, ?)',
                      (log_type, company, query, datetime.now()))
        conn.commit()
        conn.close()
        return True
    except Exception as e:
        print(f"[ERROR] save_log_entry: {e}")
        return False

def get_all_companies():
    """Pobiera firmy z bazy"""
    try:
        conn = sqlite3.connect(DATABASE_NAME)
        cursor = conn.cursor()
        cursor.execute('''SELECT name, city, country, first_visit, last_visit, total_queries,
            high_intent_queries, lost_opportunities, engagement_score, queries_json
            FROM companies ORDER BY last_visit DESC''')
        rows = cursor.fetchall()
        conn.close()
        companies = []
        for row in rows:
            queries = json.loads(row[9]) if row[9] else []
            companies.append({
                'name': row[0], 'city': row[1], 'country': row[2],
                'firstVisit': row[3], 'lastVisit': row[4], 'totalQueries': row[5],
                'highIntentQueries': row[6], 'lostOpportunities': row[7],
                'engagementScore': row[8], 'queries': queries
            })
        return companies
    except Exception as e:
        print(f"[ERROR] get_all_companies: {e}")
        return []

def get_hot_leads(limit=50):
    """Pobiera hot leads"""
    try:
        conn = sqlite3.connect(DATABASE_NAME)
        cursor = conn.cursor()
        cursor.execute('SELECT company, query, score, timestamp FROM hot_leads ORDER BY timestamp DESC LIMIT ?', (limit,))
        rows = cursor.fetchall()
        conn.close()
        return [{'company': r[0], 'query': r[1], 'score': r[2], 'timestamp': r[3]} for r in rows]
    except Exception as e:
        print(f"[ERROR] get_hot_leads: {e}")
        return []

def get_log_history(limit=100):
    """Pobiera logi"""
    try:
        conn = sqlite3.connect(DATABASE_NAME)
        cursor = conn.cursor()
        cursor.execute('SELECT log_type, company, query, timestamp FROM log_history ORDER BY timestamp DESC LIMIT ?', (limit,))
        rows = cursor.fetchall()
        conn.close()
        return [{'type': r[0], 'company': r[1], 'query': r[2], 'timestamp': r[3]} for r in rows]
    except Exception as e:
        print(f"[ERROR] get_log_history: {e}")
        return []

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

# === EMERGENCY DATABASE FIX ===
@app.route('/api/admin/fix-database-now')
@require_admin_access
def fix_database_now():
    """Endpoint ratunkowy do stworzenia brakującej tabeli"""
    try:
        conn = sqlite3.connect(DATABASE_NAME)
        cursor = conn.cursor()
        
        # 1. Stwórz tabelę admin_dashboard_state
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS admin_dashboard_state (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                state_key TEXT UNIQUE NOT NULL,
                state_data TEXT NOT NULL,
                updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # 2. Stwórz index
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_state_key ON admin_dashboard_state(state_key)')
        
        conn.commit()
        conn.close()
        
        return jsonify({
            'status': 'success', 
            'message': '✅ Tabela admin_dashboard_state została stworzona pomyślnie!'
        })
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500


# ================================================================
# URUCHAMIANIE PRODUKCYJNE (To wykona się ZAWSZE, nawet na Renderze)
# ================================================================

# 1. Upewnij się, że mamy kontekst aplikacji
with app.app_context():
    # 2. Inicjalizuj dane bota
    #bot.initialize_data()
    
    # 3. Inicjalizuj bazę danych dla Dashboardu
    DatabaseManager.initialize_database()
    
    # 4. Inicjalizuj tabele visitor tracking (RODO)
    ensure_visitor_tables_exist()
    
    # === RODO: CLEANUP OLD DATA ===
    try:
        # Clean old events (older than 30 days)
        conn = sqlite3.connect(DATABASE_NAME)
        cursor = conn.cursor()
        cutoff_date = (datetime.now() - timedelta(days=30)).strftime('%Y-%m-%d')
        cursor.execute('DELETE FROM events WHERE date(timestamp) < ?', (cutoff_date,))
        deleted_events = cursor.rowcount
        conn.commit()
        conn.close()
        if deleted_events > 0:
            print(f"[RODO CLEANUP] Cleared {deleted_events} old events")
        
        # Clean old visitor sessions (older than 30 days)
        deleted_sessions = cleanup_old_sessions()
        
    except Exception as e:
        print(f"[DATABASE] Error clearing old data: {e}")

    print("=" * 70)
    print("🎯 STUDIO ADEPT AI - DOKTRYNA CIERPLIWEGO NASŁUCHU v5.1")
    print("✅ Unified system started (Production Mode)")
    
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
            import sys
            subprocess.run([sys.executable, 'skrypthasla.py'])
    except:
        print("[STARTUP] Tabela users nie istnieje - tworzę...")
        import subprocess
        import sys
        subprocess.run([sys.executable, 'skrypthasla.py'])
    
    print("🔐 System Autoryzacji aktywny")
    
    # === KRYTYCZNE: NAPRAWA BAZY ===
    # To wywołanie jest teraz poza blokiem 'main', więc Gunicorn je wykona!
    init_database()


# ================================================================
# URUCHAMIANIE LOKALNE (Tylko przy python app.py)
# ================================================================

# === API ENDPOINTS - PERSISTENT STORAGE ===
@app.route('/api/admin/companies', methods=['GET'])
@require_admin_access
def api_get_companies():
    try:
        companies = get_all_companies()
        return jsonify({'status': 'success', 'companies': companies, 'count': len(companies)})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/admin/hot-leads', methods=['GET'])
@require_admin_access
def api_get_hot_leads():
    try:
        limit = request.args.get('limit', 50, type=int)
        hot_leads = get_hot_leads(limit)
        return jsonify({'status': 'success', 'hot_leads': hot_leads, 'count': len(hot_leads)})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/admin/log-history', methods=['GET'])
@require_admin_access
def api_get_log_history():
    try:
        limit = request.args.get('limit', 100, type=int)
        logs = get_log_history(limit)
        return jsonify({'status': 'success', 'logs': logs, 'count': len(logs)})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

if __name__ == '__main__':
    print("=" * 70)
    print("🎯 STUDIO ADEPT AI - LOCAL DEV MODE")
    print("=" * 70)
    
    # Uruchom serwer dev
    socketio.run(app, debug=True, host='0.0.0.0', port=5000)