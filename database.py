"""
Database managers and helper functions.
DatabaseManager, AdminDashboardStateManager, QueryIntentManager,
persistent storage (companies, hot_leads, log_history), visitor tracking tables.
"""
import sqlite3
import json
import re
from datetime import datetime, timedelta

from config import app, DATABASE_NAME
from privacy import scrub_pii


# ========================================
# DATABASE MANAGER (Events)
# ========================================

class DatabaseManager:
    """Manages SQLite database for the dashboard events"""

    @staticmethod
    def initialize_database():
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
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_timestamp ON events(timestamp)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_decision ON events(decision)')
        conn.commit()
        conn.close()
        print("[DATABASE] Events table initialized")

    @staticmethod
    def add_event(query_text, decision, details, category, brand_type, potential_value, explanation):
        """Add event with RODO scrubbing and deduplication (5s window)"""
        sanitized_query = scrub_pii(query_text)
        conn = sqlite3.connect(DATABASE_NAME)
        cursor = conn.cursor()
        try:
            cursor.execute('''
                SELECT id, timestamp FROM events
                WHERE query_text = ? AND decision = ? AND potential_value = ?
                AND timestamp >= datetime('now', '-5 seconds')
                ORDER BY timestamp DESC LIMIT 1
            ''', (sanitized_query, decision, potential_value))
            row = cursor.fetchone()
            if row:
                conn.close()
                app.logger.info(f"[DEDUP] Skipping duplicate event (id={row[0]}) [5s window]")
                return row[0]

            cursor.execute('''
                SELECT id, timestamp FROM events
                WHERE query_text = ? AND decision = ? AND potential_value = ?
                AND ABS(strftime('%s', timestamp) - strftime('%s', 'now')) <= 2
                ORDER BY timestamp DESC LIMIT 1
            ''', (sanitized_query, decision, potential_value))
            row2 = cursor.fetchone()
            if row2:
                conn.close()
                app.logger.info(f"[DEDUP] Skipping duplicate event (id={row2[0]}) [+-2s window]")
                return row2[0]
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
        conn = sqlite3.connect(DATABASE_NAME)
        cursor = conn.cursor()
        cursor.execute('''
            SELECT id, timestamp, query_text, decision, details, category,
                   brand_type, potential_value, explanation
            FROM events ORDER BY timestamp DESC LIMIT ?
        ''', (limit,))
        events = cursor.fetchall()
        conn.close()
        return [
            {
                'id': row[0], 'timestamp': row[1], 'query_text': row[2],
                'decision': row[3], 'details': row[4], 'category': row[5],
                'brand_type': row[6], 'potential_value': row[7], 'explanation': row[8]
            }
            for row in events
        ]

    @staticmethod
    def get_today_statistics():
        conn = sqlite3.connect(DATABASE_NAME)
        cursor = conn.cursor()
        today = datetime.now().strftime('%Y-%m-%d')
        cursor.execute('''
            SELECT decision, COUNT(*) as count, COALESCE(SUM(potential_value), 0) as total_value
            FROM events WHERE date(timestamp) = ? GROUP BY decision
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
        conn = sqlite3.connect(DATABASE_NAME)
        cursor = conn.cursor()
        week_ago = (datetime.now() - timedelta(days=7)).strftime('%Y-%m-%d')
        cursor.execute('''
            SELECT category, COUNT(*) as frequency, SUM(potential_value) as total_value
            FROM events WHERE decision = 'UTRACONE OKAZJE' AND date(timestamp) >= ?
            GROUP BY category ORDER BY frequency DESC, total_value DESC LIMIT ?
        ''', (week_ago, limit))
        results = cursor.fetchall()
        conn.close()
        return [
            {'category': row[0], 'frequency': row[1], 'total_value': int(row[2]) if row[2] else 0}
            for row in results
        ]


# ========================================
# ADMIN DASHBOARD STATE MANAGER
# ========================================

class AdminDashboardStateManager:
    """Server-side state persistence for admin dashboard (replaces localStorage)"""

    @staticmethod
    def init_table():
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
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_state_key ON admin_dashboard_state(state_key)')
        conn.commit()
        conn.close()
        print("[DATABASE] Admin dashboard state table initialized")

    @staticmethod
    def save_state(state_key, data):
        conn = sqlite3.connect(DATABASE_NAME)
        cursor = conn.cursor()
        json_data = json.dumps(data, ensure_ascii=False, default=str)
        cursor.execute('''
            INSERT INTO admin_dashboard_state (state_key, state_data, updated_at)
            VALUES (?, ?, CURRENT_TIMESTAMP)
            ON CONFLICT(state_key)
            DO UPDATE SET state_data = excluded.state_data, updated_at = CURRENT_TIMESTAMP
        ''', (state_key, json_data))
        conn.commit()
        conn.close()
        print(f"[ADMIN_STATE] Saved {state_key}: {len(json_data)} bytes")

    @staticmethod
    def get_state(state_key):
        conn = sqlite3.connect(DATABASE_NAME)
        cursor = conn.cursor()
        cursor.execute('''
            SELECT state_data, updated_at FROM admin_dashboard_state WHERE state_key = ?
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
        conn = sqlite3.connect(DATABASE_NAME)
        cursor = conn.cursor()
        cursor.execute('DELETE FROM admin_dashboard_state WHERE state_key = ?', (state_key,))
        conn.commit()
        conn.close()
        print(f"[ADMIN_STATE] Deleted {state_key}")


# ========================================
# P3 - QUERY INTENT MANAGER (RLHF DATA)
# ========================================

class QueryIntentManager:
    """
    Manages RLHF data for Scale AI / LLM fine-tuning.

    SESSION CONSOLIDATION: Only keeps FINAL INTENT per session.
    When same session sends multiple queries, we UPDATE the existing record
    instead of creating duplicates for intermediate prefixes.

    AI_READY FLAG: Marks clean data suitable for AI training.
    """

    @staticmethod
    def init_table():
        conn = sqlite3.connect(DATABASE_NAME)
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS query_intents (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT NOT NULL,
                query_text TEXT NOT NULL,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                confidence_level TEXT,
                suggestion_type TEXT,
                best_match_score INTEGER,
                clicked_alternative INTEGER DEFAULT 0,
                query_refinement_count INTEGER DEFAULT 0,
                time_to_first_click REAL,
                session_duration REAL,
                bounce INTEGER DEFAULT 0,
                added_to_cart INTEGER DEFAULT 0,
                purchased INTEGER DEFAULT 0,
                cart_value REAL DEFAULT 0.0,
                reward_score REAL,
                missing_attributes TEXT,
                matched_product_id TEXT,
                ai_ready INTEGER DEFAULT 0
            )
        ''')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_qi_session ON query_intents(session_id)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_qi_timestamp ON query_intents(timestamp)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_qi_reward ON query_intents(reward_score)')

        # Migration: Add ai_ready column if missing (for existing databases)
        try:
            cursor.execute("PRAGMA table_info(query_intents)")
            columns = [col[1] for col in cursor.fetchall()]
            if 'ai_ready' not in columns:
                cursor.execute('ALTER TABLE query_intents ADD COLUMN ai_ready INTEGER DEFAULT 0')
                print("[P3] Added ai_ready column to query_intents")
        except Exception as e:
            print(f"[P3] Migration check: {e}")

        cursor.execute('CREATE INDEX IF NOT EXISTS idx_qi_ai_ready ON query_intents(ai_ready)')

        conn.commit()
        conn.close()
        print("[P3] QueryIntent table initialized (with AI_READY flag)")

    @staticmethod
    def add_query_intent(data: dict) -> int:
        """
        Add or UPDATE query intent.

        SESSION CONSOLIDATION: If session already has a record within last 60s,
        UPDATE it instead of creating a new one. This ensures only FINAL INTENT
        is stored, not intermediate prefixes like "kompu" -> "kompute" -> "komputer".
        """
        conn = sqlite3.connect(DATABASE_NAME)
        cursor = conn.cursor()

        session_id = data.get('session_id', 'unknown')
        missing_attrs = data.get('missing_attributes')
        if isinstance(missing_attrs, (list, dict)):
            missing_attrs = json.dumps(missing_attrs, ensure_ascii=False)

        # === SESSION CONSOLIDATION: Check for existing record ===
        cursor.execute('''
            SELECT id, query_refinement_count FROM query_intents
            WHERE session_id = ?
            AND timestamp >= datetime('now', '-60 seconds')
            ORDER BY timestamp DESC LIMIT 1
        ''', (session_id,))
        existing = cursor.fetchone()

        if existing:
            # UPDATE existing record (this is a query refinement, not a new session)
            existing_id = existing[0]
            refinement_count = (existing[1] or 0) + 1

            cursor.execute('''
                UPDATE query_intents SET
                    query_text = ?,
                    timestamp = CURRENT_TIMESTAMP,
                    confidence_level = ?,
                    suggestion_type = ?,
                    best_match_score = ?,
                    clicked_alternative = ?,
                    query_refinement_count = ?,
                    time_to_first_click = ?,
                    session_duration = ?,
                    bounce = ?,
                    added_to_cart = ?,
                    purchased = ?,
                    cart_value = ?,
                    reward_score = ?,
                    missing_attributes = ?,
                    matched_product_id = ?,
                    ai_ready = ?
                WHERE id = ?
            ''', (
                data.get('query_text', ''),
                data.get('confidence_level'),
                data.get('suggestion_type'),
                data.get('best_match_score', 0),
                1 if data.get('clicked_alternative') else 0,
                refinement_count,
                data.get('time_to_first_click'),
                data.get('session_duration'),
                1 if data.get('bounce') else 0,
                1 if data.get('added_to_cart') else 0,
                1 if data.get('purchased') else 0,
                data.get('cart_value', 0.0),
                data.get('reward_score'),
                missing_attrs,
                data.get('matched_product_id'),
                1 if data.get('ai_ready') else 0,
                existing_id
            ))
            conn.commit()
            conn.close()
            print(f"[P3] QueryIntent UPDATED (consolidation): id={existing_id}, refinements={refinement_count}, ai_ready={data.get('ai_ready')}")
            return existing_id

        # === NEW RECORD (first query in session) ===
        cursor.execute('''
            INSERT INTO query_intents (
                session_id, query_text, confidence_level, suggestion_type,
                best_match_score, clicked_alternative, query_refinement_count,
                time_to_first_click, session_duration, bounce,
                added_to_cart, purchased, cart_value, reward_score,
                missing_attributes, matched_product_id, ai_ready
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            session_id, data.get('query_text', ''),
            data.get('confidence_level'), data.get('suggestion_type'),
            data.get('best_match_score', 0),
            1 if data.get('clicked_alternative') else 0,
            data.get('query_refinement_count', 0),
            data.get('time_to_first_click'), data.get('session_duration'),
            1 if data.get('bounce') else 0,
            1 if data.get('added_to_cart') else 0,
            1 if data.get('purchased') else 0,
            data.get('cart_value', 0.0), data.get('reward_score'),
            missing_attrs, data.get('matched_product_id'),
            1 if data.get('ai_ready') else 0
        ))
        record_id = cursor.lastrowid
        conn.commit()
        conn.close()
        print(f"[P3] QueryIntent NEW: id={record_id}, reward={data.get('reward_score')}, ai_ready={data.get('ai_ready')}")
        return record_id

    @staticmethod
    def get_training_data(limit: int = 1000, ai_ready_only: bool = False) -> list:
        """
        Get training data from query_intents.

        Args:
            limit: Max number of records
            ai_ready_only: If True, only return records with ai_ready=1
        """
        conn = sqlite3.connect(DATABASE_NAME)
        cursor = conn.cursor()

        if ai_ready_only:
            cursor.execute('''
                SELECT session_id, query_text, confidence_level, suggestion_type,
                    clicked_alternative, purchased, bounce, reward_score,
                    missing_attributes, matched_product_id, timestamp, ai_ready,
                    query_refinement_count
                FROM query_intents WHERE ai_ready = 1 ORDER BY timestamp DESC LIMIT ?
            ''', (limit,))
        else:
            cursor.execute('''
                SELECT session_id, query_text, confidence_level, suggestion_type,
                    clicked_alternative, purchased, bounce, reward_score,
                    missing_attributes, matched_product_id, timestamp, ai_ready,
                    query_refinement_count
                FROM query_intents ORDER BY timestamp DESC LIMIT ?
            ''', (limit,))

        rows = cursor.fetchall()
        conn.close()
        results = []
        for row in rows:
            missing_attrs = row[8]
            if missing_attrs:
                try:
                    missing_attrs = json.loads(missing_attrs)
                except:
                    missing_attrs = []
            results.append({
                'query': row[1], 'intent_label': row[3], 'confidence': row[2],
                'reward_signal': {
                    'score': row[7], 'clicked_alternative': bool(row[4]),
                    'purchased': bool(row[5]), 'bounce': bool(row[6])
                },
                'missing_features': missing_attrs or [],
                'matched_product_id': row[9], 'timestamp': row[10],
                'ai_ready': bool(row[11]) if row[11] is not None else False,
                'query_refinement_count': row[12] or 0
            })
        return results

    @staticmethod
    def get_stats() -> dict:
        """Get statistics for P4 dashboard"""
        conn = sqlite3.connect(DATABASE_NAME)
        cursor = conn.cursor()

        # Total count
        cursor.execute('SELECT COUNT(*) FROM query_intents')
        total = cursor.fetchone()[0]

        # AI Ready count
        cursor.execute('SELECT COUNT(*) FROM query_intents WHERE ai_ready = 1')
        ai_ready = cursor.fetchone()[0]

        # Average reward
        cursor.execute('SELECT AVG(reward_score) FROM query_intents WHERE reward_score IS NOT NULL')
        avg_reward = cursor.fetchone()[0] or 0.0

        # Gold signals (clicked despite no match)
        cursor.execute('''
            SELECT COUNT(*) FROM query_intents
            WHERE confidence_level = 'NO_MATCH' AND clicked_alternative = 1
        ''')
        gold_signals = cursor.fetchone()[0]

        # Bounce rate
        cursor.execute('SELECT COUNT(*) FROM query_intents WHERE bounce = 1')
        bounces = cursor.fetchone()[0]
        bounce_rate = (bounces / total * 100) if total > 0 else 0

        conn.close()
        return {
            'total_intents': total,
            'ai_ready_count': ai_ready,
            'ai_ready_percentage': (ai_ready / total * 100) if total > 0 else 0,
            'avg_reward': round(avg_reward, 4),
            'gold_signals': gold_signals,
            'bounce_rate': round(bounce_rate, 2)
        }


# ========================================
# VISITOR TRACKING TABLES
# ========================================

def ensure_visitor_tables_exist():
    """Create/update visitor_sessions table - RODO COMPLIANT"""
    conn = sqlite3.connect(DATABASE_NAME)
    cursor = conn.cursor()

    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='visitor_sessions'")
    table_exists = cursor.fetchone() is not None

    if table_exists:
        cursor.execute("PRAGMA table_info(visitor_sessions)")
        columns = [col[1] for col in cursor.fetchall()]

        new_columns = {
            'ip_hash': 'TEXT', 'ip_masked': 'TEXT',
            'device_type': 'TEXT', 'os': 'TEXT', 'browser': 'TEXT',
            'viewport_category': 'TEXT', 'anonymous_mode': 'BOOLEAN DEFAULT FALSE',
            'asn': 'TEXT',
            'radar_status': 'TEXT DEFAULT "Przegląda"',
            'radar_company': 'TEXT'
        }
        _allowed_cols = set(new_columns.keys())
        for col_name, col_type in new_columns.items():
            if col_name not in columns:
                if col_name not in _allowed_cols:
                    continue
                try:
                    if not re.match(r'^[a-zA-Z_][a-zA-Z0-9_]*$', col_name):
                        raise ValueError(f"Invalid column name: {col_name}")
                    cursor.execute(f'ALTER TABLE visitor_sessions ADD COLUMN {col_name} {col_type}')
                    print(f"[DATABASE] Added column: {col_name}")
                except Exception as e:
                    print(f"[DATABASE] Column {col_name} error: {e}")

        indexes = [
            ('idx_visitor_sessions_entry_time', 'entry_time'),
            ('idx_visitor_sessions_org', 'organization'),
            ('idx_visitor_sessions_hash', 'ip_hash')
        ]
        for idx_name, idx_column in indexes:
            try:
                if not re.match(r'^[a-zA-Z_][a-zA-Z0-9_]*$', idx_name) or not re.match(r'^[a-zA-Z_][a-zA-Z0-9_]*$', idx_column):
                    raise ValueError(f"Invalid index name/column: {idx_name}/{idx_column}")
                cursor.execute(f'CREATE INDEX IF NOT EXISTS {idx_name} ON visitor_sessions({idx_column})')
            except Exception as e:
                print(f"[DATABASE] Index {idx_name} warning: {e}")
    else:
        cursor.execute('''
            CREATE TABLE visitor_sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT UNIQUE NOT NULL,
                ip_hash TEXT, ip_masked TEXT,
                user_agent TEXT, referrer TEXT, page_url TEXT,
                entry_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                exit_time TIMESTAMP,
                last_activity TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                session_duration INTEGER DEFAULT 0,
                country TEXT, country_code TEXT, city TEXT, region TEXT, timezone TEXT,
                organization TEXT, isp TEXT, asn TEXT,
                total_messages INTEGER DEFAULT 0,
                max_scroll_depth INTEGER DEFAULT 0,
                clicks_count INTEGER DEFAULT 0,
                utm_source TEXT, utm_medium TEXT, utm_campaign TEXT,
                utm_content TEXT, utm_term TEXT,
                device_type TEXT, os TEXT, browser TEXT,
                viewport_category TEXT, language TEXT,
                anonymous_mode BOOLEAN DEFAULT FALSE,
                radar_status TEXT DEFAULT 'Przegląda',
                radar_company TEXT,
                is_active BOOLEAN DEFAULT TRUE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        cursor.execute('CREATE INDEX idx_visitor_sessions_entry_time ON visitor_sessions(entry_time)')
        cursor.execute('CREATE INDEX idx_visitor_sessions_org ON visitor_sessions(organization)')
        cursor.execute('CREATE INDEX idx_visitor_sessions_hash ON visitor_sessions(ip_hash)')
        print("[DATABASE] Created new visitor_sessions table (GDPR Compliant)")

    conn.commit()
    conn.close()
    print("[DATABASE] Visitor tracking tables initialized (GDPR Compliant)")


# ========================================
# PERSISTENT STORAGE TABLES
# ========================================

def init_persistent_storage_tables():
    """Create tables for companies, hot_leads, log_history"""
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
        print("[DATABASE] Persistent storage tables OK")
    except Exception as e:
        print(f"[DATABASE] Persistent storage error: {e}")


# ========================================
# PERSISTENT STORAGE CRUD
# ========================================

def save_company_data(organization, city, country, query, decision):
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
            return {'name': organization, 'engagement_score': engagement_score, 'is_new': False}
        else:
            now = datetime.now()
            queries = [{'text': query, 'timestamp': now.isoformat(), 'decision': decision}]
            high_intent = 1 if decision == 'ZNALEZIONE PRODUKTY' else 0
            lost_opp = 1 if decision == 'UTRACONE OKAZJE' else 0
            cursor.execute('''INSERT INTO companies (name, city, country, first_visit, last_visit,
                total_queries, high_intent_queries, lost_opportunities, engagement_score, queries_json)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                (organization, city, country, now, now, 1, high_intent, lost_opp, 10, json.dumps(queries)))
            conn.commit()
            conn.close()
            return {'name': organization, 'engagement_score': 10, 'is_new': True}
    except Exception as e:
        print(f"[ERROR] save_company_data: {e}")
        return None


def save_hot_lead(company, query, score):
    try:
        conn = sqlite3.connect(DATABASE_NAME)
        cursor = conn.cursor()
        cursor.execute('INSERT INTO hot_leads (company, query, score, timestamp) VALUES (?, ?, ?, ?)',
                       (company, query, score, datetime.now()))
        conn.commit()
        conn.close()
        return True
    except Exception as e:
        print(f"[ERROR] save_hot_lead: {e}")
        return False


def save_log_entry(log_type, company, query):
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
    """Get org/city/country context for a visitor session"""
    try:
        conn = sqlite3.connect(DATABASE_NAME)
        cursor = conn.cursor()
        cursor.execute('SELECT city, organization, country FROM visitor_sessions WHERE session_id = ?', (session_id,))
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
    """Get client info from database"""
    if not client_id:
        return None
    try:
        conn = sqlite3.connect(DATABASE_NAME)
        cursor = conn.cursor()
        cursor.execute('''
            SELECT id, company_name, domain, subscription_tier, contact_email
            FROM clients WHERE id = ? AND is_active = TRUE
        ''', (client_id,))
        row = cursor.fetchone()
        conn.close()
        if row:
            return {
                'id': row[0], 'company_name': row[1], 'domain': row[2],
                'subscription_tier': row[3], 'contact_email': row[4]
            }
        return None
    except Exception as e:
        print(f"[ERROR] Failed to get client info: {e}")
        return None


# ========================================
# P5 — SITE ANALYTICS TABLES
# ========================================

def ensure_site_tracking_tables():
    """Create site_visits and bot_queries tables for P5 Site Analytics"""
    conn = sqlite3.connect(DATABASE_NAME)
    cursor = conn.cursor()

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS site_visits (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            visit_id TEXT UNIQUE NOT NULL,
            page_path TEXT NOT NULL,
            ip_hash TEXT,
            organization TEXT,
            city TEXT,
            country TEXT,
            referrer TEXT,
            user_agent TEXT,
            entry_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            exit_time TIMESTAMP,
            session_duration INTEGER DEFAULT 0,
            is_active BOOLEAN DEFAULT TRUE
        )
    ''')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_site_visits_entry ON site_visits(entry_time)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_site_visits_page ON site_visits(page_path)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_site_visits_org ON site_visits(organization)')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS bot_queries (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            visit_id TEXT,
            page_path TEXT DEFAULT "/ldi-readme",
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            user_message TEXT NOT NULL,
            bot_reply TEXT,
            ip_hash TEXT,
            organization TEXT,
            city TEXT
        )
    ''')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_bot_queries_ts ON bot_queries(timestamp)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_bot_queries_visit ON bot_queries(visit_id)')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS copy_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            visit_id TEXT,
            page_path TEXT NOT NULL,
            copy_text TEXT NOT NULL,
            ip_hash TEXT,
            organization TEXT,
            city TEXT,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_copy_events_ts ON copy_events(timestamp)')

    conn.commit()
    conn.close()
    print("[DATABASE] P5 site tracking tables initialized")


def get_recent_site_visits(limit=40):
    """Get recent page visits for P5 dashboard"""
    try:
        conn = sqlite3.connect(DATABASE_NAME)
        cursor = conn.cursor()
        cursor.execute('''
            SELECT visit_id, page_path, organization, city, country,
                   entry_time, session_duration, is_active
            FROM site_visits
            ORDER BY entry_time DESC LIMIT ?
        ''', (limit,))
        rows = cursor.fetchall()
        conn.close()
        result = []
        for r in rows:
            result.append({
                'visit_id': r[0], 'page_path': r[1],
                'organization': r[2] or 'Nieznana firma',
                'city': r[3] or '—', 'country': r[4] or '—',
                'entry_time': r[5], 'session_duration': r[6] or 0,
                'is_active': bool(r[7])
            })
        return result
    except Exception as e:
        print(f"[P5] get_recent_site_visits error: {e}")
        return []


def get_recent_bot_queries(limit=30):
    """Get recent bot queries for P5 dashboard"""
    try:
        conn = sqlite3.connect(DATABASE_NAME)
        cursor = conn.cursor()
        cursor.execute('''
            SELECT visit_id, page_path, timestamp, user_message, bot_reply,
                   organization, city
            FROM bot_queries
            ORDER BY timestamp DESC LIMIT ?
        ''', (limit,))
        rows = cursor.fetchall()
        conn.close()
        result = []
        for r in rows:
            result.append({
                'visit_id': r[0], 'page_path': r[1],
                'timestamp': r[2], 'user_message': r[3],
                'bot_reply': (r[4] or '')[:200],
                'organization': r[5] or 'Nieznana firma',
                'city': r[6] or '—'
            })
        return result
    except Exception as e:
        print(f"[P5] get_recent_bot_queries error: {e}")
        return []


def get_recent_copy_events(limit=25):
    """Get recent copy events for P5 dashboard"""
    try:
        conn = sqlite3.connect(DATABASE_NAME)
        cursor = conn.cursor()
        cursor.execute('''
            SELECT visit_id, page_path, copy_text, organization, city, timestamp
            FROM copy_events
            ORDER BY timestamp DESC LIMIT ?
        ''', (limit,))
        rows = cursor.fetchall()
        conn.close()
        return [{
            'visit_id': r[0], 'page_path': r[1], 'copy_text': r[2],
            'organization': r[3] or 'Nieznana firma',
            'city': r[4] or '—', 'timestamp': r[5]
        } for r in rows]
    except Exception as e:
        print(f"[P5] get_recent_copy_events error: {e}")
        return []


def get_site_analytics_stats():
    """Get today's stats for P5 dashboard"""
    try:
        conn = sqlite3.connect(DATABASE_NAME)
        cursor = conn.cursor()
        today = datetime.now().strftime('%Y-%m-%d')

        cursor.execute(
            "SELECT COUNT(*) FROM site_visits WHERE date(entry_time) = ?", (today,))
        total_visits = cursor.fetchone()[0]

        cursor.execute(
            "SELECT COUNT(*) FROM site_visits WHERE date(entry_time) = ? AND page_path = '/ldi'",
            (today,))
        ldi_visits = cursor.fetchone()[0]

        cursor.execute(
            "SELECT COUNT(*) FROM site_visits WHERE date(entry_time) = ? AND page_path = '/ldi-readme'",
            (today,))
        readme_visits = cursor.fetchone()[0]

        cursor.execute(
            "SELECT COUNT(*) FROM site_visits WHERE date(entry_time) = ? AND page_path = '/ldi-tests'",
            (today,))
        tests_visits = cursor.fetchone()[0]

        cursor.execute(
            "SELECT COUNT(*) FROM bot_queries WHERE date(timestamp) = ?", (today,))
        bot_queries = cursor.fetchone()[0]

        cursor.execute(
            "SELECT COUNT(*) FROM copy_events WHERE date(timestamp) = ?", (today,))
        copy_count = cursor.fetchone()[0]

        conn.close()
        return {
            'total_visits': total_visits,
            'ldi_visits': ldi_visits,
            'readme_visits': readme_visits,
            'tests_visits': tests_visits,
            'bot_queries': bot_queries,
            'copy_events': copy_count
        }
    except Exception as e:
        print(f"[P5] get_site_analytics_stats error: {e}")
        return {'total_visits': 0, 'ldi_visits': 0, 'readme_visits': 0,
                'tests_visits': 0, 'bot_queries': 0}


def ensure_p5_user():
    """
    Tworzy użytkownika 'p5viewer' przy każdym starcie (INSERT OR IGNORE).
    Osobne konto wyłącznie do /site-analytics — nie jest to główny admin.
    """
    from werkzeug.security import generate_password_hash
    try:
        conn = sqlite3.connect(DATABASE_NAME)
        cursor = conn.cursor()
        pwd_hash = generate_password_hash('Radar2025!')
        cursor.execute('''
            INSERT OR IGNORE INTO users (username, email, password_hash, salt, role, is_active)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', ('p5viewer', 'p5viewer@adeptai.pl', pwd_hash, '', 'admin', True))
        conn.commit()
        conn.close()
        print("[STARTUP] p5viewer user ensured")
    except Exception as e:
        print(f"[STARTUP] p5viewer ensure error: {e}")


def init_database():
    """Initialize database integrity on startup"""
    print("[STARTUP] Checking database integrity...")

    # 1. Ensure admin state + persistent storage tables
    try:
        AdminDashboardStateManager.init_table()
        init_persistent_storage_tables()
        ensure_site_tracking_tables()
        print("[STARTUP] Admin state & persistent storage tables OK")
    except Exception as e:
        print(f"[STARTUP] Warning verifying admin tables: {e}")

    # 2. Ensure P5 viewer user exists (runs every startup, idempotent)
    ensure_p5_user()

    # 2. Check if users table exists (new database)
    conn = sqlite3.connect(DATABASE_NAME)
    cursor = conn.cursor()
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='users'")
    if not cursor.fetchone():
        print("[STARTUP] Empty DB (no users) - creating tables...")
        conn.close()

        from auth_manager import ensure_tables_exist
        ensure_tables_exist()

        DatabaseManager.initialize_database()
        ensure_visitor_tables_exist()

        print("[STARTUP] Setting passwords...")
        import subprocess
        import sys
        try:
            subprocess.run([sys.executable, 'skrypthasla.py'], check=True)
        except Exception as e:
            print(f"[STARTUP] Password script error: {e}")
    else:
        conn.close()
        print("[STARTUP] Users table exists - skipping base creation.")
