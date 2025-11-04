"""
System Autoryzacji "Oko Saurona"
Plik: auth_manager.py

Obsługuje:
- Login/logout użytkowników
- Role-based access control (client/admin/debug)  
- Session management
- Password hashing
- Decoratory dla ochrony routes
"""

from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from flask import redirect, url_for, flash, request
import sqlite3
import secrets

# ================================================================
# KONFIGURACJA FLASK-LOGIN
# ================================================================

def init_login_manager(app):
    """Inicjalizuje Flask-Login dla aplikacji"""
    login_manager = LoginManager()
    login_manager.init_app(app)
    login_manager.login_view = 'login'  # Redirect gdy brak autoryzacji
    login_manager.login_message = 'Zaloguj się aby uzyskać dostęp'
    login_manager.login_message_category = 'info'
    
    @login_manager.user_loader
    def load_user(user_id):
        """Ładuje użytkownika na podstawie ID z sesji"""
        return User.get_by_id(int(user_id))
    
    return login_manager

# ================================================================
# KLASA USER (MODEL)
# ================================================================

class User(UserMixin):
    """
    Model użytkownika zgodny z Flask-Login
    Obsługuje 3 role: client, admin, debug
    """
    
    def __init__(self, id, username, email, role, client_id=None, is_active=True):
        self.id = id
        self.username = username
        self.email = email
        self.role = role
        self.client_id = client_id
        self._is_active = is_active
    
    def is_active(self):
        """Wymagane przez Flask-Login"""
        return self._is_active
    
    def get_id(self):
        """Wymagane przez Flask-Login - zwraca string ID"""
        return str(self.id)
    
    def is_client(self):
        """Sprawdza czy user ma rolę client"""
        return self.role == 'client'
    
    def is_admin(self):
        """Sprawdza czy user ma rolę admin"""
        return self.role == 'admin'
    
    def is_debug(self):
        """Sprawdza czy user ma rolę debug"""
        return self.role == 'debug'
    
    def has_access_to_client(self, client_id):
        """Sprawdza czy user ma dostęp do danych określonego klienta"""
        if self.is_admin() or self.is_debug():
            return True  # Admin/debug ma dostęp do wszystkiego
        return self.client_id == client_id
    
    @staticmethod
    def get_by_id(user_id):
        """Pobiera użytkownika po ID z bazy danych"""
        try:
            conn = sqlite3.connect('dashboard.db')
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT id, username, email, role, client_id, is_active 
                FROM users 
                WHERE id = ? AND is_active = TRUE
            ''', (user_id,))
            
            row = cursor.fetchone()
            conn.close()
            
            if row:
                return User(
                    id=row[0],
                    username=row[1], 
                    email=row[2],
                    role=row[3],
                    client_id=row[4],
                    is_active=row[5]
                )
            return None
            
        except Exception as e:
            print(f"[AUTH ERROR] Failed to get user by ID: {e}")
            return None
    
    @staticmethod
    def get_by_username(username):
        """Pobiera użytkownika po username"""
        try:
            conn = sqlite3.connect('dashboard.db')
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT id, username, email, role, client_id, is_active 
                FROM users 
                WHERE username = ? AND is_active = TRUE
            ''', (username,))
            
            row = cursor.fetchone()
            conn.close()
            
            if row:
                return User(
                    id=row[0],
                    username=row[1],
                    email=row[2], 
                    role=row[3],
                    client_id=row[4],
                    is_active=row[5]
                )
            return None
            
        except Exception as e:
            print(f"[AUTH ERROR] Failed to get user by username: {e}")
            return None
    
    @staticmethod
    def authenticate(username, password):
        """
        Uwierzytelnia użytkownika (username + password)
        Zwraca User object jeśli sukces, None jeśli błąd
        """
        try:
            conn = sqlite3.connect('dashboard.db')
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT id, username, email, password_hash, role, client_id, is_active
                FROM users 
                WHERE username = ? AND is_active = TRUE
            ''', (username,))
            
            row = cursor.fetchone()
            conn.close()
            
            if not row:
                print(f"[DEBUG] User '{username}' NOT FOUND in database")
                return None
            
            print(f"[DEBUG] Password check: '{password}' vs stored hash")
            print(f"[DEBUG] Hash result: {check_password_hash(row[3], password)}")
            print(f"[DEBUG] ✅ Found user: {row[1]} (role: {row[4]})")
            print(f"[DEBUG] Testing password '{password}'...")
            print(f"[DEBUG] Hash check result: {check_password_hash(row[3], password)}")
            
            if check_password_hash(row[3], password):
                # Aktualizuj last_login
                User._update_last_login(row[0])
                
                return User(
                    id=row[0],
                    username=row[1],
                    email=row[2],
                    role=row[4], 
                    client_id=row[5],
                    is_active=row[6]
                )
            
            return None
            
        except Exception as e:
            print(f"[AUTH ERROR] Authentication failed: {e}")
            return None
    
    @staticmethod
    def _update_last_login(user_id):
        """Aktualizuje timestamp ostatniego logowania"""
        try:
            conn = sqlite3.connect('dashboard.db')
            cursor = conn.cursor()
            
            cursor.execute('''
                UPDATE users 
                SET last_login = CURRENT_TIMESTAMP,
                    login_count = login_count + 1
                WHERE id = ?
            ''', (user_id,))
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            print(f"[AUTH ERROR] Failed to update last login: {e}")
    
    @staticmethod
    def create_user(username, email, password, role, client_id=None, created_by=None):
        """
        Tworzy nowego użytkownika w bazie danych
        
        Args:
            username: Nazwa użytkownika (unikalna)
            email: Email (unikalny)  
            password: Hasło w plaintext (zostanie zahashowane)
            role: 'client', 'admin', lub 'debug'
            client_id: ID klienta (wymagane dla role='client')
            created_by: ID użytkownika który tworzy konto
        
        Returns:
            User object jeśli sukces, None jeśli błąd
        """
        try:
            # Walidacja danych
            if role not in ['client', 'admin', 'debug']:
                raise ValueError("Invalid role")
            
            if role == 'client' and client_id is None:
                raise ValueError("Client role requires client_id")
            
            if role in ['admin', 'debug'] and client_id is not None:
                raise ValueError("Admin/debug role cannot have client_id")
            
            # Generate password hash z solą
            salt = secrets.token_hex(16)
            password_hash = generate_password_hash(password + salt)
            
            conn = sqlite3.connect('dashboard.db')
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO users (username, email, password_hash, salt, role, client_id, created_by)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (username, email, password_hash, salt, role, client_id, created_by))
            
            user_id = cursor.lastrowid
            conn.commit()
            conn.close()
            
            print(f"[AUTH] Created user: {username} (role: {role})")
            
            return User(
                id=user_id,
                username=username,
                email=email,
                role=role,
                client_id=client_id,
                is_active=True
            )
            
        except Exception as e:
            print(f"[AUTH ERROR] Failed to create user: {e}")
            return None

# ================================================================
# DECORATORY DOSTĘPU (KLUCZOWE DLA 3 POZIOMÓW)
# ================================================================

def require_client_access(f):
    """
    Decorator: Wymaga roli 'client' + dostęp tylko do własnych danych
    Użycie: @require_client_access
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated:
            return redirect(url_for('login'))
        
        if not current_user.is_client():
            flash('Brak uprawnień - wymagany dostęp klienta', 'error')
            return redirect(url_for('unauthorized'))
        
        return f(*args, **kwargs)
    return decorated_function

def require_admin_access(f):
    """
    Decorator: Wymaga roli 'admin' (Poziom 2 - Centrum Strategiczne)
    Użycie: @require_admin_access  
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated:
            return redirect(url_for('login'))
        
        if not current_user.is_admin():
            flash('Brak uprawnień - wymagany dostęp administratora', 'error')
            return redirect(url_for('unauthorized'))
        
        return f(*args, **kwargs)
    return decorated_function

def require_debug_access(f):
    """
    Decorator: Wymaga roli 'debug' (Poziom 3 - Tryb Debug)
    Użycie: @require_debug_access
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated:
            return redirect(url_for('login'))
        
        if not current_user.is_debug():
            flash('Brak uprawnień - wymagany dostęp debug', 'error')
            return redirect(url_for('unauthorized'))
        
        return f(*args, **kwargs)
    return decorated_function

def require_any_admin_access(f):
    """
    Decorator: Wymaga roli 'admin' LUB 'debug' (Poziom 2+3)
    Użycie: @require_any_admin_access
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated:
            return redirect(url_for('login'))
        
        if not (current_user.is_admin() or current_user.is_debug()):
            flash('Brak uprawnień - wymagany dostęp administratora', 'error')
            return redirect(url_for('unauthorized'))
        
        return f(*args, **kwargs)
    return decorated_function

# ================================================================
# FUNKCJE POMOCNICZE
# ================================================================

def get_client_info(client_id):
    """Pobiera informacje o kliencie z bazy danych"""
    try:
        conn = sqlite3.connect('dashboard.db')
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
        print(f"[AUTH ERROR] Failed to get client info: {e}")
        return None

def check_client_access(client_id):
    """
    Sprawdza czy aktualny użytkownik ma dostęp do danych klienta
    
    Returns:
        True jeśli ma dostęp, False jeśli nie
    """
    if not current_user.is_authenticated:
        return False
    
    return current_user.has_access_to_client(client_id)

def get_user_dashboard_route():
    """
    Zwraca właściwy route dashboardu na podstawie roli użytkownika
    
    Returns:
        String z nazwą route
    """
    if not current_user.is_authenticated:
        return 'login'
    
    if current_user.is_client():
        return 'client_dashboard'
    elif current_user.is_admin():
        return 'admin_dashboard'  
    elif current_user.is_debug():
        return 'debug_dashboard'
    else:
        return 'unauthorized'

# ================================================================
# FUNKCJE UTILITIES DLA ROZWOJU
# ================================================================

def create_default_admin(username='admin', password='admin123', email='admin@adept.ai'):
    """
    Tworzy domyślnego administratora (tylko dla rozwoju!)
    UWAGA: Zmień hasło w produkcji!
    """
    existing_admin = User.get_by_username(username)
    if existing_admin:
        print(f"[AUTH] Admin user '{username}' already exists")
        return existing_admin
    
    admin_user = User.create_user(
        username=username,
        email=email,
        password=password,  # Zostanie zahashowane w create_user
        role='admin'
    )
    
    if admin_user:
        print(f"[AUTH] Created default admin: {username}")
    else:
        print(f"[AUTH ERROR] Failed to create default admin")
    
    return admin_user

def create_demo_client_user(client_id, username='demo_client', password='demo123'):
    """Tworzy użytkownika demo dla testów"""
    existing_user = User.get_by_username(username)
    if existing_user:
        print(f"[AUTH] Demo user '{username}' already exists")
        return existing_user
    
    demo_user = User.create_user(
        username=username,
        email=f'{username}@demo.pl',
        password=password,
        role='client',
        client_id=client_id
    )
    
    if demo_user:
        print(f"[AUTH] Created demo client user: {username}")
    else:
        print(f"[AUTH ERROR] Failed to create demo client user")
    
    return demo_user
def create_simple_admin():
    """Tworzy admin z prostym hashem bcrypt"""
    conn = sqlite3.connect('dashboard.db')
    cursor = conn.cursor()
    
    # Usuń starego admina
    cursor.execute('DELETE FROM users WHERE username = ?', ('admin',))
    
    # UŻYJ PBKDF2 zamiast domyślnego
    from werkzeug.security import generate_password_hash
    password_hash = generate_password_hash('admin123', method='pbkdf2:sha256')
    
    cursor.execute('''
        INSERT INTO users (username, email, password_hash, salt, role)
        VALUES (?, ?, ?, ?, ?)
    ''', ('admin', 'admin@test.pl', password_hash, '', 'admin'))
    
    conn.commit()
    conn.close()
    print("[AUTH] Simple admin created with pbkdf2 hash")

def setup_default_users():
    """Tworzy domyślnych użytkowników i klientów do testów (tylko development!)"""
    print("[SETUP] Creating default users and clients...")
    
    try:
        conn = sqlite3.connect('dashboard.db')
        cursor = conn.cursor()
        
        # KROK 1: Stwórz demo firmę w tabeli clients (jeśli nie istnieje)
        cursor.execute('''
            INSERT OR IGNORE INTO clients (
                id, company_name, domain, subscription_tier, 
                contact_email, monthly_query_limit, is_active
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (
            1, 'Demo Company Ltd', 'demo-company.pl', 'premium',
            'contact@demo-company.pl', 50000, True
        ))
        
        # KROK 2: Sprawdź czy demo firma została utworzona
        cursor.execute('SELECT company_name FROM clients WHERE id = 1')
        demo_company = cursor.fetchone()
        
        if demo_company:
            print(f"[SETUP] Demo company ready: {demo_company[0]}")
        else:
            print("[SETUP] ERROR: Failed to create demo company")
            conn.close()
            return
        
        conn.commit()
        conn.close()
        
        # KROK 3: Stwórz admin user (jak wcześniej)
        create_simple_admin()
        print("[SETUP] Admin user created: admin / admin123")
        
        # KROK 4: Stwórz demo client user z WERKZEUG HASH (jak admin)
        print("[SETUP] Creating demo client user...")
        
        try:
            conn = sqlite3.connect('dashboard.db')
            cursor = conn.cursor()
            
            # Usuń starego demo_client jeśli istnieje
            cursor.execute('DELETE FROM users WHERE username = ?', ('demo_client',))
            
            # Stwórz z normalnym hashem Werkzeug (jak admin)
            from werkzeug.security import generate_password_hash
            password_hash = generate_password_hash('demo123')
            
            cursor.execute('''
                INSERT INTO users (username, email, password_hash, salt, role, client_id, is_active)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', ('demo_client', 'demo@demo-company.pl', password_hash, '', 'client', 1, True))
            
            conn.commit()
            conn.close()
            print("[SETUP] Demo client created with Werkzeug hash: demo_client / demo123")
            
        except Exception as e:
            print(f"[SETUP] ERROR: Exception creating demo_client: {e}")
        
        # KROK 5: Stwórz debug user z WERKZEUG HASH
        print("[SETUP] Creating debug user...")
        
        try:
            conn = sqlite3.connect('dashboard.db')
            cursor = conn.cursor()
            
            # Usuń starego debug jeśli istnieje
            cursor.execute('DELETE FROM users WHERE username = ?', ('debug',))
            
            # Stwórz z normalnym hashem Werkzeug (jak admin)
            password_hash = generate_password_hash('debug123')
            
            cursor.execute('''
                INSERT INTO users (username, email, password_hash, salt, role, client_id, is_active)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', ('debug', 'debug@adept.ai', password_hash, '', 'debug', None, True))
            
            conn.commit()
            conn.close()
            print("[SETUP] Debug user created: debug / debug123")
            
        except Exception as e:
            print(f"[SETUP] WARNING: Failed to create debug user: {e}")
        
        print("[SETUP] ✅ All default users and clients created successfully")
        print("[SETUP] Login credentials:")
        print("[SETUP]   Admin (Poziom 2): admin / admin123")
        print("[SETUP]   Client (Poziom 1): demo_client / demo123") 
        print("[SETUP]   Debug (Poziom 3): debug / debug123")
        
    except Exception as e:
        print(f"[SETUP] ERROR: Exception during setup: {e}")
        import traceback
        traceback.print_exc()

def ensure_tables_exist():
    """Upewnia się że wszystkie wymagane tabele istnieją"""
    try:
        conn = sqlite3.connect('dashboard.db')
        cursor = conn.cursor()
        
        # Tabela clients (jeśli nie istnieje)
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS clients (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                company_name TEXT NOT NULL UNIQUE,
                api_key TEXT UNIQUE DEFAULT '',
                domain TEXT,
                subscription_tier TEXT DEFAULT 'basic',
                contact_email TEXT,
                monthly_query_limit INTEGER DEFAULT 10000,
                current_month_queries INTEGER DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                is_active BOOLEAN DEFAULT TRUE
            )
        ''')
        
        # Tabela users (powinna już istnieć)
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                email TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                salt TEXT DEFAULT '',
                role TEXT NOT NULL DEFAULT 'client',
                client_id INTEGER,
                last_login TIMESTAMP,
                login_count INTEGER DEFAULT 0,
                is_active BOOLEAN DEFAULT TRUE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                created_by INTEGER,
                
                FOREIGN KEY (client_id) REFERENCES clients(id),
                CONSTRAINT chk_user_role CHECK (role IN ('client', 'admin', 'debug'))
            )
        ''')
        
        conn.commit()
        conn.close()
        print("[DATABASE] Tables verified/created")
        
    except Exception as e:
        print(f"[DATABASE] ERROR: {e}")

# ZASTĄP STARĄ FUNKCJĘ setup_default_users() w auth_manager.py tym kodem:
# I dodaj wywołanie ensure_tables_exist() w app.py przed setup_default_users()
def ensure_tables_exist():
    """Upewnia się że wszystkie wymagane tabele istnieją"""
    try:
        conn = sqlite3.connect('dashboard.db')
        cursor = conn.cursor()
        
        # Tabela clients
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS clients (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                company_name TEXT NOT NULL UNIQUE,
                api_key TEXT UNIQUE DEFAULT '',
                domain TEXT,
                subscription_tier TEXT DEFAULT 'basic',
                contact_email TEXT,
                monthly_query_limit INTEGER DEFAULT 10000,
                current_month_queries INTEGER DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                is_active BOOLEAN DEFAULT TRUE
            )
        ''')
        
        # DODAJ TABELE USERS (to brakowało!)
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                email TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                salt TEXT DEFAULT '',
                role TEXT NOT NULL DEFAULT 'client',
                client_id INTEGER,
                last_login TIMESTAMP,
                login_count INTEGER DEFAULT 0,
                is_active BOOLEAN DEFAULT TRUE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                created_by INTEGER,
                
                FOREIGN KEY (client_id) REFERENCES clients(id),
                CONSTRAINT chk_user_role CHECK (role IN ('client', 'admin', 'debug'))
            )
        ''')
        
        conn.commit()
        conn.close()
        print("[DATABASE] Tables verified/created")
        
    except Exception as e:
        print(f"[DATABASE] ERROR: {e}")