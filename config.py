import eventlet
eventlet.monkey_patch()

import os
from dotenv import load_dotenv
load_dotenv()

from flask import Flask
from flask_socketio import SocketIO
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from datetime import timedelta
import logging
from logging.handlers import RotatingFileHandler

# ========================================
# ENVIRONMENT CONFIGURATION
# ========================================
DEBUG = os.getenv('FLASK_DEBUG', 'false').lower() == 'true'
DATABASE_URL = os.getenv('DATABASE_URL', '')
CORS_ORIGINS = os.getenv('CORS_ORIGINS', 'https://adeptai.pl,http://localhost:5000,http://127.0.0.1:5000').split(',')

# ========================================
# FLASK APP
# ========================================
app = Flask(__name__)

# SECRET KEY
_secret = os.getenv('SECRET_KEY', '')
if not _secret or _secret == 'change-me-to-random-64-chars':
    if not DEBUG:
        raise RuntimeError("[FATAL] SECRET_KEY not set! Set SECRET_KEY env variable for production.")
    _secret = 'dev-local-only-NOT-FOR-PRODUCTION'
app.config['SECRET_KEY'] = _secret

# ========================================
# EXTENSIONS
# ========================================

# Rate Limiter
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["2000 per day", "200 per hour"],
    storage_uri=os.getenv('RATE_LIMIT_STORAGE', 'memory://'),
    strategy="fixed-window"
)

# Login Manager
from auth_manager import init_login_manager
login_manager = init_login_manager(app)
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=24)

# Session cookie security
app.config['SESSION_COOKIE_SECURE'] = not DEBUG
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['SESSION_PERMANENT'] = False

# Flask-Talisman (production only)
if not DEBUG:
    try:
        from flask_talisman import Talisman
        Talisman(app,
                 content_security_policy=None,
                 force_https=True,
                 strict_transport_security=True,
                 session_cookie_secure=True)
        print("[SECURITY] Flask-Talisman activated (HTTPS enforced)")
    except ImportError:
        print("[SECURITY] Flask-Talisman not installed, skipping")

# Logging
if not DEBUG:
    log_file = 'adept_ai_app.log'
    file_handler = RotatingFileHandler(log_file, maxBytes=10*1024*1024, backupCount=5)
    formatter = logging.Formatter(
        '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'
    )
    file_handler.setFormatter(formatter)
    file_handler.setLevel(logging.INFO)
    app.logger.addHandler(file_handler)
    app.logger.setLevel(logging.INFO)
    app.logger.info('Adept AI Application startup')

# SocketIO
socketio = SocketIO(app,
    cors_allowed_origins=CORS_ORIGINS,
    async_mode='eventlet',
    logger=DEBUG,
    engineio_logger=DEBUG,
    ping_timeout=120,
    ping_interval=25,
    allow_upgrades=True,
    transports=['polling', 'websocket']
)

# ========================================
# DUAL BOT INITIALIZATION
# ========================================
from ecommerce_bot import EcommerceBot as MotoBot
try:
    from elektro_bot import EcommerceBot as ElektroBot
    ELEKTRO_BOT_AVAILABLE = True
    print("[BOOT] Elektro bot imported successfully")
except ImportError as e:
    print(f"[BOOT] Elektro bot not available: {e}")
    ELEKTRO_BOT_AVAILABLE = False
    ElektroBot = None

print("[BOOT] Initializing DUAL BOT system...")
moto_bot = MotoBot()
print("[BOOT] Moto bot initialized")

if ELEKTRO_BOT_AVAILABLE:
    elektro_bot = ElektroBot()
    print("[BOOT] Elektro bot initialized")
else:
    elektro_bot = None
    print("[BOOT] Elektro bot disabled - using moto only")

# Backward compatibility
bot = moto_bot

# ========================================
# CONSTANTS
# ========================================
MOTO_DECISION_MAPPING = {
    'HIGH': 'ZNALEZIONE PRODUKTY',
    'MEDIUM': 'ODFILTROWANE',
    'LOW': 'ODFILTROWANE',
    'NO_MATCH': 'UTRACONE OKAZJE'
}

ELEKTRO_DECISION_MAPPING = {
    'HIGH': 'ZNALEZIONE PRODUKTY',
    'MEDIUM': 'ZNALEZIONE PRODUKTY',
    'LOW': 'ODFILTROWANE',
    'NO_MATCH': 'UTRACONE OKAZJE'
}

LOST_DEMAND_LOG = 'lost_demand_log.csv'
DATABASE_NAME = 'dashboard.db'

# ========================================
# REWARD ENGINE
# ========================================
from reward_engine import RewardSignalCalculator, UserSession, LDIRewardCalculator, LDISession

api_sessions = {}
reward_calc = RewardSignalCalculator()
ldi_reward_calc = LDIRewardCalculator()
