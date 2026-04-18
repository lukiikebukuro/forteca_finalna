# FIXES PRIORITY
## Ranked Fix List: Current State → Enterprise-Ready
**Date:** 2026-02-05

---

## P0: MUST FIX BEFORE ACQUI-HIRE PITCH
> Każdy z tych problemów jest deal-breaker. Reviewer z Scale AI / Anthropic / Google zobaczy to w 5 minut.

### P0-1. WYŁĄCZ debug=True W PRODUKCJI
**Plik:** `app.py:3977`
**Problem:** `socketio.run(app, debug=True)` daje dostęp do interaktywnego debuggera Pythona przez przeglądarkę. Remote Code Execution.
**Fix:**
```python
import os
DEBUG = os.getenv('FLASK_DEBUG', 'false').lower() == 'true'
socketio.run(app, debug=DEBUG, host='0.0.0.0', port=int(os.getenv('PORT', 5000)))
```
**Czas:** 10 minut

---

### P0-2. USUŃ AUTO-RESET HASEŁ PRZY STARCIE
**Plik:** `wsgi.py:12-13`
**Problem:** Każdy restart serwera uruchamia `skrypthasla.py` który resetuje hasło admin do `Nokia5310!` / `admin123`. Persistent backdoor.
**Fix:** Usuń linie 12-13 z wsgi.py:
```python
# USUŃ TE LINIE:
# subprocess.run([sys.executable, 'skrypthasla.py'])
```
Oraz usuń wywołanie `auto_update_admin_password()` z `init_database()` w app.py:134.
**Czas:** 5 minut

---

### P0-3. ZMIEŃ SECRET_KEY NA LOSOWY
**Plik:** `app.py:151`
**Problem:** `SECRET_KEY = 'dev-secret-key-change-in-production'` - każdy może podrobić session cookie.
**Fix:**
```python
app.config['SECRET_KEY'] = os.environ['SECRET_KEY']  # WYMAGAJ, nie fallback
```
Na Render dodaj zmienną środowiskową: `SECRET_KEY=<64-znakowy losowy string>`
Wygeneruj: `python -c "import secrets; print(secrets.token_hex(32))"`
**Czas:** 5 minut

---

### P0-4. OGRANICZ CORS
**Plik:** `app.py:191`
**Problem:** `cors_allowed_origins="*"` pozwala na requesty z dowolnej strony.
**Fix:**
```python
ALLOWED_ORIGINS = os.getenv('CORS_ORIGINS', 'https://adeptai.pl').split(',')
socketio = SocketIO(app, cors_allowed_origins=ALLOWED_ORIGINS, ...)
```
**Czas:** 10 minut

---

### P0-5. USUŃ CREDENTIALS Z LOGIN.HTML
**Plik:** `templates/login.html:302-304`
**Problem:** Hasła testowe widoczne dla każdego kto wejdzie na stronę logowania.
**Fix:** Usuń sekcję "Konta testowe" z HTML. Przenieś do osobnego dokumentu admina.
**Czas:** 5 minut

---

### P0-6. STWÓRZ PLIK .env
**Problem:** Brak zarządzania sekretami. Wszystko hardcoded.
**Fix:** Stwórz `.env` i `.env.example`:
```env
# .env.example
SECRET_KEY=change-me-to-random-64-chars
DATABASE_URL=postgresql://user:pass@host:5432/dbname
FLASK_DEBUG=false
CORS_ORIGINS=https://adeptai.pl
ADMIN_PASSWORD=change-me
```
W app.py dodaj na początku:
```python
from dotenv import load_dotenv
load_dotenv()
```
**Czas:** 30 minut

---

### P0-7. MIGRACJA SQLite → PostgreSQL
**Problem:** Dane na Render giną przy każdym redeploy. Brak backupów. Brak skalowalności.
**Fix:** Patrz `POSTGRESQL_MIGRATION.md` - pełny plan migracji.
**Czas:** ~17 godzin (1-2 tygodnie)

---

### P0-8. ROZBIJ app.py NA MODUŁY
**Problem:** 3977 linii w jednym pliku. Każdy reviewer to zobaczy jako red flag.
**Fix:** Patrz `ARCHITECTURE_PROPOSAL.md` sekcja 5 - proponowana struktura modułów.
**Minimalny split (szybki):**
```
app.py (3977 lines) →
  app.py          (~400 lines - factory, config, startup)
  routes_bot.py   (~600 lines - moto + elektro bot endpoints)
  routes_auth.py  (~200 lines - login/logout)
  routes_admin.py (~500 lines - P2 admin API)
  routes_p3.py    (~200 lines - training data export)
  db_manager.py   (~500 lines - DatabaseManager, AdminState, QueryIntentManager)
  visitor.py      (~600 lines - visitor tracking, passive radar)
  utils.py        (~300 lines - PII scrubbing, lost value calc, helpers)
```
**Czas:** 8 godzin

---

## P1: SHOULD FIX FOR CREDIBILITY
> Te problemy nie blokują pitcha, ale znacząco wzmacniają wiarygodność techniczną.

### P1-1. DEDUPLIKACJA KODU MOTO/ELEKTRO
**Problem:** `ecommerce_bot.py` i `elektro_bot.py` to 95% copy-paste (~3400 linii duplikacji). To samo z `script.js` i `script_elektro.js`.
**Fix:** Klasa bazowa `BaseLDIBot` + dziedziczenie (patrz ARCHITECTURE_PROPOSAL.md sekcja 6).
**Czas:** 6 godzin

### P1-2. TESTY AUTOMATYCZNE (pytest)
**Problem:** Brak test suite. Jedynie `testbot.py` z ręcznymi scenariuszami.
**Fix:**
```
tests/
├── test_bot_accuracy.py      (port testbot.py do pytest)
├── test_reward_engine.py     (unit testy reward calculators)
├── test_pii_scrubber.py      (test scrub_pii z edge cases)
├── test_api_endpoints.py     (integration testy Flask routes)
└── conftest.py               (fixtures, test DB)
```
Dodaj do requirements.txt: `pytest`, `pytest-flask`, `pytest-cov`
**Czas:** 8 godzin

### P1-3. RATE LIMITER - AKTYWUJ
**Problem:** Flask-Limiter skonfigurowany (app.py:143-148) ale żaden endpoint publiczny nie ma `@limiter.limit()`.
**Fix:** Dodaj dekorator do publicznych endpointów:
```python
@app.route('/api/v1/init', methods=['POST'])
@limiter.limit("30/minute")  # DODAJ TO
def api_init(): ...
```
Endpointy do zabezpieczenia: `/api/v1/*`, `/api/receive_event`, `/api/reset_demo`, wszystkie `/bot/send`, `/bot/start`.
**Czas:** 1 godzina

### P1-4. SESSION_COOKIE_SECURE + HTTPS
**Problem:** `SESSION_COOKIE_SECURE = False` (app.py:155). Cookies przesyłane przez HTTP.
**Fix:**
```python
app.config['SESSION_COOKIE_SECURE'] = not DEBUG  # True w produkcji
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
```
Render zapewnia HTTPS - wystarczy włączyć flagę.
**Czas:** 5 minut

### P1-5. FLASK-TALISMAN - AKTYWUJ
**Problem:** W requirements.txt ale nigdzie nie użyty. Daje security headers (HSTS, CSP, X-Frame-Options).
**Fix:**
```python
from flask_talisman import Talisman
if not DEBUG:
    Talisman(app, content_security_policy=None, force_https=True)
```
**Czas:** 15 minut

### P1-6. NAPRAW SQL INJECTION
**Plik:** `app.py:3289, 3303`
**Problem:** f-string w ALTER TABLE i CREATE INDEX.
**Fix:** Użyj whitelisty dozwolonych kolumn zamiast dynamicznego SQL:
```python
ALLOWED_COLUMNS = {
    'radar_status': 'TEXT DEFAULT "Przegląda"',
    'radar_company': 'TEXT',
    'anonymous_mode': 'BOOLEAN DEFAULT FALSE',
    # ... pełna lista
}
for col_name, col_type in ALLOWED_COLUMNS.items():
    # Bezpieczne - col_name z hardcoded dict, nie z user input
    cursor.execute(f'ALTER TABLE visitor_sessions ADD COLUMN {col_name} {col_type}')
```
**Czas:** 30 minut

### P1-7. ZABEZPIECZ PUBLICZNE API
**Problem:** `/api/v1/init`, `/api/v1/chat`, `/api/v1/event` nie wymagają żadnej autoryzacji. Ktokolwiek może ich używać.
**Fix:** Dodaj API key validation:
```python
def require_api_key(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        api_key = request.headers.get('X-API-Key') or request.json.get('api_key')
        if not validate_api_key(api_key):
            return jsonify({'error': 'Invalid API key'}), 401
        return f(*args, **kwargs)
    return decorated
```
**Czas:** 2 godziny

### P1-8. MONITORING (Sentry)
**Problem:** Błędy logowane do pliku i print(). Brak alertów.
**Fix:**
```python
import sentry_sdk
sentry_sdk.init(dsn=os.getenv('SENTRY_DSN'), traces_sample_rate=0.1)
```
Free tier Sentry = 5K events/month. Wystarczy.
**Czas:** 30 minut

### P1-9. DOCUMENTATION (README.md)
**Problem:** Brak README. Każdy repo bez README wygląda amatorsko.
**Fix:** Napisz README.md z: overview, architektura, setup, API, screenshots.
**Czas:** 2 godziny

### P1-10. USUŃ PRINT PASSWORDS Z LOGÓW
**Pliki:** `auth_manager.py:168-172`, `skrypthasla.py:88-96`
**Problem:** Hasła drukowane w konsoli: `print(f"[DEBUG] Password check: '{password}' vs stored hash")`
**Fix:** Usuń wszystkie linie które logują hasła.
**Czas:** 15 minut

---

## P2: NICE TO HAVE (Polish)
> Poprawiają jakość ale nie są krytyczne.

### P2-1. CONNECTION POOLING
**Problem:** 71x `sqlite3.connect()` - każdy request otwiera/zamyka połączenie. Przy PostgreSQL to będzie katastrofa.
**Fix:** psycopg2.pool.ThreadedConnectionPool (opisane w POSTGRESQL_MIGRATION.md)

### P2-2. N+1 QUERIES W ADMIN DASHBOARD
**Problem:** app.py:1895-1921 - zagnieżdżone zapytania w pętli. 20 firm = 60+ queries.
**Fix:** Użyj JOIN lub batch query z IN clause.

### P2-3. CLEANUP api_sessions MEMORY LEAK
**Problem:** `api_sessions = {}` (app.py:856) rośnie bez limitu. Brak TTL, brak cleanup.
**Fix:** Dodaj background task czyszczący sesje starsze niż 1h:
```python
def cleanup_api_sessions():
    cutoff = time.time() - 3600
    expired = [k for k, v in api_sessions.items() if v['start_time'] < cutoff]
    for k in expired:
        del api_sessions[k]
```

### P2-4. CSS SPLIT
**Problem:** `unified_style.css` = 2600 linii. Trudne do utrzymania.
**Fix:** Split na: `base.css`, `bot.css`, `dashboard.css`, `admin.css`.

### P2-5. USUŃ forteca.db
**Problem:** Pusty plik (0 bytes), nigdzie nie używany.
**Fix:** `rm forteca.db`, dodaj do .gitignore.

### P2-6. DUPLIKAT ensure_tables_exist()
**Problem:** `auth_manager.py` ma dwie identyczne definicje `ensure_tables_exist()` (linia 576 i 628).
**Fix:** Usuń drugą kopię.

### P2-7. GIT HISTORY CLEANUP
**Problem:** Commit messages typu "kurwa dziala ten p2 jebany w koncu", "backup ratowaaaaaaaaanko"
**Fix:** Przed acqui-hire pitch: `git rebase -i` i squash/rename problematycznych commitów.

### P2-8. PRODUKTY Z PLIKU ZAMIAST HARDCODED
**Problem:** 68 produktów zahardcodowanych w `ecommerce_bot.py:426-495`. products.json istnieje ale nie jest używany.
**Fix:** Załaduj z products.json w `initialize_data()`.

### P2-9. ALEMBIC MIGRATIONS
**Problem:** Schema changes przez ręczne skrypty (fix.py, migrate.py, fix_database.py).
**Fix:** `pip install alembic` → `alembic init migrations` → proper migration files.

### P2-10. TYPING + DOCSTRINGS
**Problem:** Brak type hints w app.py. Docstrings po polsku.
**Fix:** Dodaj type hints do kluczowych funkcji. Nowe docstrings po angielsku.

---

## PODSUMOWANIE CZASOWE

| Priorytet | Ilość fixów | Szacowany czas | Deadline |
|-----------|-------------|----------------|----------|
| **P0** | 8 fixów | ~20h (2-3 dni intensive) | Przed KAŻDYM pitchem |
| **P1** | 10 fixów | ~20h (3-4 dni) | Przed poważnym pitchem |
| **P2** | 10 fixów | ~15h (2-3 dni) | When time permits |
| **TOTAL** | 28 fixów | ~55h | 2-3 tygodnie |

### Sugerowana kolejność pracy:
```
Dzień 1:  P0-1, P0-2, P0-3, P0-4, P0-5 (security quick wins - 35 min)
Dzień 1:  P0-6 (.env setup - 30 min)
Dzień 1:  P1-4, P1-5, P1-10 (more security - 35 min)
          ─── Po Dniu 1: System jest bezpieczny ───
Dzień 2-3: P0-8 (split app.py - 8h)
Dzień 4:   P1-1 (bot dedup - 6h)
Dzień 5-6: P0-7 (PostgreSQL - start)
Tydzień 2: P0-7 (PostgreSQL - finish), P1-2 (testy)
Tydzień 3: P1-3 do P1-9, P2-*
```
