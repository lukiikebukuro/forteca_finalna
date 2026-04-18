# LDI AUDIT REPORT
## Lost Demand Intelligence - Full System Audit
**Date:** 2026-02-05 | **Auditor:** Claude Code | **Scope:** Full codebase, architecture, security, performance

---

## 1. EXECUTIVE SUMMARY

The LDI system is a **functional MVP** with genuine innovation in intent classification and reward signal design. The NLP engine (ecommerce_bot.py) is impressive - a hand-crafted fuzzy matching system with automotive domain knowledge covering 300+ car brands, 500+ models, mechanic slang, multilingual terms, and typo correction. The 93% test accuracy claim is plausible based on the 100-scenario test suite.

**What works well:**
- Intent classification engine with real domain expertise
- 3-tier access control (P1/P2/P3) with proper Flask-Login integration
- Real-time WebSocket dashboard with live visitor tracking ("Passive Radar")
- LDI Reward Signal calculator with proper normalization [-1.0, +1.0]
- GDPR/RODO compliance layer (IP hashing, PII scrubbing, data retention)
- JSONL export endpoint already functional
- Dual-bot architecture (moto + elektro) proves system generalizability

**What needs immediate attention:**
- **CRITICAL security vulnerabilities** (debug=True in prod, hardcoded passwords auto-reset on restart, CORS=*)
- **SQLite on Render** = data loss risk (NOT cross-device synced - see Section 3)
- **Massive code duplication** (~2000 lines duplicated between moto/elektro routes and JS)
- **No tests** beyond the manual testbot.py scenarios
- **app.py is 3977 lines** - monolithic, hard to maintain

**Verdict:** The innovation is real. The engineering needs hardening before any acqui-hire pitch. Current state = "brilliant prototype with production-grade aspirations."

---

## 2. ARCHITECTURE ANALYSIS

### Current Flow
```
User Query (Browser)
    │
    ├─ 200ms debounce ──→ performSearch() → UI suggestions (frontend only)
    │
    └─ 800ms debounce ──→ sendFinalAnalysis() → POST /api/analyze_query
                              │
                              ├─ PII Scrubbing (scrub_pii)
                              ├─ Bot Analysis (moto_bot/elektro_bot)
                              │   └─ get_fuzzy_product_matches()
                              │       ├─ Typo correction
                              │       ├─ Slang translation
                              │       ├─ Fuzzy matching (fuzzywuzzy)
                              │       └─ Intent classification (HIGH/MEDIUM/LOW/NO_MATCH)
                              │
                              ├─ Decision Mapping (MOTO/ELEKTRO rules differ)
                              ├─ Lost Value Calculation
                              ├─ Database Insert (events table)
                              ├─ Company Data Persistence
                              ├─ Hot Lead Detection
                              ├─ Log Entry
                              └─ WebSocket Broadcast → P1 + P2 Dashboards
```

### Code Structure
```
forteca_finalna/
├── app.py                  (3977 lines - MONOLITH, needs splitting)
├── ecommerce_bot.py        (1700+ lines - NLP engine, moto)
├── elektro_bot.py          (1700+ lines - 95% duplicate of ecommerce_bot.py)
├── reward_engine.py        (278 lines - well-structured, two calculators)
├── auth_manager.py         (676 lines - Flask-Login, 3 roles, DUPLICATED ensure_tables_exist)
├── wsgi.py                 (39 lines - Gunicorn entry point)
├── createdb.py             (15 lines - DB initialization)
├── skrypthasla.py          (password reset script - SECURITY RISK)
├── testbot.py              (280 lines - 100 business test scenarios)
├── templates/
│   ├── admin-dashboard.html    (1250 lines - P2)
│   ├── client-dashboard.html   (741 lines - P1)
│   ├── debug_dashboard.html    (327 lines - P3)
│   ├── demo_page.html          (500+ lines - moto demo)
│   ├── demo_page_elektro.html  (500+ lines - elektro demo)
│   ├── index.html              (landing page)
│   ├── login.html              (326 lines - credentials displayed!)
│   ├── tech.html               (API docs)
│   ├── privacy.html            (RODO policy)
│   └── unauthorized.html       (403 page)
├── static/
│   ├── admin_dashboard.js      (1131 lines - P2 frontend)
│   ├── dashboard.js            (887 lines - P1 frontend)
│   ├── script.js               (1036 lines - moto bot UI)
│   ├── script_elektro.js       (1038 lines - elektro bot UI, 95% duplicate)
│   ├── visitor_tracking.js     (796 lines - SATELITA v2.0 GDPR tracker)
│   └── unified_style.css       (2600 lines - all styling)
├── dashboard.db                (592 KB - primary database)
├── forteca.db                  (0 bytes - unused!)
└── requirements.txt            (18 dependencies)
```

### Separation of Concerns Assessment
| Area | Status | Issue |
|------|--------|-------|
| NLP Engine | GOOD | Properly separated in ecommerce_bot.py |
| Reward Signal | GOOD | Clean module in reward_engine.py |
| Auth | OK | auth_manager.py works, but has duplicate functions |
| Routes | BAD | All 50+ routes in single app.py |
| Database | BAD | No ORM, raw SQL scattered across 71 connection calls |
| Frontend | BAD | script.js and script_elektro.js are 95% identical |
| Config | BAD | Hardcoded values, no .env, no config module |

### Antygravity P3 Integration Quality
The P3 (debug_dashboard.html) is **minimal but functional**:
- 327 lines of HTML/JS
- Shows query intent logs with reward scores
- Has JSONL export button
- Fetches from `/api/p3/query-intents` and `/api/export-training-data`
- Color-codes reward scores (green >0.3, red <-0.3)
- Auto-refreshes every 30 seconds
- **Quality: Alpha** - works but no polish, missing error handling

---

## 3. DATABASE MYSTERY - SOLVED

### The Answer: SQLite on Render's Ephemeral Filesystem

**There is NO cross-device sync.** Here's what actually happens:

1. `dashboard.db` (592KB) sits on Render's instance filesystem
2. Render uses a single instance (free/starter plan) so there's only one copy
3. Data persists across **restarts** (process restarts keep the filesystem)
4. Data is **LOST on redeployments** (new deploy = new filesystem)
5. The "it works" illusion comes from the fact that only one instance exists

**Evidence:**
- All 71 `sqlite3.connect()` calls use relative path `'dashboard.db'`
- No cloud sync code anywhere (no Redis, no S3, no PostgreSQL)
- `wsgi.py` recreates DB if missing (line 10-13): `if not os.path.exists('dashboard.db')`
- Comment at line 855: `"In-memory storage for active API sessions (in production: Redis)"`
- No persistent disk configuration found

**Risk Level: CRITICAL**
- Any Render redeploy = all data lost
- Any Render outage = all data lost
- Cannot scale to multiple instances
- No backups exist

### Schema Overview (10 tables)
| Table | Purpose | Records (est.) |
|-------|---------|---------------|
| users | Authentication (3 roles) | ~3 |
| clients | B2B company accounts | ~1 |
| events | Query classifications | Growing daily |
| visitor_sessions | GDPR-compliant tracking | Growing daily |
| admin_dashboard_state | P2 panel state | ~3 keys |
| companies | Persistent company data | Growing |
| hot_leads | High-value prospects | Growing |
| log_history | Audit trail | Growing |
| query_intents | P3 training data | Growing |
| bot_messages | Chat transcripts | Growing |

### Performance Assessment
- **Indexes:** Present on critical columns (timestamp, decision, session_id) - GOOD
- **Missing indexes:** `events.query_text` (needed for dedup), `visitor_sessions.organization`
- **N+1 queries:** Admin dashboard makes nested queries in loops (lines 1895-1921) - BAD
- **Connection pooling:** None - opens/closes per query - ACCEPTABLE for SQLite but terrible for PostgreSQL migration
- **Data retention:** 30-day cleanup exists (RODO compliance) - GOOD
- **Deduplication:** Double-check with 5s and 2s windows - GOOD but CPU-expensive

### SQL Injection Risks
| Location | Severity | Code |
|----------|----------|------|
| app.py:3289 | HIGH | `f'ALTER TABLE visitor_sessions ADD COLUMN {col_name} {col_type}'` |
| app.py:3303 | HIGH | `f'CREATE INDEX IF NOT EXISTS {idx_name} ON visitor_sessions({idx_column})'` |
| app.py:1901 | MEDIUM | `f'%{org}%'` in LIKE clause (org from DB, not user input) |
| All other queries | SAFE | Use parameterized `?` placeholders |

---

## 4. TECH DEBT ASSESSMENT (Priority Ranked)

### P0 - MUST FIX (Blocks acqui-hire)
1. **app.py monolith** (3977 lines) → Split into modules
2. **Hardcoded credentials** (admin123, demo123, Nokia5310!) → Environment variables
3. **debug=True in production** → Conditional based on environment
4. **CORS=*** → Whitelist specific origins
5. **Password auto-reset on wsgi startup** → Remove skrypthasla.py auto-run
6. **No .env file** → Implement proper secret management
7. **SQLite in production** → PostgreSQL migration (see POSTGRESQL_MIGRATION.md)

### P1 - SHOULD FIX (Credibility)
8. **Code duplication** (moto/elektro) → Single parameterized bot class
9. **No test suite** → pytest with CI/CD
10. **No API documentation** → OpenAPI/Swagger spec
11. **No error monitoring** → Sentry integration
12. **Session cookie insecure** → HTTPS + Secure flag
13. **Rate limiter unused** → Apply to all public endpoints
14. **SQL injection in schema migration** → Parameterize

### P2 - NICE TO HAVE (Polish)
15. **CSS file too large** (2600 lines) → Split/minimize
16. **Console.log/print statements everywhere** → Proper logging
17. **No database migrations framework** → Alembic
18. **auth_manager.py has duplicate ensure_tables_exist** → Remove duplicate
19. **forteca.db is 0 bytes** → Delete unused file
20. **Git commit messages in Polish with profanity** → Clean history

---

## 5. SECURITY FINDINGS

### CRITICAL (Immediate Action Required)
| # | Finding | Impact | Location |
|---|---------|--------|----------|
| S1 | `debug=True` in production SocketIO | Remote code execution via debugger | app.py:3977 |
| S2 | `cors_allowed_origins="*"` | CSRF from any website | app.py:191 |
| S3 | Password auto-reset to `admin123` on every restart | Persistent backdoor | wsgi.py:13 + skrypthasla.py |
| S4 | SECRET_KEY = `'dev-secret-key-change-in-production'` | Session forgery | app.py:151 |
| S5 | Test credentials displayed in login.html | Anyone can access admin | login.html:302-304 |

### HIGH
| # | Finding | Impact | Location |
|---|---------|--------|----------|
| S6 | SQL injection via f-string in ALTER TABLE | Schema manipulation | app.py:3289,3303 |
| S7 | SESSION_COOKIE_SECURE=False | Cookie theft via HTTP | app.py:155 |
| S8 | Rate limiter configured but never applied | DDoS vulnerability | app.py:143-148 |
| S9 | No HTTPS enforcement | All traffic unencrypted | app.py |
| S10 | Flask-Talisman imported but not used | Missing security headers | requirements.txt |
| S11 | Public API endpoints `/api/v1/*` have no auth | Unauthorized access | app.py:860-998 |

### MEDIUM
| S12 | Passwords printed to console/logs | Log file capture | skrypthasla.py, auth_manager.py:168-172 |
| S13 | Database files committed to git | Data exposure in repo | git history |
| S14 | No CSRF protection on forms | Cross-site attacks | login form |
| S15 | api_sessions stored in memory | Data loss, no limit on growth | app.py:856 |

---

## 6. PERFORMANCE BOTTLENECKS

1. **N+1 queries in admin dashboard** - Nested SQL queries in loop (lines 1895-1921). For 20 companies, this runs 60+ queries. Fix: JOIN or batch query.

2. **Bot initialization creates new instance per API session** (line 880): `'bot_instance': MotoBot()`. Each MotoBot loads 68 products + massive dictionaries into memory.

3. **No connection pooling** - Each request opens/closes SQLite connection. Acceptable for SQLite but will be a disaster with PostgreSQL.

4. **In-memory session storage** (api_sessions dict) - No TTL, no cleanup, unbounded growth. Will consume all memory over time.

5. **fuzzywuzzy without python-Levenshtein optimization** - The C extension is in requirements.txt (good) but needs verification it's actually compiled.

6. **WebSocket broadcasts to all clients** - Every query triggers broadcast to both `client_demo` and `admin_dashboard` rooms. At scale, this becomes a bottleneck.

7. **Synchronous IP geolocation lookups** - visitor_tracking.js calls external APIs (ipify.org, ipapi.co) synchronously on page load.

### Scalability Assessment: 1M queries/month
- **Current architecture:** Would fail at ~10K queries/day (SQLite write locks, memory leaks from api_sessions)
- **With PostgreSQL + Redis:** Achievable with connection pooling
- **With proper queuing:** Kafka/RabbitMQ for async processing would handle 1M+ easily
- **WebSocket at scale:** Needs Redis adapter for SocketIO

---

## 7. REWARD SIGNAL ANALYSIS

### Two Calculators

**Legacy: RewardSignalCalculator** (for chatbot RLHF)
- Score range: raw (-100 to +200)
- Based on: purchase, cart_add, message engagement, duration sweet spot, vogal shift
- Used by: `/api/v1/event` endpoint
- Status: Legacy, maintained for backward compatibility

**Current: LDIRewardCalculator** (for product search, P3)
- Score range: normalized [-1.0, +1.0]
- Key signals:
  - `clicked_despite_no_match` = GOLD SIGNAL (+15 raw, highest weight)
  - `clicked_alternative` = +20 raw
  - `quick_click_bonus` (<10s) = +10 raw
  - `cart_add` = +35 raw
  - `purchase` = +50 raw
  - `bounce` = instant -1.0 (bypasses scoring)
  - `multiple_refinements` (>=3) = -15 raw
  - `long_session_no_action` (>3min) = -10 raw
- Normalization: `max(-1.0, min(1.0, score / 100.0))`
- Status: Active, well-designed

### Assessment
**Strengths:**
- Anti-bait design prevents gaming the system
- Gold signal (clicked_despite_no_match) captures genuine learning
- Normalization to [-1.0, +1.0] is standard for RLHF
- Logging is comprehensive

**Weaknesses:**
- No temporal weighting (recent signals should matter more)
- No confidence calibration (reward doesn't factor in match confidence)
- Binary signals only (clicked/not) - no dwell time or scroll depth
- No A/B testing framework to validate signal quality
- Cart value multiplier cap at 20 points seems arbitrary

### Scale AI / OpenAI Fine-tuning Compatibility
Current JSONL format from `/api/export-training-data`:
```json
{
  "query": "klocki bmw e90",
  "intent_label": "product_match",
  "confidence": "HIGH",
  "reward_signal": {
    "score": 0.45,
    "clicked_alternative": true,
    "purchased": false,
    "bounce": false
  },
  "missing_features": [],
  "matched_product_id": "KH001",
  "timestamp": "2025-12-01T15:30:00"
}
```

**Gap to target format:**
```json
{
  "query": "klocki bmw e90",
  "intent": "specific_product_search",
  "product_match": true,
  "reward_signal": 0.45,
  "metadata": {
    "confidence_level": "HIGH",
    "session_id": "uuid",
    "timestamp": "ISO8601",
    "source_bot": "moto",
    "query_language": "pl",
    "user_session_duration": 45.2,
    "query_refinement_count": 0
  }
}
```

Missing fields: `intent` classification label, `product_match` boolean, flattened reward_signal, session metadata, source bot, language detection.

---

## APPENDIX: FILE-BY-FILE ASSESSMENT

| File | Lines | Quality | Tech Debt |
|------|-------|---------|-----------|
| app.py | 3977 | 5/10 | CRITICAL - needs splitting into 8+ modules |
| ecommerce_bot.py | 1700+ | 7/10 | Good NLP, hardcoded products should be external |
| elektro_bot.py | 1700+ | 3/10 | 95% copy-paste from ecommerce_bot.py |
| reward_engine.py | 278 | 8/10 | Clean, well-structured, good documentation |
| auth_manager.py | 676 | 6/10 | Functional but has duplicate function, prints passwords |
| wsgi.py | 39 | 4/10 | Auto-resets passwords, dangerous |
| testbot.py | 280 | 7/10 | Good scenarios, needs pytest framework |
| admin_dashboard.js | 1131 | 8/10 | Professional, proper state management |
| dashboard.js | 887 | 8/10 | Good deduplication, counter animation |
| script.js | 1036 | 9/10 | Excellent debounce design (200ms/800ms) |
| script_elektro.js | 1038 | 3/10 | Pure code duplication |
| visitor_tracking.js | 796 | 9/10 | GDPR-first design, excellent |
| unified_style.css | 2600 | 8/10 | Professional, responsive |
