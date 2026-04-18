# LDI Architecture Deep Dive

**System:** Lost Demand Intelligence (LDI)
**Version:** 5.1 Production
**Last Updated:** 2026-02-06

---

## Table of Contents

1. [Data Flow: Query → Reward](#1-data-flow-query--reward)
2. [Reward Logic: Mathematical Model](#2-reward-logic-mathematical-model)
3. [RAG Compatibility: Vector Search Readiness](#3-rag-compatibility-vector-search-readiness)
4. [Production Readiness: Security Hardening](#4-production-readiness-security-hardening)

---

## 1. Data Flow: Query → Reward

### 1.1 High-Level Flow Diagram

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           USER INTERACTION LAYER                            │
├─────────────────────────────────────────────────────────────────────────────┤
│  Browser (demo_page.html)                                                   │
│       │                                                                     │
│       ▼ [200ms debounce - UI layer]                                        │
│  search-suggestions endpoint (real-time autocomplete)                       │
│       │                                                                     │
│       ▼ [800ms debounce - "Doktryna Cierpliwego Nasluchu"]                 │
│  analyze_query endpoint (final query submission)                            │
└─────────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                           PROCESSING LAYER                                  │
├─────────────────────────────────────────────────────────────────────────────┤
│  routes/bot.py :: analyze_query()                                           │
│       │                                                                     │
│       ├──► scrub_pii() [RODO compliance]                                   │
│       │                                                                     │
│       ├──► bot.get_fuzzy_product_matches(query, analyze_intent=True)       │
│       │         │                                                           │
│       │         ├──► analyze_query_intent() [NLP analysis]                 │
│       │         ├──► get_fuzzy_product_matches() [fuzzywuzzy scoring]      │
│       │         └──► Returns: (products[], confidence, type, analysis)     │
│       │                                                                     │
│       ├──► DECISION_MAPPING[confidence] → decision                         │
│       │         HIGH    → "ZNALEZIONE PRODUKTY"                            │
│       │         MEDIUM  → "ODFILTROWANE" (MOTO) / "ZNALEZIONE" (ELEKTRO)   │
│       │         LOW     → "ODFILTROWANE"                                   │
│       │         NO_MATCH → "UTRACONE OKAZJE"                               │
│       │                                                                     │
│       ├──► calculate_lost_value_internal() [if UTRACONE OKAZJE]            │
│       │                                                                     │
│       └──► DatabaseManager.add_event() [events table]                      │
└─────────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                           P3 REWARD LAYER                                   │
├─────────────────────────────────────────────────────────────────────────────┤
│  LDIRewardCalculator.calculate_from_dict(reward_data)                       │
│       │                                                                     │
│       ├──► Build LDISession dataclass                                      │
│       ├──► Apply reward weights and penalties                              │
│       ├──► Normalize to [-1.0, +1.0]                                       │
│       └──► Return reward_score                                             │
│                                                                             │
│  QueryIntentManager.add_query_intent({...})                                 │
│       │                                                                     │
│       └──► INSERT INTO query_intents (...)                                 │
└─────────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                           OUTPUT LAYER                                      │
├─────────────────────────────────────────────────────────────────────────────┤
│  WebSocket emit('live_feed_update') → Client Dashboard (P1)                 │
│  WebSocket emit('live_feed_update') → Admin Dashboard (P2)                  │
│  query_intents table → Debug Dashboard (P4)                                 │
│  /api/export-training-data → JSONL export for LLM fine-tuning              │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 1.2 Detailed Code Path

**Entry Point:** `routes/bot.py` line 373 (MOTO) / line 545 (ELEKTRO)

```python
@bot_bp.route('/motobot-prototype/api/analyze_query', methods=['POST'])
def analyze_query():
    # 1. Extract request data
    data = request.get_json()
    query = data.get('query', '').strip()
    session_id = data.get('session_id', None)

    # 2. RODO: Sanitize PII
    sanitized_query = scrub_pii(query)  # privacy.py

    # 3. NLP Analysis via bot
    result = bot.get_fuzzy_product_matches(
        sanitized_query,
        machine_filter=None,
        limit=6,
        analyze_intent=True
    )
    # Returns: (products, confidence_level, suggestion_type, analysis)

    # 4. Map confidence to business decision
    decision = MOTO_DECISION_MAPPING.get(confidence_level, 'ODFILTROWANE')

    # 5. Calculate potential value for lost opportunities
    if decision == 'UTRACONE OKAZJE':
        potential_value = calculate_lost_value_internal(sanitized_query)

    # 6. Save to events table (TCD - real-time dashboard)
    event_id = DatabaseManager.add_event(...)

    # 7. P3: Calculate reward and save to query_intents
    reward_data = {
        'session_id': session_id,
        'original_query': sanitized_query,
        'confidence_level': confidence_level,
        'was_lost_demand': decision == 'UTRACONE OKAZJE',
        # ... behavioral signals (initially False, updated by frontend)
    }
    reward_score = ldi_reward_calc.calculate_from_dict(reward_data)

    QueryIntentManager.add_query_intent({
        'query_text': sanitized_query,
        'confidence_level': confidence_level,
        'reward_score': reward_score,
        'best_match_score': best_match_score,
        'matched_product_id': matched_product_id,
        # ...
    })

    # 8. Emit to WebSocket for live dashboards
    socketio.emit('live_feed_update', feed_data, room='client_demo')
    socketio.emit('live_feed_update', feed_data, room='admin_dashboard')
```

### 1.3 Dual Debounce Architecture

```
User types: "i" "p" "h" "o" "n" "e" " " "1" "3"
            │   │   │   │   │   │   │   │   │
            ▼   ▼   ▼   ▼   ▼   ▼   ▼   ▼   ▼
         [200ms UI debounce - resets on each keystroke]
                                            │
                                            ▼
                              search-suggestions (autocomplete)
                                            │
                              [800ms backend debounce - "Doktryna Cierpliwego Nasluchu"]
                                            │
                                            ▼
                              analyze_query (FINAL - saved to DB)
```

**Why dual debounce?**
- 200ms: Prevents API spam during typing, provides responsive autocomplete
- 800ms: Ensures we capture the user's "final intent" - the pause indicates thinking completion

---

## 2. Reward Logic: Mathematical Model

### 2.1 LDIRewardCalculator Architecture

**File:** `reward_engine.py`
**Class:** `LDIRewardCalculator`

The reward calculator is designed for **product search optimization**, not chatbot RLHF. Key principle: **Reward MATCHING, not clickbait.**

### 2.2 Weight Configuration

```python
self.weights = {
    # MATCH QUALITY
    'high_confidence_match': 10.0,      # Direct product match
    'clicked_despite_no_match': 15.0,   # 🏆 GOLD SIGNAL

    # BEHAVIORAL QUALITY
    'clicked_alternative': 20.0,        # User engaged with suggestions
    'quick_click_bonus': 10.0,          # <10s to click = good match

    # CONVERSION
    'cart_add': 35.0,                   # Strong purchase intent
    'purchase': 50.0,                   # Actual conversion
    'cart_value_multiplier': 0.4,       # Per 100 PLN, cap at 20
}

self.penalties = {
    'bounce': -100.0,                   # Instant normalization to -1.0
    'multiple_refinements': -15.0,      # >=3 query changes = frustration
    'long_session_no_action': -10.0,    # >3min without click
}
```

### 2.3 Reward Calculation Formula

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         REWARD SCORE CALCULATION                            │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  IF bounce == True:                                                         │
│      RETURN -1.0  (instant penalty, no further calculation)                │
│                                                                             │
│  raw_score = 0.0                                                           │
│                                                                             │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │ LAYER 1: MATCH QUALITY                                              │   │
│  ├─────────────────────────────────────────────────────────────────────┤   │
│  │ IF confidence == 'HIGH':                                            │   │
│  │     raw_score += 10.0                                               │   │
│  │                                                                     │   │
│  │ ELIF confidence == 'NO_MATCH' AND clicked_alternative:              │   │
│  │     raw_score += 15.0  # GOLD SIGNAL                                │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │ LAYER 2: BEHAVIORAL QUALITY                                         │   │
│  ├─────────────────────────────────────────────────────────────────────┤   │
│  │ IF clicked_alternative:                                             │   │
│  │     raw_score += 20.0                                               │   │
│  │                                                                     │   │
│  │     IF 0 < time_to_first_click < 10:                                │   │
│  │         raw_score += 10.0  # Quick click bonus                      │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │ LAYER 3: ANTI-BAIT PENALTIES                                        │   │
│  ├─────────────────────────────────────────────────────────────────────┤   │
│  │ IF query_refinement_count >= 3:                                     │   │
│  │     raw_score += (-15.0)  # Frustration penalty                     │   │
│  │                                                                     │   │
│  │ IF session_duration > 180 AND NOT clicked_alternative:              │   │
│  │     raw_score += (-10.0)  # Long session, no engagement             │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │ LAYER 4: CONVERSION                                                 │   │
│  ├─────────────────────────────────────────────────────────────────────┤   │
│  │ IF added_to_cart:                                                   │   │
│  │     raw_score += 35.0                                               │   │
│  │     cart_bonus = min(cart_value * 0.4 / 100, 20.0)                  │   │
│  │     raw_score += cart_bonus                                         │   │
│  │                                                                     │   │
│  │ IF purchased:                                                       │   │
│  │     raw_score += 50.0                                               │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │ NORMALIZATION                                                       │   │
│  ├─────────────────────────────────────────────────────────────────────┤   │
│  │ normalized = max(-1.0, min(1.0, raw_score / 100.0))                 │   │
│  │ RETURN round(normalized, 4)                                         │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 2.4 Example Calculations

**Scenario 1: Perfect Match with Purchase**
```
confidence = HIGH           → +10.0
clicked_alternative = True  → +20.0
time_to_first_click = 5s    → +10.0 (quick click)
added_to_cart = True        → +35.0
cart_value = 500 PLN        → +2.0 (500 * 0.4 / 100 = 2.0)
purchased = True            → +50.0
────────────────────────────────────
raw_score = 127.0
normalized = min(1.0, 127/100) = 1.0
```

**Scenario 2: Lost Demand - User Found Alternative**
```
confidence = NO_MATCH       → +0.0
clicked_alternative = True  → +20.0 + 15.0 (GOLD SIGNAL)
time_to_first_click = 8s    → +10.0
────────────────────────────────────
raw_score = 45.0
normalized = 45/100 = 0.45
```

**Scenario 3: Frustrated User**
```
confidence = MEDIUM         → +0.0
query_refinement_count = 5  → -15.0
session_duration = 240s     → -10.0 (>180s, no click)
clicked_alternative = False → +0.0
────────────────────────────────────
raw_score = -25.0
normalized = -25/100 = -0.25
```

**Scenario 4: Instant Bounce**
```
bounce = True               → RETURN -1.0 (immediate)
```

### 2.5 Why These Weights?

| Signal | Weight | Rationale |
|--------|--------|-----------|
| `high_confidence_match` | +10 | System did its job - found what user wanted |
| `clicked_despite_no_match` | +15 | **GOLD**: User taught us something new |
| `clicked_alternative` | +20 | Engagement = search relevance |
| `quick_click_bonus` | +10 | Fast decision = accurate suggestion |
| `cart_add` | +35 | Strong commercial intent signal |
| `purchase` | +50 | Ultimate success metric |
| `bounce` | -100 | Complete failure (normalized to -1.0) |
| `multiple_refinements` | -15 | User struggling = bad UX |
| `long_session_no_action` | -10 | Wasted time = irrelevant results |

---

## 3. RAG Compatibility: Vector Search Readiness

### 3.1 query_intents Table Schema

```sql
CREATE TABLE query_intents (
    -- IDENTIFIERS
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id TEXT NOT NULL,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,

    -- QUERY DATA (RAG-ready)
    query_text TEXT NOT NULL,              -- Original user query
    confidence_level TEXT,                  -- HIGH/MEDIUM/LOW/NO_MATCH
    suggestion_type TEXT,                   -- Category/intent type

    -- MATCH QUALITY
    best_match_score INTEGER,               -- Fuzzy match score (0-100)
    matched_product_id TEXT,                -- ID of best matching product
    missing_attributes TEXT,                -- JSON: what user wanted but we lack

    -- BEHAVIORAL SIGNALS
    clicked_alternative INTEGER DEFAULT 0,  -- Boolean: user clicked suggestion
    query_refinement_count INTEGER DEFAULT 0,
    time_to_first_click REAL,              -- Seconds
    session_duration REAL,                  -- Seconds
    bounce INTEGER DEFAULT 0,               -- Boolean: instant exit

    -- CONVERSION
    added_to_cart INTEGER DEFAULT 0,
    purchased INTEGER DEFAULT 0,
    cart_value REAL DEFAULT 0.0,

    -- REWARD (P3 output)
    reward_score REAL                       -- Normalized [-1.0, +1.0]
);

-- Indexes for efficient querying
CREATE INDEX idx_qi_session ON query_intents(session_id);
CREATE INDEX idx_qi_timestamp ON query_intents(timestamp);
CREATE INDEX idx_qi_reward ON query_intents(reward_score);
```

### 3.2 RAG Integration Points

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                      RAG INTEGRATION ARCHITECTURE                           │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  CURRENT STATE (SQLite):                                                   │
│  ┌───────────────────┐                                                     │
│  │   query_intents   │                                                     │
│  │   ─────────────   │                                                     │
│  │   query_text      │◄──── Text for embedding                            │
│  │   reward_score    │◄──── Quality signal for ranking                    │
│  │   missing_attrs   │◄──── Gap analysis data                             │
│  │   confidence      │◄──── Filter/boost parameter                        │
│  └───────────────────┘                                                     │
│           │                                                                 │
│           ▼                                                                 │
│  FUTURE STATE (Vector DB):                                                 │
│  ┌───────────────────────────────────────────────────────────────────┐     │
│  │                         PINECONE / WEAVIATE / QDRANT              │     │
│  ├───────────────────────────────────────────────────────────────────┤     │
│  │  {                                                                │     │
│  │    "id": "qi_12345",                                              │     │
│  │    "vector": [0.12, -0.34, 0.56, ...],  // OpenAI embedding      │     │
│  │    "metadata": {                                                  │     │
│  │      "query_text": "iPhone 13 Pro Max 256GB",                     │     │
│  │      "confidence": "HIGH",                                        │     │
│  │      "reward_score": 0.65,                                        │     │
│  │      "was_lost_demand": false,                                    │     │
│  │      "missing_attributes": ["color:gold"],                        │     │
│  │      "matched_product": "iphone_13_pro_256",                      │     │
│  │      "timestamp": "2026-02-06T11:33:05"                           │     │
│  │    }                                                              │     │
│  │  }                                                                │     │
│  └───────────────────────────────────────────────────────────────────┘     │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 3.3 JSONL Export Format (LLM Fine-tuning Ready)

**Endpoint:** `GET /api/export-training-data?limit=5000`
**Format:** JSONL (newline-delimited JSON)

```jsonl
{"query":"iPhone 13 Pro Max 256GB","intent_label":"smartphone","confidence":"HIGH","reward_signal":{"score":0.65,"clicked_alternative":true,"purchased":false,"bounce":false},"missing_features":["color:gold"],"matched_product_id":"iphone_13_pro_256","timestamp":"2026-02-06T11:33:05"}
{"query":"OnePlus 12 Pro","intent_label":"elektronika","confidence":"NO_MATCH","reward_signal":{"score":-0.15,"clicked_alternative":false,"purchased":false,"bounce":false},"missing_features":[],"matched_product_id":null,"timestamp":"2026-02-06T11:35:12"}
```

### 3.4 RAG Use Cases

**Use Case 1: Similar Query Retrieval**
```python
# Future implementation
def find_similar_queries(user_query: str, top_k: int = 5):
    embedding = openai.embed(user_query)
    results = vector_db.search(
        vector=embedding,
        top_k=top_k,
        filter={"reward_score": {"$gt": 0.3}}  # Only positive outcomes
    )
    return results
```

**Use Case 2: Lost Demand Analysis**
```python
# Find queries where users wanted something we don't have
lost_demand = vector_db.search(
    filter={
        "confidence": "NO_MATCH",
        "clicked_alternative": True,  # GOLD signals
        "reward_score": {"$gt": 0}
    },
    top_k=100
)
# Analyze missing_attributes to identify inventory gaps
```

**Use Case 3: Query Understanding Improvement**
```python
# Use high-reward queries to improve NLP
training_data = vector_db.search(
    filter={"reward_score": {"$gt": 0.5}},
    top_k=1000
)
# Feed to LLM for intent classification fine-tuning
```

### 3.5 Migration Path to Vector DB

```
Phase 1 (Current):
  SQLite → query_intents table → JSONL export

Phase 2 (Near-term):
  Add embedding generation on INSERT
  Store embeddings in separate column (BLOB)

Phase 3 (Production):
  Migrate to Pinecone/Weaviate
  Dual-write: SQLite + Vector DB
  Enable semantic search in P4 dashboard

Phase 4 (Advanced):
  Real-time RAG for product suggestions
  LLM-powered "Did you mean?" using similar queries
  Automatic inventory gap detection
```

---

## 4. Production Readiness: Security Hardening

### 4.1 Security Fixes (Phase 1)

| Issue | Risk | Fix |
|-------|------|-----|
| Test credentials in login.html | HIGH | Removed hardcoded P1/P2 credentials from UI |
| `debug=True` in production | HIGH | DEBUG controlled by `FLASK_DEBUG` env only |
| No rate limiting on /api/v1/event | MEDIUM | Added `@limiter.limit("100/minute")` |
| SQL injection in ALTER TABLE | MEDIUM | Added `_allowed_cols` whitelist |
| Dead code with auth logic | LOW | Removed `auto_update_admin_password()` |

### 4.2 Security Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         SECURITY LAYERS                                     │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  LAYER 1: TRANSPORT                                                        │
│  ┌───────────────────────────────────────────────────────────────────┐     │
│  │  Flask-Talisman (production only)                                 │     │
│  │  ├── force_https=True                                             │     │
│  │  ├── strict_transport_security=True                               │     │
│  │  └── session_cookie_secure=True                                   │     │
│  └───────────────────────────────────────────────────────────────────┘     │
│                                                                             │
│  LAYER 2: RATE LIMITING                                                    │
│  ┌───────────────────────────────────────────────────────────────────┐     │
│  │  Flask-Limiter                                                    │     │
│  │  ├── Default: 2000/day, 200/hour                                  │     │
│  │  ├── Bot endpoints: 20/minute (start), 100/minute (send)          │     │
│  │  ├── API v1: 60/minute (init/chat), 100/minute (event)            │     │
│  │  └── Visitor tracking: 100/minute                                 │     │
│  └───────────────────────────────────────────────────────────────────┘     │
│                                                                             │
│  LAYER 3: AUTHENTICATION                                                   │
│  ┌───────────────────────────────────────────────────────────────────┐     │
│  │  Flask-Login + 3-tier RBAC                                        │     │
│  │  ├── client: P1 dashboard only                                    │     │
│  │  ├── admin: P1 + P2 dashboards                                    │     │
│  │  └── debug: P1 + P2 + P3 + P4 dashboards                          │     │
│  │                                                                   │     │
│  │  Decorators:                                                      │     │
│  │  ├── @login_required                                              │     │
│  │  ├── @require_client_access                                       │     │
│  │  ├── @require_admin_access                                        │     │
│  │  └── @require_debug_access                                        │     │
│  └───────────────────────────────────────────────────────────────────┘     │
│                                                                             │
│  LAYER 4: SESSION SECURITY                                                 │
│  ┌───────────────────────────────────────────────────────────────────┐     │
│  │  Cookie Configuration:                                            │     │
│  │  ├── SESSION_COOKIE_SECURE = True (production)                    │     │
│  │  ├── SESSION_COOKIE_HTTPONLY = True                               │     │
│  │  ├── SESSION_COOKIE_SAMESITE = 'Lax'                              │     │
│  │  └── PERMANENT_SESSION_LIFETIME = 24 hours                        │     │
│  └───────────────────────────────────────────────────────────────────┘     │
│                                                                             │
│  LAYER 5: INPUT VALIDATION                                                 │
│  ┌───────────────────────────────────────────────────────────────────┐     │
│  │  RODO/GDPR Compliance:                                            │     │
│  │  ├── scrub_pii() - removes emails, phones, IDs from queries       │     │
│  │  ├── hash_ip_address() - SHA-256 hashing                          │     │
│  │  ├── mask_ip_address() - 192.168.1.xxx format                     │     │
│  │  └── cleanup_old_sessions() - 30-day retention                    │     │
│  │                                                                   │     │
│  │  SQL Injection Prevention:                                        │     │
│  │  ├── Parameterized queries throughout                             │     │
│  │  └── Column whitelist for ALTER TABLE                             │     │
│  └───────────────────────────────────────────────────────────────────┘     │
│                                                                             │
│  LAYER 6: SECRET MANAGEMENT                                                │
│  ┌───────────────────────────────────────────────────────────────────┐     │
│  │  Environment Variables:                                           │     │
│  │  ├── SECRET_KEY - REQUIRED in production (raises RuntimeError)    │     │
│  │  ├── FLASK_DEBUG - controls debug mode                            │     │
│  │  └── .env file in .gitignore                                      │     │
│  └───────────────────────────────────────────────────────────────────┘     │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 4.3 RODO/GDPR Compliance

```python
# privacy.py

def scrub_pii(text: str) -> str:
    """Remove PII from user queries before storage."""
    patterns = [
        (r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', '[EMAIL]'),
        (r'\b\d{9,11}\b', '[PHONE]'),
        (r'\b\d{11}\b', '[PESEL]'),
        (r'\b\d{2}-\d{3}\b', '[POSTAL]'),
    ]
    for pattern, replacement in patterns:
        text = re.sub(pattern, replacement, text)
    return text

def hash_ip_address(ip: str) -> str:
    """One-way hash for IP anonymization."""
    return hashlib.sha256(ip.encode()).hexdigest()

def mask_ip_address(ip: str) -> str:
    """Partial masking: 192.168.1.xxx"""
    parts = ip.split('.')
    if len(parts) == 4:
        return f"{parts[0]}.{parts[1]}.{parts[2]}.xxx"
    return "masked"
```

### 4.4 Security Checklist

- [x] SECRET_KEY enforcement (RuntimeError if not set in production)
- [x] Debug mode disabled by default
- [x] HTTPS enforced via Flask-Talisman
- [x] Secure session cookies (HttpOnly, Secure, SameSite)
- [x] Rate limiting on all public endpoints
- [x] 3-tier RBAC (client/admin/debug)
- [x] PII scrubbing before database storage
- [x] IP hashing and masking (GDPR)
- [x] 30-day data retention with automatic cleanup
- [x] Parameterized SQL queries
- [x] No credentials in source code
- [x] .env in .gitignore

---

## Appendix A: Key Files Reference

| File | Lines | Purpose |
|------|-------|---------|
| `app.py` | 97 | Entry point, startup initialization |
| `config.py` | 153 | Flask app, extensions, bots, constants |
| `database.py` | 643 | DatabaseManager, QueryIntentManager, CRUD |
| `privacy.py` | 138 | RODO compliance functions |
| `reward_engine.py` | 278 | RewardSignalCalculator, LDIRewardCalculator |
| `routes/bot.py` | 760 | Bot endpoints with P3 integration |
| `routes/api.py` | 1058 | Headless API, admin, debug endpoints |
| `routes/pages.py` | 463 | Static pages, auth, dashboards |

---

## Appendix B: Environment Variables

```bash
# REQUIRED
SECRET_KEY=<64-character-random-string>

# OPTIONAL
FLASK_DEBUG=false                    # true for development
DATABASE_URL=                        # PostgreSQL URL (uses SQLite if empty)
CORS_ORIGINS=https://adeptai.pl      # Comma-separated
RATE_LIMIT_STORAGE=memory://         # Or redis://host:port
PORT=5000                            # Server port
```

---

*Document generated for LDI v5.1 Production*
*Last updated: 2026-02-06*
