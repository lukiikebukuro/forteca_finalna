# ARCHITECTURE PROPOSAL
## LDI System Redesign - P1/P2/P3/P4 + JSONL Export
**Date:** 2026-02-05

---

## 1. CURRENT STATE vs PROPOSED STATE

### Current (3 Levels)
```
P1 (Client Dashboard)    → Metrics, live feed, lost products report
P2 (Admin Dashboard)     → Hot leads, passive radar, visitor tracking, company cards
P3 (Debug Dashboard)     → Raw query intent logs, JSONL export, reward scores
```

### Problems with Current
1. P2 mixes B2B sales intelligence with admin functions
2. P3 is minimal (327 lines) and has no real debug capability
3. No clear separation between "debug" and "training data management"
4. JSONL export exists but format needs enrichment
5. No data validation or quality dashboard

### Proposed (4 Levels)
```
P1 (Client Dashboard)    → B2B customer-facing analytics
P2 (Sales Intelligence)  → Hot leads, company radar, conversion tracking
P3 (Training Data Hub)   → JSONL management, reward signal tuning, data quality
P4 (System Debug)        → Raw logs, performance metrics, error tracking, system health
```

---

## 2. LEVEL REDESIGN

### P1 - Client Dashboard (keep, enhance)
**Audience:** E-commerce clients paying for reports
**Access:** `@require_client_access`

Current features (keep):
- Daily/weekly metrics (found, lost, filtered)
- Live feed of query classifications
- Top missing products chart
- Gap analysis chart

Enhancements:
- PDF weekly report download (endpoint exists but needs content)
- Trend comparison (this week vs last week)
- Lost revenue calculator with actual product prices
- Actionable recommendations ("Add these 5 products to capture 12K PLN/month")

### P2 - Sales Intelligence (refactor from current P2)
**Audience:** Internal sales team, system owner
**Access:** `@require_admin_access`

Keep:
- Hot Leads B2B cards with engagement scoring
- Passive Radar (live visitor tracking)
- Company database with query history
- Log history (Matrix view)

Remove:
- Debug-related functions (move to P4)
- Raw log access (move to P4)
- Database fix endpoint (move to P4)

Add:
- Lead scoring algorithm configuration
- Company CRM integration hooks
- Email alert triggers for high-value leads
- Conversion funnel visualization
- ROI calculator for acqui-hire pitch

### P3 - Training Data Hub (NEW - major expansion)
**Audience:** ML engineers, AI researchers, data scientists
**Access:** `@require_debug_access` (rename to `@require_researcher_access`)

This is the **core value proposition** for acqui-hire. Current P3 is 327 lines - needs 10x expansion.

Features:
```
┌─────────────────────────────────────────────────────┐
│  P3: LDI Training Data Hub                          │
├─────────────────────────────────────────────────────┤
│                                                     │
│  ┌─────────────┐  ┌─────────────┐  ┌────────────┐ │
│  │ Data Quality │  │ Reward      │  │ Export     │ │
│  │ Dashboard    │  │ Signal Lab  │  │ Pipeline   │ │
│  │             │  │             │  │            │ │
│  │ - Total     │  │ - Score     │  │ - JSONL    │ │
│  │   records   │  │   histogram │  │ - CSV      │ │
│  │ - Coverage  │  │ - Weight    │  │ - Parquet  │ │
│  │   by intent │  │   tuning    │  │ - API      │ │
│  │ - Missing   │  │ - Gold      │  │ - S3 push  │ │
│  │   labels    │  │   signals   │  │ - Schedule │ │
│  │ - Drift     │  │ - Anti-bait │  │ - Filter   │ │
│  │   detection │  │   monitor   │  │            │ │
│  └─────────────┘  └─────────────┘  └────────────┘ │
│                                                     │
│  ┌─────────────────────────────────────────────┐   │
│  │ Query Intent Browser                         │   │
│  │ ┌──────┬──────┬────┬────────┬───────┬─────┐ │   │
│  │ │Time  │Query │Conf│Reward  │Clicked│Match│ │   │
│  │ ├──────┼──────┼────┼────────┼───────┼─────┤ │   │
│  │ │15:30 │klocki│HIGH│ +0.45  │  Yes  │KH001│ │   │
│  │ │15:31 │tesla │NONE│ -0.20  │  No   │ --- │ │   │
│  │ │15:32 │bmw   │HIGH│ +0.80  │  Yes  │KH001│ │   │
│  │ └──────┴──────┴────┴────────┴───────┴─────┘ │   │
│  │ [Filter] [Sort] [Annotate] [Export Selected] │   │
│  └─────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────┘
```

### P4 - System Debug (NEW)
**Audience:** DevOps, system admin
**Access:** `@require_debug_access`

Features:
- Real-time error log viewer
- Performance metrics (response times, DB query times)
- WebSocket connection monitor
- Database table sizes and index usage
- Memory usage (api_sessions size)
- Rate limiter statistics
- System health dashboard
- Emergency database fix tools
- Bot accuracy live testing console

---

## 3. JSONL EXPORT SYSTEM ARCHITECTURE

### Current State
- Endpoint: `GET /api/export-training-data?limit=1000`
- Format: Application/x-ndjson
- Access: Debug role only
- Data source: query_intents table
- Output format: Basic (missing metadata)

### Proposed Architecture
```
┌──────────────────────────────────────────────────┐
│  JSONL Export Pipeline                            │
├──────────────────────────────────────────────────┤
│                                                  │
│  Data Sources:                                   │
│  ├── query_intents table (P3 reward signals)     │
│  ├── events table (classifications)              │
│  ├── visitor_sessions (behavioral context)        │
│  └── bot analysis metadata                       │
│                                                  │
│  Processing:                                     │
│  ├── JOIN query_intents + events + sessions      │
│  ├── Enrich with session metadata                │
│  ├── Apply PII scrubbing                         │
│  ├── Validate data quality (completeness check)  │
│  └── Format to target schema                     │
│                                                  │
│  Export Modes:                                   │
│  ├── /api/v2/export/jsonl (download file)        │
│  ├── /api/v2/export/stream (streaming NDJSON)    │
│  ├── /api/v2/export/batch (scheduled job)        │
│  └── /api/v2/export/s3 (push to S3 bucket)      │
│                                                  │
│  Filters:                                        │
│  ├── date_from, date_to                          │
│  ├── min_reward, max_reward                      │
│  ├── confidence_level (HIGH/MEDIUM/LOW/NO_MATCH) │
│  ├── source_bot (moto/elektro)                   │
│  ├── has_conversion (true/false)                 │
│  └── is_gold_signal (clicked_despite_no_match)   │
└──────────────────────────────────────────────────┘
```

### Target JSONL Format (OpenAI Fine-tuning Compatible)
```json
{
  "query": "klocki bmw e90",
  "intent": "specific_product_search",
  "product_match": true,
  "reward_signal": 0.45,
  "metadata": {
    "confidence_level": "HIGH",
    "suggestion_type": "direct_match",
    "best_match_score": 92,
    "session_id": "a1b2c3d4",
    "timestamp": "2025-12-01T15:30:00Z",
    "source_bot": "moto",
    "source_industry": "automotive",
    "query_language": "pl",
    "session_duration_seconds": 45.2,
    "query_refinement_count": 0,
    "time_to_first_click_seconds": 3.5,
    "clicked_alternative": true,
    "added_to_cart": false,
    "purchased": false,
    "bounce": false,
    "was_lost_demand": false,
    "matched_product_id": "KH001",
    "matched_product_name": "Klocki hamulcowe przód Bosch BMW E90 320i",
    "missing_attributes": [],
    "visitor_country": "PL",
    "visitor_city_hash": "hash_a1b2c3d4"
  }
}
```

### API Specification
```
GET /api/v2/export/jsonl
  Headers:
    Authorization: Bearer <api_key>
  Query Parameters:
    limit: int (default 1000, max 100000)
    offset: int (default 0)
    date_from: ISO8601
    date_to: ISO8601
    min_reward: float (-1.0 to 1.0)
    max_reward: float (-1.0 to 1.0)
    confidence: HIGH|MEDIUM|LOW|NO_MATCH (comma-separated)
    source: moto|elektro
    format: jsonl|csv|parquet
  Response:
    Content-Type: application/x-ndjson
    Content-Disposition: attachment; filename="ldi_training_{date}_{count}.jsonl"
```

---

## 4. REWARD SIGNAL IMPROVEMENTS

### Current LDIRewardCalculator Issues
1. No temporal decay (old sessions weight same as recent)
2. No confidence-weighted rewards (HIGH match with click should score higher than LOW match with click)
3. No A/B testing framework
4. No calibration against actual conversion data
5. Cart value cap seems arbitrary (20 points max)

### Proposed Enhancements

**A. Confidence-Weighted Scoring**
```python
confidence_multiplier = {
    'HIGH': 1.0,
    'MEDIUM': 0.8,
    'LOW': 0.5,
    'NO_MATCH': 1.2  # Higher weight because learning from mismatches is gold
}
score *= confidence_multiplier[session.confidence_level]
```

**B. Temporal Decay**
```python
days_old = (datetime.now() - session_timestamp).days
decay_factor = max(0.5, 1.0 - (days_old * 0.01))  # 1% decay per day, floor 0.5
score *= decay_factor
```

**C. Ensemble Reward (combine multiple signals)**
```python
final_reward = (
    0.4 * match_quality_score +
    0.3 * behavioral_score +
    0.2 * conversion_score +
    0.1 * session_quality_score
)
```

---

## 5. PROPOSED MODULE STRUCTURE (app.py split)

```
forteca_finalna/
├── app/
│   ├── __init__.py              (Flask app factory)
│   ├── config.py                (All configuration, from .env)
│   ├── extensions.py            (SocketIO, Limiter, LoginManager)
│   ├── models/
│   │   ├── database.py          (DatabaseManager, connection pool)
│   │   ├── user.py              (User model from auth_manager.py)
│   │   ├── event.py             (Event model)
│   │   ├── visitor.py           (VisitorSession model)
│   │   ├── company.py           (Company, HotLead models)
│   │   └── query_intent.py      (QueryIntent model for P3)
│   ├── routes/
│   │   ├── auth.py              (login, logout, unauthorized)
│   │   ├── bot_moto.py          (moto bot endpoints)
│   │   ├── bot_elektro.py       (elektro bot endpoints)
│   │   ├── dashboard_client.py  (P1 routes)
│   │   ├── dashboard_admin.py   (P2 routes)
│   │   ├── dashboard_training.py (P3 routes - NEW)
│   │   ├── dashboard_debug.py   (P4 routes - NEW)
│   │   ├── api_public.py        (public API v1/v2)
│   │   └── api_export.py        (JSONL export endpoints)
│   ├── services/
│   │   ├── nlp_engine.py        (base class for bots)
│   │   ├── moto_bot.py          (automotive NLP)
│   │   ├── elektro_bot.py       (electronics NLP, inherits base)
│   │   ├── reward_engine.py     (reward calculators)
│   │   ├── visitor_tracker.py   (GDPR-compliant tracking)
│   │   ├── pii_scrubber.py      (RODO compliance)
│   │   └── export_pipeline.py   (JSONL/CSV/Parquet export)
│   ├── websocket/
│   │   ├── events.py            (all SocketIO event handlers)
│   │   └── rooms.py             (room management)
│   └── utils/
│       ├── lost_value.py        (lost value calculation)
│       ├── deduplication.py     (event dedup logic)
│       └── category.py          (category extraction)
├── migrations/                  (Alembic migrations)
├── tests/
│   ├── test_bot_accuracy.py     (from testbot.py, pytest format)
│   ├── test_reward_engine.py
│   ├── test_pii_scrubber.py
│   ├── test_api_endpoints.py
│   └── test_export_pipeline.py
├── .env                         (secrets, not in git)
├── .env.example                 (template with placeholder values)
├── wsgi.py                      (clean entry point)
├── requirements.txt
└── README.md
```

---

## 6. BOT DEDUPLICATION STRATEGY

Current problem: `ecommerce_bot.py` (1700+ lines) and `elektro_bot.py` (1700+ lines) are 95% identical.

### Solution: Inheritance
```python
# services/nlp_engine.py - Base class
class BaseLDIBot:
    """Base NLP engine for Lost Demand Intelligence"""

    def __init__(self, config):
        self.config = config
        self.product_database = {}
        self.knowledge_base = {}
        self.slang_dict = {}
        self.multilingual = {}
        # ... shared initialization

    def analyze_query_intent(self, query): ...
    def get_fuzzy_product_matches(self, query, filter, limit, analyze_intent): ...
    def has_domain_context(self, tokens): ...  # Renamed from has_automotive_context
    def is_structural_query(self, tokens): ...
    def correct_typos(self, query): ...
    # ... all shared methods

# services/moto_bot.py
class MotoBotEngine(BaseLDIBot):
    """Automotive-specific NLP engine"""

    def __init__(self):
        super().__init__(config=MotoConfig)
        self.load_automotive_knowledge()
        self.load_automotive_products()

    def load_automotive_knowledge(self):
        self.knowledge_base = {
            'car_brands': [...],
            'motorcycle_brands': [...],
            'luxury_brands': [...],
            # ... automotive-specific
        }

# services/elektro_bot.py
class ElektroBotEngine(BaseLDIBot):
    """Electronics-specific NLP engine"""

    def __init__(self):
        super().__init__(config=ElektroConfig)
        self.load_electronics_knowledge()
        self.load_electronics_products()
```

This reduces ~3400 lines to ~2200 lines while making it trivial to add new domains (fashion, groceries, etc.).

---

## 7. TEXT-BASED UI MOCKUP - P3 Training Data Hub

```
┌──────────────────────────────────────────────────────────────────────┐
│  LDI Training Data Hub                          [Export ▼] [Logout] │
│  Role: Researcher | Connected: ● Live                               │
├──────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐ │
│  │ 12,847   │ │  0.34    │ │   847    │ │  12.3%   │ │   93%    │ │
│  │ Total    │ │ Avg      │ │ Gold     │ │ Bounce   │ │ Bot      │ │
│  │ Records  │ │ Reward   │ │ Signals  │ │ Rate     │ │ Accuracy │ │
│  └──────────┘ └──────────┘ └──────────┘ └──────────┘ └──────────┘ │
│                                                                      │
│  ┌─ Reward Distribution ─────────────────────────────────────────┐  │
│  │  -1.0          -0.5           0.0           0.5           1.0 │  │
│  │   ▓▓▓          ▓▓             ▓▓▓▓▓▓        ▓▓▓▓▓▓▓▓▓    ▓▓ │  │
│  │   12%           8%             22%            42%          16% │  │
│  └───────────────────────────────────────────────────────────────┘  │
│                                                                      │
│  ┌─ Query Intent Browser ────────────────────────────────────────┐  │
│  │ Filter: [All Confidence ▼] [All Bots ▼] [Date Range] [Search]│  │
│  │                                                                │  │
│  │ Time  │ Query              │ Conf │ Reward │ Gold │ Match     │  │
│  │───────┼────────────────────┼──────┼────────┼──────┼───────────│  │
│  │ 15:30 │ klocki bmw e90     │ HIGH │ +0.45  │      │ KH001    │  │
│  │ 15:31 │ tesla model 3 parts│ NONE │ -0.20  │  ★   │ ---      │  │
│  │ 15:32 │ filtr mann hu719   │ HIGH │ +0.80  │      │ FO001    │  │
│  │ 15:33 │ pizza hamburger    │ NONE │ -1.00  │      │ BOUNCE   │  │
│  │ 15:34 │ amory sachs        │ MED  │ +0.35  │  ★   │ AM003    │  │
│  │                                                                │  │
│  │ [◄ Prev] Page 1 of 128 [Next ►]  Showing 10 of 12,847       │  │
│  └────────────────────────────────────────────────────────────────┘  │
│                                                                      │
│  ┌─ Export Pipeline ─────────────────────────────────────────────┐  │
│  │                                                                │  │
│  │  Format: [JSONL ▼]  Records: [All ▼]  Date: [Last 30 days ▼] │  │
│  │                                                                │  │
│  │  Filters applied:                                              │  │
│  │  ☑ Include HIGH confidence    ☑ Include gold signals           │  │
│  │  ☑ Include MEDIUM confidence  ☐ Only with conversion           │  │
│  │  ☑ Include LOW confidence     ☐ Only bounces                   │  │
│  │  ☑ Include NO_MATCH          ☐ Min reward: [___]               │  │
│  │                                                                │  │
│  │  Preview (first 3 records):                                    │  │
│  │  {"query":"klocki bmw","intent":"product_search","reward":0.45}│  │
│  │  {"query":"tesla parts","intent":"lost_demand","reward":-0.20} │  │
│  │  {"query":"filtr mann","intent":"product_search","reward":0.80}│  │
│  │                                                                │  │
│  │  [Download JSONL] [Push to S3] [Schedule Monthly Export]       │  │
│  └────────────────────────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────────────────────┘
```
