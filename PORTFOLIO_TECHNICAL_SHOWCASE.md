# Lost Demand Intelligence (LDI) - Technical Portfolio

**Role:** Lead Developer / System Architect
**Stack:** Python, Flask, WebSocket, SQLite, Real-time Analytics
**Status:** Production (SaaS B2B)

---

## Executive Summary

I designed and built a real-time e-commerce intelligence system that detects "lost demand" - products customers search for but can't find. The system processes user queries in real-time, classifies intent, calculates a proprietary reward signal for ML training, and surfaces actionable insights to business users.

**Key Achievement:** Refactored a 4,000-line monolith into a modular 10-file architecture while adding a complete ML data pipeline, all without breaking production.

---

## 1. System Architecture

### High-Level Design

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              CLIENT LAYER                                   │
├─────────────────────────────────────────────────────────────────────────────┤
│   Demo Widget        Client Dashboard (P1)      Admin Dashboard (P2)        │
│   (Search UI)        (Real-time feed)           (Analytics & Leads)         │
│        │                    │                          │                    │
│        └────────────────────┼──────────────────────────┘                    │
│                             │                                               │
│                        WebSocket (Socket.IO)                                │
└─────────────────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                           API GATEWAY                                       │
├─────────────────────────────────────────────────────────────────────────────┤
│   Flask + Blueprints (51 endpoints)                                         │
│   ├── /bot/*          → Query processing & suggestions                      │
│   ├── /api/v1/*       → Headless API for external integrations             │
│   ├── /api/admin/*    → Protected admin endpoints                          │
│   └── /api/p3/*       → ML training data export                            │
│                                                                             │
│   Security: Flask-Talisman, Flask-Limiter, 3-tier RBAC                     │
└─────────────────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                         PROCESSING ENGINE                                   │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│   ┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐        │
│   │  Intent Engine  │    │  Match Engine   │    │ Reward Engine   │        │
│   │  ─────────────  │    │  ─────────────  │    │  ─────────────  │        │
│   │  NLP Analysis   │───▶│  Product Search │───▶│  Score Calc     │        │
│   │  Context Det.   │    │  Fuzzy Matching │    │  Normalization  │        │
│   │  Noise Filter   │    │  Ranking        │    │  [-1.0, +1.0]   │        │
│   └─────────────────┘    └─────────────────┘    └─────────────────┘        │
│           │                      │                      │                   │
│           └──────────────────────┼──────────────────────┘                   │
│                                  ▼                                          │
│                    ┌─────────────────────────┐                              │
│                    │   Decision Classifier   │                              │
│                    │   ─────────────────────  │                              │
│                    │   FOUND / FILTERED /    │                              │
│                    │   LOST OPPORTUNITY      │                              │
│                    └─────────────────────────┘                              │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                          DATA LAYER                                         │
├─────────────────────────────────────────────────────────────────────────────┤
│   ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐       │
│   │   events    │  │  query_     │  │  visitor_   │  │  companies  │       │
│   │   (TCD)     │  │  intents    │  │  sessions   │  │  (CRM)      │       │
│   │             │  │  (P3/ML)    │  │  (GDPR)     │  │             │       │
│   └─────────────┘  └─────────────┘  └─────────────┘  └─────────────┘       │
│                                                                             │
│   Export: JSONL (LLM fine-tuning compatible)                               │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Modular File Structure

```
ldi-system/
├── app.py (97 lines)              # Slim entry point
├── config.py                       # App factory, extensions
├── database.py                     # 3 database managers
├── privacy.py                      # GDPR compliance module
├── reward_engine.py                # ML reward signal calculator
├── routes/
│   ├── bot.py                      # Query processing (760 lines)
│   ├── api.py                      # REST API (1,058 lines)
│   └── pages.py                    # Web pages & auth
├── [proprietary]/
│   └── intent_engine.py            # Core NLP logic (not shown)
└── tests/
    └── 54 pytest tests
```

**Refactoring Achievement:** Decomposed a 3,965-line monolith into 10 focused modules with zero production downtime.

---

## 2. Real-Time Processing Pipeline

### Dual Debounce Architecture

I implemented a two-stage debounce system to balance responsiveness with data quality:

```
User Input Stream:  k → kl → klo → kloc → klock → klocki
                    │    │    │     │      │       │
                    ▼    ▼    ▼     ▼      ▼       ▼
Stage 1 (200ms):    ─────────────────────────────► Autocomplete
                                                   (instant feedback)

Stage 2 (800ms):    ────────────────────────────────────────► Final Analysis
                                                              (intent capture)
```

**Why 800ms?** User research showed this is the "thinking pause" - the moment between typing and decision. Capturing this yields higher-quality intent signals than raw keystroke data.

### WebSocket Event Flow

```python
# Simplified - actual implementation handles edge cases
@socketio.on('connect')
def handle_connect():
    join_room(f'session_{session_id}')
    emit('connection_established', {'status': 'ready'})

# Real-time broadcast to all dashboards
def broadcast_event(event_data):
    socketio.emit('live_feed_update', event_data, room='admin_dashboard')
    socketio.emit('live_feed_update', event_data, room='client_dashboard')
```

---

## 3. ML Reward Signal System

### The Problem

Traditional e-commerce analytics track conversions, but miss the "why" behind failed searches. I needed a signal that could:
1. Quantify search quality (not just clicks)
2. Identify valuable "near misses" (user wanted X, we showed Y, they engaged)
3. Generate training data for future ML models

### My Solution: Normalized Reward Score

I designed a reward function that outputs a score in **[-1.0, +1.0]** range, suitable for:
- Reinforcement Learning from Human Feedback (RLHF)
- LLM fine-tuning
- A/B test evaluation

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                      REWARD CALCULATION LAYERS                              │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  Layer 1: Match Quality                                                    │
│  ├── High confidence match      → Positive signal                          │
│  └── "Gold Signal" detection    → User taught us something new             │
│                                                                             │
│  Layer 2: Behavioral Quality                                               │
│  ├── Engagement metrics         → Click, dwell time                        │
│  └── Frustration detection      → Query refinements, bounces               │
│                                                                             │
│  Layer 3: Conversion                                                       │
│  ├── Cart actions               → Strong intent signal                     │
│  └── Purchase                   → Ultimate success                         │
│                                                                             │
│  Layer 4: Normalization                                                    │
│  └── Clamp to [-1.0, +1.0]      → ML-ready output                         │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Key Innovation: "Gold Signal" Detection

The most valuable training data isn't successful searches - it's when users find value despite a "no match" classification:

```
Query: "OnePlus 12 Pro"
System: NO_MATCH (we don't carry OnePlus)
User: Clicks on Samsung Galaxy suggestion anyway

This is GOLD - the user just taught us that:
1. OnePlus searchers might accept Samsung
2. Our "no match" was actually a "different match"
3. This query-product pair should be learned
```

### Output Format (JSONL for LLM Training)

```jsonl
{"query":"...", "intent":"...", "reward_signal":{"score":0.65, "clicked":true, "purchased":false}, "missing_features":["color:gold"]}
```

---

## 4. GDPR/Privacy Architecture

### Data Flow with Privacy Controls

```
Raw User Input
      │
      ▼
┌─────────────────┐
│   PII Scrubber  │ ──► Emails, phones, IDs → [REDACTED]
└─────────────────┘
      │
      ▼
┌─────────────────┐
│   IP Processor  │ ──► 192.168.1.42 → hash: a3f2... / masked: 192.168.1.xxx
└─────────────────┘
      │
      ▼
┌─────────────────┐
│   Retention     │ ──► Auto-delete after 30 days
└─────────────────┘
      │
      ▼
   Clean Data → Database
```

### Privacy-First Design Decisions

| Decision | Rationale |
|----------|-----------|
| Hash IPs, don't store raw | Can still detect repeat visitors, can't identify them |
| PII scrubbing at entry | Defense in depth - even if DB leaks, no PII present |
| 30-day auto-purge | GDPR compliance + reduces liability |
| Opt-out endpoint | User can request deletion via API |

---

## 5. Security Implementation

### 6-Layer Security Model

```
┌─────────────────────────────────────────────────────────────────┐
│ Layer 1: Transport       │ HTTPS forced, HSTS enabled          │
├──────────────────────────┼──────────────────────────────────────┤
│ Layer 2: Rate Limiting   │ Per-endpoint limits, DDoS protection│
├──────────────────────────┼──────────────────────────────────────┤
│ Layer 3: Authentication  │ Flask-Login, session management     │
├──────────────────────────┼──────────────────────────────────────┤
│ Layer 4: Authorization   │ 3-tier RBAC (client/admin/debug)    │
├──────────────────────────┼──────────────────────────────────────┤
│ Layer 5: Input Validation│ Parameterized queries, sanitization │
├──────────────────────────┼──────────────────────────────────────┤
│ Layer 6: Secrets         │ Env vars, no hardcoded credentials  │
└─────────────────────────────────────────────────────────────────┘
```

### Rate Limiting Strategy

```python
# Different limits for different risk profiles
@limiter.limit("20/minute")   # Bot initialization (prevent session spam)
@limiter.limit("100/minute")  # Search queries (normal usage)
@limiter.limit("60/minute")   # API calls (external integrations)
```

---

## 6. Testing & Quality

### Test Coverage

```
tests/
├── test_reward_engine.py    # 10 tests - reward calculation edge cases
├── test_bots.py             # 11 tests - intent classification
├── test_api_routes.py       # 15 tests - API contract validation
└── test_database.py         # 15 tests - data integrity

Result: 54 passed, 1 skipped (session state edge case)
```

### Key Test Categories

1. **Reward Engine Tests**
   - Bounce always returns -1.0
   - Purchase always positive
   - Score always in [-1.0, +1.0] range
   - Gold signal detection works

2. **API Contract Tests**
   - Auth required on protected endpoints
   - Rate limiting enforced
   - JSONL export format valid

---

## 7. Technical Decisions & Trade-offs

### Decision: SQLite over PostgreSQL

**Context:** SaaS deployed on Render with ephemeral filesystem
**Choice:** SQLite with JSONL export for persistence
**Rationale:**
- Simpler ops for MVP
- Export mechanism provides backup
- Easy migration path to Postgres when needed

### Decision: Dual Debounce (200ms + 800ms)

**Context:** Need real-time autocomplete AND quality intent data
**Choice:** Two-stage debounce with different timeouts
**Rationale:**
- 200ms: Fast enough for autocomplete UX
- 800ms: Captures "final intent" after user stops typing
- Prevents polluting ML data with partial queries

### Decision: Normalized Reward [-1.0, +1.0]

**Context:** Need reward signal for multiple ML use cases
**Choice:** Clamp all scores to [-1.0, +1.0]
**Rationale:**
- Compatible with standard RL algorithms
- Easy to interpret (negative = bad, positive = good)
- No need for per-model normalization

---

## 8. Results & Metrics

### System Performance

| Metric | Value |
|--------|-------|
| Endpoints | 51 |
| Avg response time | <100ms |
| Test coverage | 54 tests passing |
| Code reduction | 3,965 → 97 lines (entry point) |

### Business Impact

- **Lost demand detection:** System identifies products customers want but can't find
- **Lead scoring:** Automatic engagement scoring for B2B sales
- **ML-ready data:** JSONL export for future model training

---

## 9. What I'd Do Differently

1. **Start with PostgreSQL** - SQLite works but limits scaling options
2. **Add OpenTelemetry from day 1** - Debugging distributed issues is hard without tracing
3. **GraphQL for admin API** - REST works but GraphQL would reduce over-fetching

---

## 10. Skills Demonstrated

- **Architecture:** Monolith decomposition, modular design, clean separation of concerns
- **Real-time systems:** WebSocket, debouncing, event-driven architecture
- **ML Engineering:** Reward signal design, RLHF-compatible data pipelines, JSONL export
- **Security:** OWASP awareness, GDPR compliance, defense in depth
- **Testing:** pytest, fixtures, edge case coverage
- **Python:** Flask, SQLite, eventlet, dataclasses

---

## Contact

Available to discuss architecture decisions, implementation details, or potential collaboration.

*Note: Proprietary NLP/matching algorithms not included in this document.*
