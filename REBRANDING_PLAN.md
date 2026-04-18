# REBRANDING PLAN
## From Polish E-commerce Tool → Enterprise Training Data Platform
**Date:** 2026-02-05

---

## 1. STRATEGIC POSITIONING

### Current Positioning (Kill)
> "Raport utraconych sprzedaży dla Janusza" / "System dla e-commerce"

### Target Positioning (Build)
> "Enterprise training data platform that learns purchase intent from real-world e-commerce interactions. Generates labeled RLHF datasets for LLM fine-tuning with built-in reward signal computation."

### One-Liner for Acqui-hire Pitch
> "We built the infrastructure to capture and label purchase intent at scale. Our system generates OpenAI-compatible training data from live e-commerce interactions, with a novel reward signal that identifies when users find what they didn't know they wanted."

---

## 2. UI TEXT CHANGES (Complete List)

### A. Decision Classifications (Global - affects all dashboards)
| Current (Polish) | New (English) | Location |
|-------------------|---------------|----------|
| ZNALEZIONE PRODUKTY | MATCHED | app.py, dashboard.js, admin_dashboard.js, all templates |
| UTRACONE OKAZJE | LOST DEMAND | app.py, dashboard.js, admin_dashboard.js, all templates |
| ODFILTROWANE | FILTERED | app.py, dashboard.js, admin_dashboard.js, all templates |

### B. Login Page (login.html)
| Current | New |
|---------|-----|
| CENTRUM ANALITYCZNE UTRACONYCH OKAZJI | LDI Platform - Lost Demand Intelligence |
| Nazwa użytkownika | Username |
| Hasło | Password |
| Zaloguj się | Sign In |
| Konta testowe | Demo Credentials |
| Poziom 1: Raporty klienta | Level 1: Client Analytics |
| Poziom 2: Live B2B admin | Level 2: Sales Intelligence |
| Remove test credentials from HTML | Move to separate admin docs |

### C. Client Dashboard (P1 - client-dashboard.html)
| Current | New |
|---------|-----|
| Puls Rynku - Top Utracone Produkty | Market Pulse - Top Demand Gaps |
| Utracony przychód High-Ticket | Lost High-Ticket Revenue |
| Szacowana utracona marża (tygodniowo) | Estimated Weekly Revenue Gap |
| Dzisiejsze zapytania | Today's Queries |
| W tym tygodniu | This Week |
| W analizie | In Analysis |
| Czas odpowiedzi | Response Time |

### D. Admin Dashboard (P2 - admin-dashboard.html)
| Current | New |
|---------|-----|
| Centrum Analityczne - Admin Dashboard | LDI Sales Intelligence |
| Poziom 2: Centrum Strategiczne | Level 2: Strategic Command |
| HOT LEADS B2B - Firmy Gotowe Do Rozmowy | Hot Prospects - High-Intent Companies |
| Temperatura Rynku (Live) | Market Temperature (Live) |
| Passive Radar - Ostatnie Wizyty | Visitor Radar - Recent Sessions |
| Ostatnie Zdarzenia (Matrix) | Event Log (Matrix) |
| Widok Klienta | Client View |

### E. Bot Interface (demo_page.html, script.js)
| Current | New |
|---------|-----|
| System LDI (Lost Demand Intelligence) | LDI - Intent Classification Engine |
| TRYB: MOTORYZACJA | MODE: AUTOMOTIVE |
| Przełącz na ELEKTRONIKĘ | Switch to ELECTRONICS |
| Reset Analizy | Reset Analysis |
| Wprowadź numer części... | Enter product query... |
| OTWÓRZ PEŁNE CENTRUM ANALITYCZNE | OPEN ANALYTICS CENTER |

### F. Debug Dashboard (P3 - debug_dashboard.html)
| Current | New |
|---------|-----|
| P3 Debug Dashboard \| LDI RLHF Analytics | LDI Training Data Hub \| RLHF Analytics |
| Query Intent Logs | Intent Classification Logs |
| Export JSONL | Export Training Data (JSONL) |

### G. Tech Documentation (tech.html)
| Current | Keep/Change |
|---------|-------------|
| Technical documentation | Keep - already English |
| Endpoint descriptions | Keep - enhance with OpenAPI spec |

### H. Health Endpoint (app.py:2205)
| Current | New |
|---------|-----|
| Universal Soldier E-commerce Bot v5.0 | LDI Intent Engine v5.1 |
| Doktryna Cierpliwego Nasłuchu | Patient Listening Architecture |

---

## 3. COPY REWRITES FOR ENTERPRISE POSITIONING

### Landing Page (index.html) - Complete Rewrite Needed

**Hero Section:**
```
Lost Demand Intelligence

Transform e-commerce search queries into labeled training data
for LLM intent classification and product recommendation systems.

[Live Demo]  [API Documentation]  [Export Training Data]
```

**Value Props:**
```
┌────────────────────┐  ┌────────────────────┐  ┌────────────────────┐
│ Intent              │  │ Reward Signal       │  │ Training Data      │
│ Classification      │  │ Generation          │  │ Pipeline           │
│                     │  │                     │  │                     │
│ 93% accuracy on     │  │ Novel anti-bait     │  │ OpenAI-compatible   │
│ real-world e-comm   │  │ reward function     │  │ JSONL export with   │
│ queries with typo   │  │ normalized to       │  │ configurable        │
│ correction, slang,  │  │ [-1.0, +1.0] with   │  │ filtering and       │
│ and multilingual    │  │ gold signal          │  │ batch scheduling    │
│ support             │  │ detection           │  │                     │
└────────────────────┘  └────────────────────┘  └────────────────────┘
```

**Technical Differentiators:**
```
What Makes LDI Different

1. REAL DATA, NOT SYNTHETIC
   Training data from actual purchase intent signals,
   not GPT-generated synthetic queries.

2. ANTI-BAIT REWARD SIGNAL
   Our reward function penalizes clickbait matches and
   rewards genuine product discovery (clicked_despite_no_match).

3. DOMAIN-AGNOSTIC ARCHITECTURE
   Currently deployed for automotive + electronics.
   Architecture supports any e-commerce vertical.

4. GDPR-FIRST DATA COLLECTION
   IP hashing, PII scrubbing, data retention policies.
   Every data point is privacy-compliant by design.

5. PRODUCTION-VALIDATED
   Running on live e-commerce with real users,
   not a research prototype.
```

### API Documentation Header
```
LDI API v2.0

Enterprise API for intent classification and training data export.
Designed for integration with LLM fine-tuning pipelines.

Base URL: https://adeptai.pl/api/v2
Authentication: Bearer token
Rate Limit: 1000 req/hour (configurable)
```

---

## 4. TONE GUIDE

### Kill These Patterns
- "Dla Janusza" / "Dla e-commerce"
- Polish business jargon
- Casual/informal tone
- Emoji in production copy (keep in debug only)
- "klocki BMW" as primary example (keep as demo data, not marketing)

### Use These Patterns
- Technical precision ("intent classification", "reward signal", "RLHF-compatible")
- Quantified claims ("93% accuracy on 100-scenario test suite")
- Research vocabulary ("domain-agnostic", "anti-bait mechanism", "gold signal detection")
- Enterprise language ("production-validated", "GDPR-compliant", "batch export pipeline")

### Voice Examples
```
BAD:  "System pokazuje co ludzie chcieli kupić ale nie znaleźli"
GOOD: "LDI captures purchase intent signals from queries that don't match
       existing inventory, generating labeled training data for demand prediction."

BAD:  "Utracone okazje sprzedażowe"
GOOD: "Lost Demand signals - queries expressing purchase intent for products
       outside current catalog, labeled with reward scores for RLHF training."

BAD:  "Wykrywamy firmę która weszła na stronę"
GOOD: "Visitor Intelligence: GDPR-compliant company identification from
       session metadata, with engagement scoring for lead qualification."
```

---

## 5. DOCUMENTATION OVERHAUL

### Current State
- tech.html exists with basic endpoint docs
- No README.md
- No API spec (OpenAPI/Swagger)
- Comments in Polish throughout codebase

### Needed Documents
1. **README.md** - Project overview, setup, architecture diagram
2. **API.md** - Full API specification (or OpenAPI YAML)
3. **REWARD_SIGNAL.md** - Explanation of reward signal methodology
4. **ARCHITECTURE.md** - System architecture for technical reviewers
5. **DEPLOYMENT.md** - Render setup, PostgreSQL config, env vars
6. **CONTRIBUTING.md** - Code style, PR process (shows maturity)

### Code Comments Strategy
- Don't translate all existing Polish comments (waste of time)
- Write all NEW comments in English
- Translate critical module docstrings to English
- Add English module-level docstrings to all Python files

---

## 6. VISUAL/BRAND CHANGES

### Color Palette
| Current | Proposed | Usage |
|---------|----------|-------|
| #dc2626 (red) | #6366f1 (indigo) | Primary brand |
| #fbbf24 (amber) | #06b6d4 (cyan) | Accent |
| #0a0a0a (black) | #0f172a (slate-900) | Dashboard bg |
| #00d4ff (cyan) | Keep | Data visualization |

### Typography
- Current: Inter (good choice, keep)
- Add: JetBrains Mono for code/data displays

### Logo/Brand Name
- Current: "Adept AI" with generic logo
- Proposed: "LDI" as primary brand, "by Adept AI" as secondary
- Clean wordmark, no emoji in logo

### Dashboard Theme
- Keep dark theme (good for analytics tools)
- Reduce Polish-specific design elements
- Add English-language tooltips
- Remove "Oko Saurona" references from code

---

## 7. IMPLEMENTATION PRIORITY

### Phase 1 (Before acqui-hire pitch) - 2 days
1. Update decision mappings to English (MATCHED/LOST DEMAND/FILTERED)
2. Rewrite login page in English
3. Rewrite landing page hero section
4. Update health endpoint description
5. Remove test credentials from HTML
6. Write README.md

### Phase 2 (For credibility) - 3 days
7. Translate admin dashboard UI
8. Translate client dashboard UI
9. Write API documentation
10. Write REWARD_SIGNAL.md methodology paper
11. Update tech.html with enterprise positioning

### Phase 3 (Polish) - 2 days
12. Update bot interface messages to English
13. Translate debug dashboard
14. Update all console.log/print messages to English
15. Create .env.example with documentation
16. Clean up git commit history (squash Polish profanity commits)
