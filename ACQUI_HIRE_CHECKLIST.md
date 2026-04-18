# ACQUI-HIRE CHECKLIST
## Technical Showcase & Partnership Positioning
**Date:** 2026-02-05 | **Target:** Scale AI, Anthropic, OpenAI, Google, Meta

---

## 1. TECHNICAL SHOWCASE ITEMS

### A. Gotowe do pokazania DZIŚ
| Item | Co pokazujesz | Wow factor |
|------|---------------|------------|
| Live demo (moto) | Wpisz "klocki bmw e90" → instant classification | Real-time intent analysis |
| Live demo (elektro) | Wpisz "iPhone 15 pro" → instant classification | Domain-agnostic proof |
| Typo correction | Wpisz "kloki bosch" → system naprawia i znajduje | NLP robustness |
| Slang handling | Wpisz "amory sachs" → rozumie mechanicki slang | Domain expertise depth |
| Multilingual | Wpisz "brake pads bmw" → works in English too | Language flexibility |
| Lost demand detection | Wpisz "klocki ferrari" → NO_MATCH + value estimation | Revenue gap identification |
| Nonsense filtering | Wpisz "pizza hamburger" → properly filtered | Anti-noise intelligence |
| 93% accuracy test | Uruchom testbot.py → 93/100 pass | Quantified proof |
| Real-time dashboard | Otwórz P1 → live feed z WebSocket | Production-grade UX |
| Passive Radar | Otwórz P2 → widać kto pisze w real-time | B2B intelligence |
| JSONL export | Otwórz P3 → download training data | ML pipeline ready |
| Reward signal | Pokaż reward_engine.py → explain anti-bait design | Novel RLHF approach |
| GDPR compliance | Pokaż visitor_tracking.js → PII scrubbing | Enterprise readiness |

### B. Gotowe po P0 fixach (1-2 dni)
| Item | Co pokazujesz | Wow factor |
|------|---------------|------------|
| PostgreSQL | "We run on PostgreSQL with connection pooling" | Enterprise infrastructure |
| Environment config | "All secrets in env vars, zero hardcoded" | Security maturity |
| Modular architecture | "Clean separation of concerns" | Code quality |
| English UI | "Enterprise-grade international interface" | Global positioning |

### C. Gotowe po P1 fixach (1-2 tygodnie)
| Item | Co pokazujesz | Wow factor |
|------|---------------|------------|
| Test suite | "93% accuracy with automated pytest CI" | Engineering discipline |
| API docs | "OpenAPI spec, documented endpoints" | Developer experience |
| Sentry monitoring | "Real-time error tracking in production" | Ops maturity |
| Rate limiting | "DDoS protection, per-endpoint limits" | Security depth |

---

## 2. DEMO SCENARIOS (Script for 15-min pitch)

### Scenario 1: "The Intent Classification Engine" (3 min)
```
1. Otwórz adeptai.pl/demo
2. Wpisz: "klocki bmw e90"
   → Pokaż: instant match, HIGH confidence, product found
   → Explain: "Our NLP engine classified this as a specific product search
               with 92% match score in under 50ms"

3. Wpisz: "kloki bosch" (literówka)
   → Pokaż: system naprawił literówkę, znalazł produkt
   → Explain: "Fuzzy matching with Levenshtein distance + domain-specific
               typo dictionaries. Works for Polish, English, German."

4. Wpisz: "klocki ferrari"
   → Pokaż: NO_MATCH, classified as LOST DEMAND
   → Explain: "This is the gold signal. User wants something we don't have.
               This becomes labeled training data: query='klocki ferrari',
               intent='lost_demand', reward_signal=-0.2"
```

### Scenario 2: "The Training Data Pipeline" (3 min)
```
1. Otwórz P3 Debug Dashboard
2. Pokaż tabelę query_intents z reward scores
   → Explain: "Every search interaction generates a labeled data point
               with our novel reward signal normalized to [-1, +1]"

3. Kliknij "Export JSONL"
   → Pokaż format: query, intent, confidence, reward_signal, metadata
   → Explain: "OpenAI fine-tuning compatible format. Each record has
               behavioral signals: did they click? did they bounce?
               did they find what they didn't know they wanted?"

4. Otwórz reward_engine.py
   → Pokaż LDIRewardCalculator
   → Explain: "Our anti-bait reward function. We penalize clickbait matches
               and reward genuine product discovery. The 'gold signal' is
               when a user searches for X, doesn't find it, but clicks Y instead.
               That's learning data worth more than any synthetic dataset."
```

### Scenario 3: "Domain Agnosticity" (2 min)
```
1. Przełącz na ELEKTRONIKĘ
2. Wpisz: "iPhone 15 pro max"
   → Pokaż: works identically, different product database
   → Explain: "Same engine, different domain knowledge. We proved it works
               for automotive AND electronics. The architecture supports
               any e-commerce vertical - fashion, groceries, industrial."

3. Pokaż dual decision mapping:
   → MOTO: MEDIUM confidence = FILTERED (short product names)
   → ELEKTRO: MEDIUM confidence = FOUND (long product names)
   → Explain: "Domain-specific calibration. The same confidence level
               means different things in different verticals."
```

### Scenario 4: "The B2B Intelligence Layer" (3 min)
```
1. Otwórz P2 Admin Dashboard
2. Pokaż Passive Radar
   → Explain: "Real-time visitor tracking with GDPR compliance.
               We detect companies visiting our demo, track their
               search patterns, and score engagement 0-100."

3. Pokaż Hot Leads
   → Explain: "Automatic lead qualification based on search behavior.
               Company X searched for premium products 5 times = hot lead."

4. Pokaż WebSocket real-time feed
   → Explain: "Every search event is classified and broadcast in real-time.
               This is production infrastructure, not a prototype."
```

### Scenario 5: "The Data Moat" (2 min)
```
1. Pokaż architekturę na diagramie
   → Explain: "Every e-commerce site using our system generates labeled
               training data. More sites = more data = better models.
               This is a data flywheel, not a one-time product."

2. Pokaż reward_engine.py anti-bait mechanism
   → Explain: "Our reward signal is designed to prevent gaming.
               You can't trick the system into generating fake positive signals.
               This makes our training data trustworthy for RLHF."

3. Ending: "We have the system, the methodology, and growing real-world data.
            What we need is scale - and that's where [Scale AI/Anthropic/Google]
            comes in."
```

---

## 3. CODE QUALITY PROOF POINTS

### Dla technicznego reviewera (CTO/Staff Engineer)

**Pokaż te pliki w tej kolejności:**

1. **reward_engine.py** (278 lines)
   - Czytelny, dobrze udokumentowany
   - Dwa kalkulatory: legacy (chatbot) + current (product search)
   - Proper dataclasses, type hints, logging
   - Normalization [-1.0, +1.0]
   - *"This is our research contribution"*

2. **ecommerce_bot.py** - `has_automotive_context()` method
   - 300+ marek, 500+ modeli, slang, multilingual
   - Regex patterns dla kodów produktów
   - Fuzzy matching z fuzzywuzzy
   - *"Deep domain knowledge encoded in code"*

3. **visitor_tracking.js** - GDPR layer
   - IP hashing z Web Crypto API
   - PII scrubbing (email, phone, PESEL, credit cards, IBAN)
   - Do Not Track support
   - *"Privacy by design, not afterthought"*

4. **testbot.py** - 100 scenarios
   - 10 kategorii testów (literówki, slang, kody, edge cases)
   - Pokrywa: basic, typos, product codes, context, slang, multilingual, specs, nonsense, luxury, edge
   - *"Quantified accuracy: 93% on real-world scenarios"*

### Metryki do przygotowania
| Metric | Current | Target (post-fixes) |
|--------|---------|---------------------|
| Bot accuracy (100 tests) | 93% | 95%+ |
| Test coverage | 0% (no pytest) | 60%+ |
| Code duplication | ~40% (moto/elektro) | <5% |
| app.py lines | 3977 | <500 (split) |
| Security vulnerabilities | 15 | 0 critical, <3 medium |
| API endpoints documented | 0 | 100% |
| JSONL records exported | Working | With metadata enrichment |

---

## 4. INNOVATION DIFFERENTIATORS

### Co wyróżnia LDI od konkurencji

**1. Anti-Bait Reward Signal**
- Większość systemów RLHF nagradza kliknięcia → clickbait
- LDI karze bounce, multiple refinements, long sessions without action
- Gold signal: `clicked_despite_no_match` → genuine discovery
- *Publikowalny research paper*

**2. Real Data vs Synthetic**
- GPT-generated training data ma known biases
- LDI zbiera dane z prawdziwych interakcji zakupowych
- Każdy data point ma behavioral validation (click/bounce/purchase)
- *Data moat - impossible to replicate without production deployment*

**3. Domain-Agnostic Architecture**
- Udowodnione na 2 domenach (moto + elektro)
- Architektura obsługuje dowolny vertical
- Decision mapping kalibrowany per-domena
- *Platform play, not point solution*

**4. "Doktryna Cierpliwego Nasłuchu" (Patient Listening)**
- 200ms: UI feedback (instant gratification)
- 800ms: Backend analysis (thoughtful classification)
- Dwuwarstwowy debounce → lepsze dane + lepszy UX
- *Novel UX pattern for intent capture*

**5. GDPR-First Data Collection**
- IP hashing + masking
- PII scrubbing (7 categories)
- Data retention (30 days auto-delete)
- DNT support
- *Enterprise-ready from day one*

---

## 5. PARTNERSHIP POSITIONING BY TARGET

### Scale AI
**Angle:** "We generate the labeled training data you sell to AI companies"
**Pitch:** "Our system produces RLHF-compatible labeled data from live e-commerce interactions. Each data point has behavioral validation - not just labels, but reward signals based on actual user behavior. We can plug into your data pipeline and generate training data at scale."
**Ask:** Partnership / Acqui-hire into data operations team
**Leverage:** Working system + methodology + growing dataset

### Anthropic
**Angle:** "We built a real-world RLHF data collection system"
**Pitch:** "Our reward signal methodology could improve Claude's understanding of purchase intent. We have a novel anti-bait mechanism that prevents reward hacking. The system is production-validated on live e-commerce traffic."
**Ask:** Research partnership / Acqui-hire into RLHF team
**Leverage:** Novel reward signal design + anti-bait research

### OpenAI
**Angle:** "Fine-tuning data pipeline for e-commerce"
**Pitch:** "Our system generates OpenAI-compatible JSONL training data from real purchase intent interactions. The data includes reward signals that could improve GPT's product recommendation capabilities."
**Ask:** Partnership / Integration into fine-tuning ecosystem
**Leverage:** Compatible format + production data + domain expertise

### Google (Vertex AI / DeepMind)
**Angle:** "Real-world RLHF for e-commerce understanding"
**Pitch:** "We capture purchase intent signals at the point of search, with behavioral validation and GDPR compliance. This data could improve Google Shopping, product recommendations, and LLM understanding of commercial intent."
**Ask:** Acqui-hire into Shopping/Search team
**Leverage:** E-commerce domain expertise + production system + EU compliance

### Meta (FAIR / Commerce)
**Angle:** "Social commerce intent data"
**Pitch:** "Our intent classification engine works across languages (Polish, English, German) and domains. It could enhance Meta's commerce features - Instagram Shopping, Facebook Marketplace - with better intent understanding from search behavior."
**Ask:** Acqui-hire into Commerce AI team
**Leverage:** Multilingual NLP + intent classification + reward signal

---

## 6. PRE-PITCH TECHNICAL CHECKLIST

### 48 Hours Before Any Pitch
- [ ] All P0 fixes deployed (security, .env, debug=False)
- [ ] Demo site working: adeptai.pl/demo
- [ ] Admin login works (changed from default password)
- [ ] P3 JSONL export downloads correctly
- [ ] testbot.py passes 93%+
- [ ] README.md exists and is professional
- [ ] No Polish profanity in visible git log (last 20 commits)
- [ ] Landing page rebranded to English
- [ ] Login page credentials removed from HTML
- [ ] Health endpoint returns English description

### Day-of Checklist
- [ ] Demo site responding (check adeptai.pl/demo)
- [ ] WebSocket connections working (live feed updates)
- [ ] P2 admin dashboard loads without errors
- [ ] JSONL export produces valid JSON
- [ ] Prepare screen recording backup (in case of network issues)
- [ ] Have reward_engine.py open in editor for code walkthrough
- [ ] Have testbot.py results screenshot ready
- [ ] Clear browser cache before demo

### Materials to Have Ready
- [ ] Architecture diagram (draw.io / Excalidraw)
- [ ] 1-page technical summary (PDF)
- [ ] JSONL sample file (100 records, sanitized)
- [ ] Reward signal methodology explanation (1 page)
- [ ] Accuracy metrics table
- [ ] GitHub repo link (cleaned up)
- [ ] This checklist (printed)

---

## 7. TALKING POINTS FOR COMMON QUESTIONS

**Q: "Why not just use GPT to classify intent?"**
A: "GPT gives you classification. We give you classification + behavioral validation + reward signal. Our data is ground-truth from real user behavior, not model-generated labels. That's what makes it valuable for RLHF - it's verified by actual clicks, purchases, and bounces."

**Q: "How does this scale?"**
A: "Current architecture handles ~10K queries/day on SQLite. With PostgreSQL + Redis (planned), it handles 1M+/month. The NLP engine is CPU-only (no GPU needed), running at <50ms per query. Each new e-commerce deployment adds to the data flywheel."

**Q: "Why 93% and not 99%?"**
A: "93% is on our hardest test suite including multilingual queries, mechanic slang, and edge cases. The 7% failures are mostly in ambiguous slang where even humans disagree. With more training data and fine-tuned models, we project 97%+ within 6 months."

**Q: "What's the moat?"**
A: "Three things: (1) The reward signal methodology - novel anti-bait design that's publishable research. (2) The growing dataset of real purchase intent with behavioral validation. (3) Domain expertise - 300+ brands, 500+ models, slang dictionaries across languages. This took months to build and validate."

**Q: "Is the code production-ready?"**
A: "The core engine is production-validated on live traffic. We're currently hardening the infrastructure (PostgreSQL migration, proper secret management, monitoring). The NLP logic and reward signal are solid. Think of it as a proven research system being upgraded to enterprise infrastructure."

**Q: "What would you do with our resources?"**
A: "(1) Scale data collection across more e-commerce verticals. (2) Train actual LLM on our reward signal data. (3) Build comparative studies: our behavioral reward signal vs standard RLHF. (4) Publish the anti-bait reward methodology. (5) Deploy to 100+ e-commerce sites for data flywheel effect."

---

## 8. COMPENSATION POSITIONING

### What You Bring to the Table
1. **Working system** - not a pitch deck, a deployed production system
2. **Novel research** - anti-bait reward signal, publishable methodology
3. **Domain expertise** - deep e-commerce NLP knowledge across verticals
4. **Growing dataset** - real behavioral data, not synthetic
5. **Full-stack capability** - built entire system solo (backend, frontend, NLP, DevOps, GDPR)

### Positioning for Negotiation
- "I built this entire system from scratch - backend, NLP engine, GDPR compliance, real-time dashboards, reward signal research. I'm looking for a role where I can apply this at scale."
- "The system is my proof of concept. The methodology is my intellectual contribution. I want equity in the outcome, not just a salary."
- "I'm not selling a product. I'm offering a partnership: my system + my expertise + your scale = training data at a level neither of us could achieve alone."
