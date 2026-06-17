# LDI Evolution Log — 2026-06-17

**Projekt:** forteca_finalna (Lost Demand Intelligence)
**Deployment:** adeptai.pl (Render)
**Sesja:** kontynuacja 2026-06-16 — pełen audyt architektury + 4 fixy krytyczne
**Status:** zmiany lokalne, NIE pushowane na produkcję

---

## Kontekst — dlaczego ta sesja istnieje

Sesja 2026-06-16 zamknęła 7 fixów JSONL pipeline (Gold Signal, missing_features 8 typów, purchased flag, bounce detection, MEDIUM score, MOTO Gold Signal, P5 modale). Stanowisko: "JSONL gotowy na produkcję".

Sesja 2026-06-17 zaczęła się od pytania użytkownika: **"jsonl gotowy na produkcje?"**

Odpowiedziałem: nie. Trzy problemy: endpoint eksportuje śmieci (brak `ai_ready=1` filtra), brak pola `source`, `intent_label` może być null. Wdrożyłem te 3 fixy. Po fixach — wszystkie zielone testy.

Następnie użytkownik zażądał **PEŁNEGO audytu architektury, BEZ poprawek**. Audyt ujawnił 15 dalszych problemów (4 krytyczne, 7 ważnych, 4 średnie). Naprawiliśmy 4 krytyczne sekwencyjnie, każdy z explicite zatwierdzonym planem.

---

## 1. Fixy JSONL production readiness (3 zmiany przed audytem)

### 1.1 Endpoint eksportu — domyślnie tylko `ai_ready=1`

**Problem:** `/api/export-training-data` wywoływał `get_training_data(limit)` bez `ai_ready_only=True`. Eksportował wszystko, łącznie z rekordami które semantic validator odrzucił.

**Fix `routes/api.py`:**
```python
limit = request.args.get('limit', 5000, type=int)
ai_ready_only = request.args.get('ai_ready', '1') != '0'
training_data = QueryIntentManager.get_training_data(limit, ai_ready_only=ai_ready_only)
```

- Domyślnie `ai_ready=1` (clean data)
- Override: `?ai_ready=0` → raw dump z śmieciami (do debugowania)
- Domyślny limit podniesiony z 1000 → 5000

### 1.2 Pole `source` (moto/elektro/unknown)

**Problem:** brak rozróżnienia domeny botów w JSONL. Multi-tenant niemożliwy.

**Fix `database.py`:**
- Nowa kolumna `source TEXT DEFAULT 'unknown'` w `query_intents`
- Migracja: `ALTER TABLE ADD COLUMN source TEXT DEFAULT 'unknown'` (SQLite backfilluje istniejące wiersze)
- `add_query_intent()`: INSERT i UPDATE biorą `source` z `data.get('source', 'unknown')`
- `get_training_data()`: SELECT zwraca source, result dict eksportuje pole

**Fix `routes/bot.py`:**
- MOTO sekcja: `'source': 'moto'`
- ELEKTRO sekcja: `'source': 'elektro'`

### 1.3 `intent_label` fallback

W tym kroku zrobiłem fallback `intent_label = row[3] or source` — naprawione w fixie #3 z audytu (patrz niżej).

---

## 2. Audyt — 15 znalezisk

### Krytyczne (zatruwają training data)

1. **NO_MATCH + ai_ready=True + missing_features=[]** — walidator akceptuje query gdy brand jest rozpoznany, niezależnie od ekstraktora. `"samsung galaxy"` → ai_ready=True, missing_features=[]. Model dostaje "NO_MATCH" bez informacji DLACZEGO.

2. **MissingFeatureExtractor = ELECTRONICS-FIRST** — wszystkie 8 typów (capacity, ram, screen, gen, variant, model itd.) zaprojektowane pod elektronikę. MOTO bot wywołuje ten sam ekstraktor i dostaje praktycznie zawsze `[]`. Cała wartość zapytań typu "klocki audi a4 b8 2.0 tdi 2010" znika.

3. **`intent_label = row[3] or source`** — miesza category (`"elektronika"`) z domain (`"elektro"`). Te same labele różnych znaczeń → chaos dla ML.

4. **`ai_ready` overwrite przy refinement** — session consolidation nadpisuje ai_ready ostatnim refinementem. User pisze "iphone 13" (valid) → "asdfgh" (junk) → record z valid signalu jest tracony.

### Ważne (operational)

5. **Bounce detection tylko przy eksporcie** — `_mark_stale_bounces()` w `get_training_data()`. Dashboard pokazuje 0% bounce do momentu eksportu JSONL.

6. **`unrealistic_model_patterns` hardcoded i się starzeje** — `iphone: (1, 16)`, `bmw: (1, 8)`. iPhone 17 (Q3 2026) będzie odrzucany. BMW pomija i3/i4/i7/iX/M-series.

7. **Dwa systemy scoringu** — `LDIRewardCalculator.calculate_from_dict()` (engine pełny) i `score_for_export()` (uproszczona tabela). Dla tego samego rekordu mogą zwrócić różne wartości. Confusion.

### Średnie (do uporządkowania)

8. **Cart duplikaty przy wielokrotnym kliknięciu** — `session['cart'].append(product_id)` bez deduplikacji.

9. **Hardcoded `'dashboard.db'` w obu botach** — zamiast `DATABASE_NAME` z config. Zmiana nazwy DB wymaga ręcznej aktualizacji w 2 miejscach.

10. **Brak `IS_DEMO` flagi** — w demo `add_to_cart = purchased=true`, w produkcji webhook ustawia osobno. Obie ścieżki w tej samej logice. Pierwszy prawdziwy klient wymaga zmiany kodu.

### Do weryfikacji (potencjalne ryzyko)

11. **`scrub_pii` zakres** — sprawdzić czy łapie credit card, NIP, PESEL (nie tylko email/phone).

12. **Race condition w consolidation** — dwa równoczesne POST z tej samej sesji mogą zinsertować duplikaty (SELECT przed INSERT bez transakcji).

13. **`alternative_clicked_id` walidacja** — `add_to_cart(product_id)` nie sprawdza czy `product_id` był w sugestiach po NO_MATCH. Kliknięcie produktu z menu/homepage zatruwa "alternative" data.

14. **Domain leakage w validatorze** — `_has_domain_context()` łączy auto + electronics brands w jeden pool. `"tesla telewizor"` przechodzi dla ELEKTRO.

15. **`SemanticValidator` nie odświeża się** gdy klient uploaduje nowe produkty. Walidator zna zamknięty zbiór brandów/kategorii hardcoded w kodzie.

---

## 3. Fixy 4 krytycznych — szczegóły wdrożenia

### Fix #1: NO_MATCH wymaga missing_features

**Zmiana:** validator dostaje `missing_features` jako parametr i traktuje NO_MATCH z pustą listą jako nieinformatywny szum.

**`reward_engine.py:SemanticValidator.validate()`:**
```python
def validate(self, query, confidence_level=None, missing_features=None):
    # ... istniejące walidacje ...
    if confidence_level == 'NO_MATCH':
        if not self._has_domain_context(tokens):
            return False, "NO_MATCH_NO_CONTEXT"
        if not missing_features:
            return False, "NO_MATCH_NO_FEATURES"  # NOWE
        return True, "VALID_LOST_DEMAND"
    return True, "OK"
```

**`routes/bot.py`:** odwrócona kolejność w obu sekcjach (MOTO + ELEKTRO):
```python
# NAJPIERW ekstrakcja
missing_attrs = MissingFeatureExtractor.extract(query, source='moto') if NO_MATCH else []
# POTEM walidacja Z features
is_valid, reason = semantic_validator.validate(query, conf, missing_features=missing_attrs)
```

**Wpływ:** `"samsung galaxy"`, `"audi"`, `"laptop dell"` → wcześniej ai_ready=True, teraz `NO_MATCH_NO_FEATURES` → ai_ready=False. Wszystkie 12 test cases zielone. Backward compat zachowany (`missing_features=None` default).

### Fix #2: MotoFeatureExtractor + dispatcher

**Nowa klasa `MotoFeatureExtractor`** w `reward_engine.py` z 6 typami:

| Typ | Wzorce | Przykład → wynik |
|-----|--------|------------------|
| color | reused `_SHARED_COLORS` | "audi czarny" → `color:black` |
| year | `19[89]\d\|20[0-3]\d` (1980-2039) | "bmw 2005" → `year:2005` |
| gen | BMW `e\d{2,3}/f\d{2,3}/g\d{2,3}`, Audi `b[3-9]/c[5-8]/d[3-5]`, Mercedes `w\d{3}`, VW `mk[1-8]` | "audi a4 b8" → `gen:b8` |
| engine | `\d\.\d` + `tdi/hdi/tsi/tfsi/fsi/tdci/cdti/dci/crdi/jtd/sdi/cdi/kompressor/v6/v8/v12/i4/i6` | "2.0 tdi" → `engine:2.0_tdi` |
| fuel | słownik PL+EN: diesel/benzyna/hybryda/lpg/elektryczny + warianty | "diesel" → `fuel:diesel` |
| body | słownik PL+EN: sedan/kombi/suv/hatchback/coupe/liftback/pickup/van/cabrio/roadster | "kombi" → `body:wagon` |

**Dispatcher** w `MissingFeatureExtractor.extract()`:
```python
def extract(cls, query, source='elektro'):
    if source == 'moto':
        return MotoFeatureExtractor.extract(query)
    # default: existing elektro logic
```

**`routes/bot.py`:** MOTO przekazuje `source='moto'`, ELEKTRO explicit `source='elektro'`.

**Wpływ:** `"klocki hamulcowe audi a4 b8 2.0 tdi 2010"` → 3 features (gen:b8, engine:2.0_tdi, year:2010). Wcześniej: pusty. Cross-domain odseparowane (MOTO query przez ELEKTRO extractor = pusty, sanity OK). 8/8 MOTO + 3/3 ELEKTRO backward compat tests zielone.

### Fix #3: rozdziel `intent_label` od `source`

**Zmiana w `database.py:get_training_data()`** — usunięty fallback:
```python
raw_intent = row[3]
intent_label = raw_intent if (raw_intent and raw_intent.strip()) else None

results.append({
    'intent_label': intent_label,  # category — może być null
    'source': source,              # domain — zawsze ma wartość
    ...
})
```

**Semantyczny rozdział:**
- `intent_label` = product category (`"elektronika"`, `"hamulce"`) — może być `null` dla NO_MATCH bez klasyfikacji
- `source` = bot domain (`"moto"`, `"elektro"`, `"unknown"`) — zawsze obecne
- Empty string `""` i whitespace → `null` (nie pollutujemy JSONL pustymi stringami)

**Wpływ:** ML pipeline dostaje czysty schemat. `source` jako deterministyczny domain label, `intent_label` jako opcjonalna category. 9/9 wariantów rekordów (włącznie z legacy NULL source) handled.

### Fix #4: preserve valid state przy session consolidation

**Zmiana w `database.py:add_query_intent()`** — consolidation path:

1. SELECT pobiera teraz też `ai_ready` istniejącego rekordu
2. Decision tree:
   - `old=1, new=0` → **PRESERVE**: tylko bump `query_refinement_count` + `timestamp`, reszta nietknięta
   - Pozostałe (good→good, bad→bad, bad→good) → standard UPDATE

```python
if old_ai_ready == 1 and new_ai_ready == 0:
    cursor.execute('UPDATE query_intents SET query_refinement_count=?, timestamp=CURRENT_TIMESTAMP WHERE id=?', ...)
    print(f"[P3] PRESERVED valid record: id={existing_id} (good→bad refinement #{refinement_count})")
    return existing_id
# else: standard UPDATE
```

**Wpływ:** sekwencja "iphone 13" (valid) → "asdfgh" (junk) → "qqqq" (junk) → "iphone 13 red" (valid) → "qqqq" (junk) kończy się w DB z `query_text="iphone 13 red"`, `ai_ready=1`, `refinement_count=4`. Wcześniej: `query_text="qqqq"`, `ai_ready=0`. 10/10 test cases zielone na realnej SQLite (4 scenariusze: preserve sequence, recovery, legacy NULL, good-good).

---

## 4. Pliki dotknięte w tej sesji

| Plik | Zmiany |
|------|--------|
| `reward_engine.py` | NOWA klasa `MotoFeatureExtractor`, `_SHARED_COLORS` extracted, `SemanticValidator.validate()` + parametr `missing_features`, `MissingFeatureExtractor.extract()` + dispatcher po `source` |
| `database.py` | Kolumna `source` (CREATE + migracja + INSERT + UPDATE + SELECT), `_mark_stale_bounces()` przy eksporcie, `score_for_export()` przekazuje `purchased`, `intent_label` separation od source, consolidation preserve logic |
| `routes/api.py` | Endpoint domyślnie `ai_ready_only=True`, default limit 5000, override `?ai_ready=0` |
| `routes/bot.py` | MOTO + ELEKTRO: ekstrakcja PRZED walidacją, `source='moto'/'elektro'` w add_query_intent |

Nie dotknięte (wszystko OK z poprzedniej sesji): `elektro_bot.py`, `ecommerce_bot.py`, `templates/site_analytics.html`.

---

## 5. Backlog na następne sesje (punkty 5-15 z audytu)

**Operational priority:**
- [ ] **#5 — Bounce detection real-time** — uruchamiać `_mark_stale_bounces()` też przed `get_stats()`, lub uzupełnić frontend o `beforeunload` → `navigator.sendBeacon` dla precyzji <5s
- [ ] **#6 — `unrealistic_model_patterns`** — przenieść do JSON config, możliwość update bez deploy. Alternatywnie: walidator dynamicznie czyta z katalogu produktów
- [ ] **#7 — Ujednolicić scoring** — zdecydować: zostawić `LDIRewardCalculator.calculate_from_dict()` dla real-time stats i `score_for_export()` dla JSONL (z jasną dokumentacją), albo deprecjacja jednego

**Cleanup priority:**
- [ ] **#8 — Cart deduplication** — `if product_id not in session['cart']: session['cart'].append(...)`, lub model `[{product_id, quantity}]`
- [ ] **#9 — `DATABASE_NAME` z config** — wymienić `sqlite3.connect('dashboard.db')` w `elektro_bot.py` i `ecommerce_bot.py` na import z config
- [ ] **#10 — `IS_DEMO` flag** — zmienna env `LDI_DEMO_MODE` w `add_to_cart()`, kiedy False → nie ustawiaj `purchased=1` (czeka na webhook)

**Verification priority:**
- [ ] **#11 — Audit `scrub_pii`** — przeczytać `privacy.py`, sprawdzić zakres: email, phone, NIP, PESEL, credit card, IBAN. Dopisać brakujące + testy
- [ ] **#12 — Race condition w consolidation** — owinąć SELECT+INSERT w transakcję `BEGIN IMMEDIATE`, lub UNIQUE constraint na `(session_id, timestamp)` z buckets
- [ ] **#13 — Walidacja `alternative_clicked_id`** — w `add_to_cart()` sprawdzić czy `product_id` był w ostatnich sugestiach (przechowywać `session['last_suggested_products']`)
- [ ] **#14 — Domain leakage** — `_has_domain_context()` powinno znać `source` i sprawdzać brands per-domain
- [ ] **#15 — Dynamiczny SemanticValidator** — load brand/category list z katalogu produktów per-client, nie hardcoded w kodzie

---

## TL;DR dla AI

**Co poszło źle przed audytem:** Zaczynałem od punktowych fixów ("napraw Gold Signal score"), rozwiązywałem każdy zgłoszony bug w izolacji, deklarowałem "production ready" po przejściu testów. Trzy razy w tej sesji użytkownik musiał zapytać "czy gotowe na produkcję?" i "co jeszcze pominąłeś?" zanim wykonałem prawdziwy audyt. Każde takie pytanie ujawniało 3-5 dodatkowych problemów, których nie zauważyłem, bo nie patrzyłem systemowo.

**Wzorzec błędu (powtarza się u modeli):** Punktowe łatanie zamiast pełnego audytu. Widzę zgłoszony bug → naprawiam → testuję ten przypadek → ogłaszam sukces. Nie pytam "jakie inne ścieżki kodu mają ten sam problem", "jakie założenia są w architekturze wokół tego", "kto jeszcze konsumuje to wyjście". Efekt: zostawiam 5-10 powiązanych bugów dla użytkownika, które wychodzą iteracyjnie przez kolejne pytania.

**Reguła architektoniczna na przyszłość:** **Przed implementacją — pełen audyt. Przed deklaracją "gotowe" — drugi pełen audyt.** Jeśli user pyta "co jeszcze pominąłem?", to znaczy że SYS-AUDIT nie był zrobiony przed implementacją. Konkretnie dla tego repo: przy dotykaniu JSONL pipeline ZAWSZE sprawdzić wszystkie 4 warstwy (`reward_engine.py` extractor/validator → `database.py` schema/queries → `routes/bot.py` save path → `routes/api.py` export endpoint) ORAZ obie domeny (moto + elektro), nie tylko zgłoszoną.

**Praktyczna konsekwencja:** Każda zmiana w extractor wymaga refleksji nad MOTO i ELEKTRO osobno. Każda zmiana w schema DB wymaga sprawdzenia migracji + INSERT + UPDATE + SELECT + export endpoint. Każde dodanie pola wymaga przemyślenia czy to category czy domain czy metadata — nie mieszać semantycznie różnych rzeczy w jednym polu z fallbackiem.
