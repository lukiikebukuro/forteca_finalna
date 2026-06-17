# LDI Evolution Log — 2026-06-16

**Projekt:** forteca_finalna (Lost Demand Intelligence)
**Deployment:** adeptai.pl (Render)
**Sesja:** full-day, kontynuacja z poprzedniej sesji

---

## 1. Kontekst startowy

Na wejściu w sesję istniały następujące znane problemy:

- `score=0.0` dla Gold Signal (NO_MATCH + kliknięcie alternatywy)
- `alternative_clicked_id` nie było zapisywane do JSONL
- `missing_features` zawsze puste (`[]`) dla NO_MATCH
- `purchased` nigdy nie ustawiane (brak checkout flow)
- `bounce` nigdy nie ustawiane (brak logiki detekcji)
- MEDIUM confidence score=0.0 mimo znalezionego produktu
- MOTO bot bez Gold Signal (zero obsługi `add_to_cart` w DB)
- Modalne okna w P5 Site Analytics nie scrollowały

---

## 2. JSONL Training Data — wszystkie naprawy

### 2.1 Gold Signal: score 0.8 (NO_MATCH + click)

**Problem:** `reward_score` był zapisywany przy tworzeniu rekordu, kiedy `clicked_alternative=False`. Wynik: 0.0 zamiast 0.8.

**Rozwiązanie:** Metoda `score_for_export()` w `LDIRewardCalculator` — recalculate at export time z aktualnych danych w DB.

```python
# reward_engine.py
@staticmethod
def score_for_export(confidence_level, clicked_alternative, purchased=False, stored_score=0.0):
    if purchased:
        return 1.0
    if confidence_level == 'NO_MATCH':
        return 0.8 if clicked_alternative else 0.0
    if confidence_level in ('HIGH', 'MEDIUM') and clicked_alternative:
        return 0.1
    if confidence_level == 'MEDIUM':
        return 0.3
    return stored_score if stored_score is not None else 0.0
```

### 2.2 `alternative_clicked_id` — który produkt kliknięto po NO_MATCH

**Problem:** `add_to_cart()` w elektro_bot.py ustawiał tylko `clicked_alternative=1`, bez zapisu `product_id`.

**Rozwiązanie:**
- `database.py`: nowa kolumna `alternative_clicked_id TEXT` + migracja
- `elektro_bot.py`: UPDATE zapisuje `alternative_clicked_id = product_id`
- `database.py:get_training_data()`: SELECT + eksport pola

### 2.3 `purchased=true` (demo mode)

**Decyzja architektoniczna:** brak checkout flow w demo. `add_to_cart` = `purchased=true`. W produkcji: webhook od klienta.

**Implementacja:** oba boty (`elektro_bot.py`, `ecommerce_bot.py`) w UPDATE Gold Signal:
```sql
SET clicked_alternative = 1,
    alternative_clicked_id = ?,
    purchased = 1,
    added_to_cart = 1
```

**Efekt w score_for_export:** `purchased=True` → `score=1.0` (najsilniejszy sygnał treningowy).

### 2.4 MEDIUM confidence score=0.3

**Problem:** MEDIUM (znaleziono produkt ze średnią pewnością) → score=0.0. Zero nagrody za trafne, choć niepewne dopasowanie.

**Rozwiązanie w `score_for_export()`:**
```
MEDIUM (bez kliknięcia) → 0.3  (soft match: produkt znaleziony, niepotwierdzone)
MEDIUM (z kliknięciem)  → 0.1  (potwierdzone kliknięciem)
```

Hierarchia score po wszystkich zmianach:
```
purchased         → 1.0  (zakup)
NO_MATCH + click  → 0.8  (Gold Signal)
NO_MATCH no click → 0.0  (brak sygnału)
HIGH/MED + click  → 0.1  (potwierdzone)
MEDIUM no click   → 0.3  (soft match)
HIGH no click     → stored_score
```

### 2.5 Bounce detection (server-side)

**Problem:** `bounce=0` zawsze, brak logiki detekcji.

**Decyzja:** bez zmian w frontend. Retroaktywna detekcja przy eksporcie.

**Implementacja:** `_mark_stale_bounces()` w `QueryIntentManager`, wywoływane z `get_training_data()`:
```sql
UPDATE query_intents SET bounce = 1
WHERE clicked_alternative = 0 AND purchased = 0 AND bounce = 0
AND timestamp < datetime('now', '-5 minutes')
```

**Logika:** rekord starszy niż 5 minut bez konwersji = bounce. Poprawne — jeśli user kupił/kliknął, `clicked_alternative=1` wyklucza go z UPDATE.

### 2.6 MOTO bot — Gold Signal (był zerowy)

**Odkrycie podczas audytu:** `ecommerce_bot.py` (moto) miał `add_to_cart()` bez żadnej logiki DB. MOTO nigdy nie zapisywał Gold Signal.

**Dwie poprawki:**

1. `routes/bot.py` — MOTO sekcja, po zapisie NO_MATCH:
```python
if confidence_level == 'NO_MATCH':
    session['last_no_match_qi_session'] = session_id or f'moto_{request_id}'
    session['last_no_match_query'] = sanitized_query
    session.modified = True
```

2. `ecommerce_bot.py:add_to_cart()` — analogiczna logika DB UPDATE jak w elektro_bot.py.

### 2.7 MissingFeatureExtractor — rozszerzenie z 2 do 8 typów

**Poprzedni stan:** tylko `color` i `capacity`.

**Nowe typy:**

| Typ | Przykład zapytania | Wynik |
|-----|--------------------|-------|
| `color` | `iphone 13 red` | `color:red` |
| `capacity` | `samsung 512gb` | `capacity:512gb` |
| `ram` | `laptop 16gb ram` | `ram:16gb` |
| `screen` | `laptop 15.6 cali` | `screen:15.6` |
| `year` | `iphone 2023` | `year:2023` |
| `gen` | `macbook m2`, `ryzen 5` | `gen:m2`, `gen:ryzen5` |
| `variant` | `iphone 13 pro max` | `variant:pro_max` |
| `model` | `dell xps 14` | `model:14` |

**Kluczowe reguły rozróżnienia:**
- `ram` vs `capacity`: kontekst ("ram"/"pamięć"/"memory" w sąsiedztwie liczby gb)
- `model` vs `screen`: screen wymaga jednostki ("cali/cale/cal/inch")
- `model` vs `year`: year = 4 cyfry (2020-2030), model = 1-3 cyfry ≥5
- `model` vs `capacity`: capacity ma sufiks gb/tb/mb bezpośrednio po liczbie

**Pułapka: compound variants.** "pro max" musi być wykryte PRZED "pro" i "max" osobno. Rozwiązanie: pre-compiled `_VARIANT_PATTERNS` + konsumowanie dopasowanego tekstu przed kolejnym sprawdzeniem:

```python
q_variants = q
for pattern, label in cls._VARIANT_PATTERNS:
    if pattern.search(q_variants):
        add(label)
        q_variants = pattern.sub('', q_variants)  # konsumuj, żeby "pro" nie matchowało po "pro max"
```

Dynamiczne budowanie wzorców przez `re.escape().replace()` zawiodło w Python 3.13 — zamienione na statyczne `re.compile(r'\bpro[\s_]?max\b')`.

---

## 3. P5 Site Analytics — modalne okna

### Problem
Modalne okna w `/site-analytics` nie scrollowały zawartości.

### Root cause
CSS `overflow-y: auto` na `.modal-body` nie działa bez `min-height: 0` na flex-childzie.

### Fix
```css
.modal-body {
    padding: 20px 24px;
    overflow-y: auto;
    flex: 1;
    min-height: 0;  /* critical for overflow in flex child */
}
```

### Bonus fix: stale closure w event handlerach
Poprzednia implementacja trzymała dane w tablicach globalnych (`allBotQueries[i]`) — po rebuild DOM indeksy były nieaktualne.

Rozwiązanie: `div.dataset.item = JSON.stringify(data)` + inline addEventListener:
```javascript
div.dataset.item = JSON.stringify(q);
div.addEventListener('click', function() {
    openBotModal(JSON.parse(this.dataset.item));
});
```

---

## 4. Stan JSONL po wszystkich naprawach

Przykład rekordu Gold Signal (production-ready):
```json
{
  "query": "dell xps 14",
  "intent_label": "elektronika",
  "confidence": "NO_MATCH",
  "reward_signal": {
    "score": 0.8,
    "clicked_alternative": true,
    "purchased": false,
    "bounce": false
  },
  "missing_features": ["model:14"],
  "matched_product_id": null,
  "alternative_clicked_id": "dell-xps-15-32gb-1tb",
  "timestamp": "2026-06-16 18:47:32",
  "ai_ready": true,
  "query_refinement_count": 0
}
```

Przykład rekordu purchased:
```json
{
  "query": "iphone 13 pro max 256gb",
  "confidence": "NO_MATCH",
  "reward_signal": {
    "score": 1.0,
    "clicked_alternative": true,
    "purchased": true,
    "bounce": false
  },
  "missing_features": ["variant:pro_max", "capacity:256gb", "model:13"],
  "alternative_clicked_id": "iphone-13-64gb"
}
```

---

## 5. Lekcja architektoniczna — standard pracy

> **ZERO łatania taśmą. To jest standard pracy Łukasza Piskorskiego.**

Każda implementacja w tym projekcie przechodzi przez trzy fazy:

### Faza 1: Pełny audyt architektury
Przed napisaniem jednej linii kodu: przeczytać WSZYSTKIE pliki które dotyczą obszaru zmian. Nie "plik który mi pokazano", ale cały flow — od wejścia requestu przez wszystkie warstwy do wyjścia.

**Przykład z tej sesji:** Gold Signal wymagał audytu 4 plików jednocześnie:
`visitor_tracking.js` → `routes/bot.py` → `elektro_bot.py` → `database.py` → JSONL export.
Gdyby audyt był niekompletny: naprawilibyśmy elektro i pominęli MOTO (dokładnie co się stało z poprzednią implementacją `alternative_clicked_id`).

### Faza 2: Lista wszystkich scenariuszy
Przed implementacją: wypisać WSZYSTKIE przypadki które muszą działać.

**Przykład z tej sesji dla score_for_export:**
```
purchased=True           → 1.0
NO_MATCH + clicked       → 0.8
NO_MATCH + no click      → 0.0
HIGH/MEDIUM + clicked    → 0.1
MEDIUM + no click        → 0.3   ← ten scenariusz był pomijany
HIGH + no click          → stored_score
```

Gdyby lista była niepełna: wdrożylibyśmy 5/6 przypadków i zostawili regresję.

### Faza 3: Dopiero implementacja
Kod pisany po (1) i (2) jest prosty. Komplikacje to sygnał że audyt był niekompletny.

### Antywzorzec który eliminujemy
```
❌ Widzę błąd X → łatam X → deploy → następny dzień: błąd Y (konsekwencja X)
✓  Widzę błąd X → audyt całego flow → lista scenariuszy → naprawiam X, Y, Z jednocześnie
```

**Konkretny przykład z tej sesji:** MOTO Gold Signal. Gdybym łatał tylko ELEKTRO (bo tam była zgłoszona usterka), MOTO nigdy by nie zbierał danych treningowych. Audyt `ecommerce_bot.py` ujawnił brak całej logiki zanim klient by to zauważył.

---

## 6. Pliki zmodyfikowane

| Plik | Zmiana |
|------|--------|
| `reward_engine.py` | `MissingFeatureExtractor` 2→8 typów, `score_for_export()` +purchased +MEDIUM |
| `elektro_bot.py` | `add_to_cart()` +purchased=1, +added_to_cart=1 |
| `ecommerce_bot.py` | `add_to_cart()` — cała logika Gold Signal DB (była pusta) |
| `database.py` | `alternative_clicked_id` kolumna, `score_for_export()` call +purchased, `_mark_stale_bounces()` |
| `routes/bot.py` | MOTO sekcja: NO_MATCH → `session['last_no_match_qi_session']` |
| `templates/site_analytics.html` | modal scroll fix (`min-height: 0`), stale closure fix |

---

## 7. Otwarte (nie wdrożone w tej sesji)

- `score_for_export()` nie aktualizuje retroaktywnie starych rekordów w DB — score jest liczony przy eksporcie, co jest poprawne
- Bounce detection wymaga sygnału `beforeunload` z frontend dla precyzji < 5 sekund (teraz: proxy 5-minutowy)
- MOTO nie ma produktów w bazie do "add_to_cart" — Gold Signal w moto zadziała dopiero gdy klient ma produkty moto w katalogu
- `query_refinement_count` działa poprawnie przez session consolidation, ale test JSONL pokazuje 0 bo dane testowe miały różne session_id
