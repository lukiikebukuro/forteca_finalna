# Bug: Modal kopiowania nie scrollował — pełny tekst niedostępny

**Data:** 2026-06-16  
**Zgłoszenie:** Modal z skopiowanym tekstem (site_analytics.html) nie miał scrolla — nie można było przeczytać całości.  
**Czas debugowania:** ~2h (3 błędne próby Claude przed tą sesją)

---

## Gdzie szukać przy podobnym problemie

1. `static/site_tracker.js` — frontend wysyłający dane do API
2. `routes/api.py` — endpoint `/api/site-track` przyjmujący dane
3. `templates/site_analytics.html` — CSS modala

---

## Root cause: dwa niezależne limity, oba ucinały do 300 znaków

### Problem 1 — Frontend (główna przyczyna)
**Plik:** `static/site_tracker.js` linia ~74

```js
// PRZED (błąd):
copy_text: selected.slice(0, 300),

// PO (poprawka):
copy_text: selected.slice(0, 50000),
```

Tekst był ucinany **przed wysłaniem do API**. Do bazy nigdy nie trafiało więcej niż 300 znaków. Modal nie miał czego scrollować — dane były krótkie, nie CSS był winny.

### Problem 2 — Backend (dodatkowe zabezpieczenie, też błędne)
**Plik:** `routes/api.py` w funkcji `site_track()`, event_type == 'copy'

```python
# PRZED (błąd):
copy_text = (data.get('copy_text') or '').strip()[:300]

# PO (poprawka):
copy_text = (data.get('copy_text') or '').strip()[:50000]
```

Nawet gdyby frontend wysłał więcej, backend też ucinał do 300.

---

## Ślepy zaułek (CSS był niewinny, ale i tak był błąd)

CSS modala miał realny, niezależny bug — `overflow: hidden` brakowało na `.modal-box`:

**Plik:** `templates/site_analytics.html`

```css
/* PRZED (błąd): */
.modal-box {
    max-height: 85vh; display: flex; flex-direction: column;
    /* brak overflow: hidden */
}

/* PO (poprawka): */
.modal-box {
    max-height: 85vh; display: flex; flex-direction: column;
    overflow: hidden; /* CRITICAL */
}
```

**Dlaczego to bug mimo że scroll "nie działał" z innego powodu:**  
Flex container z `max-height` bez `overflow: hidden` nie wymusza tej granicy na flex children. `modal-body` dostaje pełny content height i `overflow-y: auto` nigdy nie odpala. Gdyby dane były długie, ten bug by uniemożliwił scroll.

Ten fix był poprawny i pozostaje w kodzie.

---

## Jak zdiagnozowaliśmy

Kluczowy snippet w DevTools Console (po otwarciu modala):

```javascript
const overlay = document.querySelector('.modal-overlay.active');
const box = overlay?.querySelector('.modal-box');
const mb = overlay?.querySelector('.modal-body');
console.log('modal-body height:', mb?.offsetHeight, 'scrollHeight:', mb?.scrollHeight);
console.log('modal-box height:', box?.offsetHeight, 'maxHeight:', getComputedStyle(box).maxHeight);
```

**Wynik który ujawnił problem:**
```
modal-body height: 383  scrollHeight: 383   ← offsetHeight === scrollHeight = brak contentu do scrollowania
modal-box height: 460   maxHeight: 781.15px
```

`scrollHeight === offsetHeight` oznacza: **treść jest za krótka, nie ma czego scrollować**. Problem nie w CSS, problem w danych.

Następnie:
```javascript
const text = document.getElementById('copy-modal-text').textContent;
console.log('długość tekstu:', text.length); // → 300
```

300 znaków = hard limit. Szukaj `slice(0, 300)` lub `[:300]` w kodzie.

---

## Pułapki debugowania

- **Hard-refresh nie pomaga jeśli Cloudflare cachuje** — po zmianie statycznego pliku JS wymagany purge Cloudflare (Caching → Configuration → Purge Everything)
- **`querySelector('.modal-overlay')` zwraca pierwszy modal (bot-modal)** — przy dwóch modalach zawsze używaj `.modal-overlay.active`
- **Nie uruchamiaj snippet gdy modal jest zamknięty** — `display: none` na overlay daje `offsetHeight: 0` dla wszystkich dzieci, wyniki są bez sensu

---

## Commity

| Hash | Plik | Zmiana |
|------|------|--------|
| `c92ebb1` | `templates/site_analytics.html` | CSS fix: `overflow:hidden` na `.modal-box`, scrollbar track, padding na overlay |
| `7be46c0` | `routes/api.py` | Backend limit: `300` → `50000` |
| `3df1523` | `static/site_tracker.js` | Frontend limit: `300` → `50000` (root cause) |
