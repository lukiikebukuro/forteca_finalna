"""
Publiczne podglądy P2 (radar B2B) i P3 (dane treningowe) na danych FIKCYJNYCH.

Firmy i sesje są wymyślone i tak oznaczone. Klasyfikację każdego zapytania liczy jednak
prawdziwy silnik LDI przy każdym wejściu na stronę — podgląd pokazuje działanie produktu,
nie makietę. Nagroda w rekordzie JSONL liczona jest tą samą funkcją co w eksporcie.
Żywe P2/P3 (prawdziwe firmy, prawdziwe logi) zostają za logowaniem.
"""
import contextlib
import io
import json

from flask import Blueprint, render_template

from config import moto_bot, elektro_bot, MOTO_DECISION_MAPPING, ELEKTRO_DECISION_MAPPING
from reward_engine import LDIRewardCalculator, semantic_validator, MissingFeatureExtractor

demo_previews_bp = Blueprint('demo_previews', __name__)

DECISION_LABEL = {'ZNALEZIONE PRODUKTY': 'SPRZEDAŻ', 'UTRACONE OKAZJE': 'UTRACONY POPYT', 'ODFILTROWANE': 'SZUM'}

# Wszystkie firmy są FIKCYJNE — celowo nazwy „Firma Demo X", żeby nie trafić w istniejący podmiot.
RADAR_SESSIONS = [
    {'name': 'Firma Demo A', 'kind': 'hurtownia części samochodowych', 'city': 'Poznań', 'when': '2 min temu',
     'queries': ['klocki brembo bmw e90', 'tarcze audi a4 b8 320mm', 'rozrusznik ford focus mk2', 'sprzęgło sachs passat b6']},
    {'name': 'Firma Demo B', 'kind': 'serwis flotowy', 'city': 'Wrocław', 'when': '14 min temu',
     'queries': ['olej castrol 5w30', 'filtr oleju mann', 'akumulator varta 74ah']},
    {'name': 'Firma Demo C', 'kind': 'warsztat samochodowy', 'city': 'Gdańsk', 'when': '1 godz. temu',
     'queries': ['klocki ferrari']},
    {'name': 'Odwiedzający bez rozpoznanej firmy', 'kind': 'sieć prywatna', 'city': '—', 'when': '3 godz. temu',
     'queries': ['kanapka z serem']},
]

DATA_QUERIES = [
    ('moto', 'klocki brembo bmw e90'), ('moto', 'tarcze audi a4 b8 320mm'), ('moto', 'amory sachs'),
    ('moto', 'klocki ferrari'), ('moto', 'kanapka z serem'), ('moto', 'akumlator varta'),
    ('elektro', 'iphone 13 128gb'), ('elektro', 'samsung s25'), ('elektro', 'laptop rtx 4090'),
    ('elektro', 'oneplus 12'), ('elektro', 'makbuk air'), ('elektro', 'asdfghjkl'),
]


def _classify(source, query):
    bot, mapping = (elektro_bot, ELEKTRO_DECISION_MAPPING) if source == 'elektro' and elektro_bot else (moto_bot, MOTO_DECISION_MAPPING)
    with contextlib.redirect_stdout(io.StringIO()):
        level = bot.analyze_query_intent(query)['confidence_level']
        # Ta sama ścieżka co produkcja (routes/bot.py:493, :733): cechy tylko dla NO_MATCH
        features = MissingFeatureExtractor.extract(query, source=source) if level == 'NO_MATCH' else []
        valid, reason = semantic_validator.validate(query, level, missing_features=features)
    decision = mapping.get(level, 'ODFILTROWANE')
    return {'query': query, 'source': source, 'level': level, 'decision': decision,
            'label': DECISION_LABEL.get(decision, decision), 'ai_ready': bool(valid), 'reason': reason,
            'features': features}


@demo_previews_bp.route('/radar-demo')
def radar_demo():
    sessions = []
    for s in RADAR_SESSIONS:
        rows = [_classify('moto', q) for q in s['queries']]
        lost = sum(r['decision'] == 'UTRACONE OKAZJE' for r in rows)
        found = sum(r['decision'] == 'ZNALEZIONE PRODUKTY' for r in rows)
        n = len(rows)
        temp = 'gorąca' if n >= 4 else ('bada ofertę' if n >= 2 else 'pojedyncze wejście')
        sessions.append({**s, 'rows': rows, 'lost': lost, 'found': found, 'n': n, 'temp': temp})
    totals = {'firmy': sum(1 for s in sessions if s['name'].startswith('Firma')),
              'zapytania': sum(s['n'] for s in sessions),
              'utracone': sum(s['lost'] for s in sessions)}
    return render_template('radar_demo.html', sessions=sessions, totals=totals)


@demo_previews_bp.route('/dane-demo')
def dane_demo():
    rows = [_classify(src, q) for src, q in DATA_QUERIES]
    for r in rows:
        r['score'] = LDIRewardCalculator.score_for_export(r['level'], False, False, 0.0)
    n = len(rows)
    stats = {'n': n,
             'lost': sum(r['decision'] == 'UTRACONE OKAZJE' for r in rows),
             'noise': sum(r['decision'] == 'ODFILTROWANE' for r in rows),
             'ready': sum(r['ai_ready'] for r in rows)}
    sample = next((r for r in rows if r['decision'] == 'UTRACONE OKAZJE' and r['ai_ready']), rows[0])
    record = {
        'query': sample['query'],
        'intent_label': sample['source'],
        'confidence': sample['level'],
        'source': sample['source'],
        'reward_signal': {'score': sample['score'], 'clicked_alternative': False, 'purchased': False, 'bounce': False},
        'missing_features': sample['features'],
        'ai_ready': sample['ai_ready'],
    }
    return render_template('dane_demo.html', rows=rows, stats=stats, sample_query=sample['query'],
                           record_json=json.dumps(record, ensure_ascii=False, indent=2))
