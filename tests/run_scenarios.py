"""
Pomiar dokładności klasyfikatora LDI na zestawach scenariuszy (tests/scenarios/*.json).

Uruchomienie:  python tests/run_scenarios.py [moto|elektro|all] [--show-fail]
Wynik: tabela + tests/scenarios/results_<suite>_<data>.json (z datą i commitem — tak mają być cytowane liczby).

Ocena jak w oryginalnym debug.py (źródło wyniku 91/100): confidence_level z analyze_query_intent()
mapowany na decyzję biznesową (BUSINESS). Obok liczony jest wynik "widok dashboardu" — to samo, ale
z mapowaniem z config.py, czyli tym, co klient faktycznie widzi (w moto MEDIUM = ODFILTROWANE).
"""
import contextlib
import io
import json
import os
import subprocess
import sys
from datetime import date

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
os.chdir(ROOT)

SUITES = {
    'moto': ('tests/scenarios/moto_100.json', 'ecommerce_bot'),
    'elektro': ('tests/scenarios/elektro_183.json', 'elektro_bot'),
    'elektro_105': ('tests/scenarios/elektro_105_2026-09.json', 'elektro_bot'),
}


BUSINESS = {'HIGH': 'SPRZEDAŻ', 'MEDIUM': 'SPRZEDAŻ', 'LOW': 'STRACONY KLIENT',
            'NO_MATCH': 'ZAPYTANIE O ROZSZERZENIE OFERTY'}
# Kopia MOTO/ELEKTRO_DECISION_MAPPING z config.py (import config uruchamiałby całą aplikację)
DASHBOARD = {
    'moto': {'HIGH': 'SPRZEDAŻ', 'MEDIUM': 'ODFILTROWANE', 'LOW': 'STRACONY KLIENT',
             'NO_MATCH': 'ZAPYTANIE O ROZSZERZENIE OFERTY'},
    'elektro_105': {'HIGH': 'SPRZEDAŻ', 'MEDIUM': 'SPRZEDAŻ', 'LOW': 'STRACONY KLIENT',
                    'NO_MATCH': 'ZAPYTANIE O ROZSZERZENIE OFERTY'},
    'elektro': {'HIGH': 'SPRZEDAŻ', 'MEDIUM': 'SPRZEDAŻ', 'LOW': 'STRACONY KLIENT',
                'NO_MATCH': 'ZAPYTANIE O ROZSZERZENIE OFERTY'},
}


def _quiet(fn, *a):
    with contextlib.redirect_stdout(io.StringIO()):
        return fn(*a)


def _commit():
    try:
        sha = subprocess.check_output(['git', 'rev-parse', '--short', 'HEAD'], text=True).strip()
        dirty = subprocess.check_output(['git', 'status', '--porcelain', '--', '*.py'], text=True).strip()
        return sha + ('+zmiany' if dirty else '')
    except Exception:
        return 'unknown'


def run(name, show_fail=False):
    path, module = SUITES[name]
    data = json.load(open(path, encoding='utf-8'))
    bot_cls = _quiet(lambda: __import__(module).EcommerceBot)
    bot = _quiet(bot_cls)
    results = []
    for sc in data['scenarios']:
        level = _quiet(bot.analyze_query_intent, sc['query'])['confidence_level']
        got = BUSINESS[level]
        results.append({**sc, 'level': level, 'got': got, 'pass': got == sc['expected'],
                        'pass_dashboard': DASHBOARD[name][level] == sc['expected']})
    passed = sum(r['pass'] for r in results)
    passed_dash = sum(r['pass_dashboard'] for r in results)
    total = len(results)
    meta = {'suite': name, 'date': date.today().isoformat(), 'commit': _commit(),
            'passed': passed, 'total': total, 'accuracy': round(100 * passed / total, 1),
            'passed_dashboard_view': passed_dash}
    print(f"[{name}] {passed}/{total} = {meta['accuracy']}%  (widok dashboardu: {passed_dash}/{total})"
          f"  data {meta['date']}, kod {meta['commit']}")
    if show_fail:
        for r in results:
            if not r['pass']:
                print(f"   #{r['id']:>3} {r['query']!r:40} oczekiwane {r['expected']:32} jest {r['got']} ({r['level']})")
    out = f"tests/scenarios/results_{name}_{meta['date']}.json"
    json.dump({'meta': meta, 'results': results}, open(out, 'w', encoding='utf-8'), ensure_ascii=False, indent=1)
    return meta


if __name__ == '__main__':
    args = [a for a in sys.argv[1:] if not a.startswith('--')]
    which = args[0] if args else 'all'
    names = list(SUITES) if which == 'all' else [which]
    for n in names:
        if os.path.exists(SUITES[n][0]):
            run(n, '--show-fail' in sys.argv)
