"""
Macierz pomyłek (oczekiwane x otrzymane) i precyzja/recall klasy NO_MATCH na zestawach scenariuszy LDI.

Uruchomienie:  python tests/confusion_matrix.py [moto|elektro|all]
Tylko odczyt: nie zapisuje nic do bazy ani do tests/scenarios (wynik idzie na stdout).

Klasyfikacja i ocena identyczne jak w run_scenarios.py (ten sam BUSINESS, ta sam DASHBOARD).
NO_MATCH = poziom zwracany przez analyze_query_intent(); w zestawach jego odpowiednik to
oczekiwanie 'ZAPYTANIE O ROZSZERZENIE OFERTY' (brak w ofercie).
"""
import json
import sys
from collections import Counter

from run_scenarios import BUSINESS, DASHBOARD, SUITES, _commit, _quiet

NO_MATCH_LABEL = BUSINESS['NO_MATCH']
LABELS = ['SPRZEDAŻ', 'ODFILTROWANE', 'STRACONY KLIENT', NO_MATCH_LABEL]
SHORT = {'SPRZEDAŻ': 'SPRZ', 'ODFILTROWANE': 'ODFI', 'STRACONY KLIENT': 'STRAC', NO_MATCH_LABEL: 'NO_MATCH'}


def classify(name):
    path, module = SUITES[name]
    data = json.load(open(path, encoding='utf-8'))
    bot = _quiet(_quiet(lambda: __import__(module).EcommerceBot))
    return [(sc, _quiet(bot.analyze_query_intent, sc['query'])['confidence_level']) for sc in data['scenarios']]


def matrix(rows, mapping):
    m = Counter((sc['expected'], mapping[level]) for sc, level in rows)
    used = [l for l in LABELS if any(l in k for k in m)]
    width = max(len(SHORT[l]) for l in used) + 2
    head = 'oczekiwane \\ otrzymane'
    print(f"    {head:<24}" +''.join(f"{SHORT[l]:>{width}}" for l in used) + f"{'suma':>{width}}")
    for exp in used:
        row = [m[(exp, got)] for got in used]
        if sum(row):
            print(f"    {SHORT[exp]:<24}" + ''.join(f"{v:>{width}}" for v in row) + f"{sum(row):>{width}}")
    tp = m[(NO_MATCH_LABEL, NO_MATCH_LABEL)]
    pred = sum(v for (e, g), v in m.items() if g == NO_MATCH_LABEL)
    actual = sum(v for (e, g), v in m.items() if e == NO_MATCH_LABEL)
    correct = sum(v for (e, g), v in m.items() if e == g)
    fmt = lambda a, b: f"{a}/{b} = {100 * a / b:.1f}%" if b else f"{a}/0 = n/d"
    print(f"    trafność ogółem:   {fmt(correct, len(rows))}")
    print(f"    NO_MATCH precyzja: {fmt(tp, pred)}   (trafne NO_MATCH / wszystkie przewidziane NO_MATCH)")
    print(f"    NO_MATCH recall:   {fmt(tp, actual)}   (trafne NO_MATCH / wszystkie oczekiwane NO_MATCH)")
    return m


def main(which):
    print(f"kod: {_commit()}")
    for name in (['moto', 'elektro'] if which == 'all' else [which]):
        rows = classify(name)
        levels = Counter(level for _, level in rows)
        print(f"\n[{name}] n={len(rows)}  poziomy z klasyfikatora: {dict(levels)}")
        print("  ocena testowa (MEDIUM = SPRZEDAŻ, jak w 91/100 i 167/183):")
        matrix(rows, BUSINESS)
        if DASHBOARD[name] != BUSINESS:
            print("  widok dashboardu (mapowanie z config.py):")
            matrix(rows, DASHBOARD[name])


if __name__ == '__main__':
    main(sys.argv[1] if len(sys.argv) > 1 else 'all')
