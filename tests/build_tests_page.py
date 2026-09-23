"""
Generuje templates/ldi_tests.html z wyników tests/run_scenarios.py — strona /testy nie może się
rozjechać z pomiarem (wcześniej pokazywała inne scenariusze niż te, które dały 91/100).

Uruchomienie:  python tests/run_scenarios.py all && python tests/build_tests_page.py
"""
import glob
import html
import json
import os

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
os.chdir(ROOT)

TITLES = {
    'moto': ('Motoryzacja', 'ecommerce_bot.py', 'Oryginalny zestaw z debug.py (wynik opublikowany w czerwcu 2026), '
             'odtworzony 1:1 i przeliczony ponownie.'),
    'elektro': ('Elektronika', 'elektro_bot.py', 'Zestaw napisany od nowa 23.09.2026 — oryginalny (169/183) zaginął. '
                'Oczekiwane wyniki ustalone z reguł i katalogu demo przed pierwszym uruchomieniem.'),
}


def latest(suite):
    files = sorted(glob.glob(f'tests/scenarios/results_{suite}_*.json'))
    return json.load(open(files[-1], encoding='utf-8')) if files else None


def score_class(p):
    return ('perfect', 'perfect') if p == 100 else ('good', 'good') if p >= 80 else ('low', 'low')


def section(suite, data):
    name, module, origin = TITLES[suite]
    m, res = data['meta'], data['results']
    groups = []
    for r in res:
        if not groups or groups[-1][0] != r['group']:
            groups.append((r['group'], []))
        groups[-1][1].append(r)
    out = [f'''
    <div class="header">
        <div class="header-title">LDI — {name}: wyniki testów</div>
        <div class="header-subtitle">{module} · {m['total']} scenariuszy · {len(groups)} grup</div>
        <div class="summary-score">
            <div class="score-big">{m['accuracy']:g}%</div>
            <div class="score-label">
                <strong>{m['passed']} / {m['total']} scenariuszy zaliczonych</strong>
                pomiar {m['date']} · kod {html.escape(m['commit'])}
            </div>
        </div>
        <div class="run-info">{html.escape(origin)}</div>
    </div>''']
    for g, rows in groups:
        ok = sum(r['pass'] for r in rows)
        pct = round(100 * ok / len(rows))
        cls, fill = score_class(pct)
        items = []
        for r in rows:
            note = f" · {html.escape(r['note'])}" if r.get('note') else ''
            got = '' if r['pass'] else f" · otrzymano: {html.escape(r['got'])}"
            q = html.escape(r['query']) if r['query'] else '<em>(puste zapytanie)</em>'
            items.append(f'            <div class="test-row"><span class="test-status">{"✅" if r["pass"] else "❌"}</span>'
                         f'<span class="test-num">#{r["id"]}</span><div class="test-body"><div class="test-query">{q}</div>'
                         f'<div class="test-expected">oczekiwano: {html.escape(r["expected"])}{note}{got}</div></div></div>')
        out.append(f'''
    <div class="section">
        <div class="section-header">
            <span class="section-name">{html.escape(g)}</span>
            <span class="section-score score-{cls}">{ok} / {len(rows)} · {pct}%</span>
        </div>
        <div class="progress-bar"><div class="progress-fill fill-{fill}" style="width:{pct}%"></div></div>
        <div class="tests-list">
{chr(10).join(items)}
        </div>
    </div>''')
    return '\n'.join(out)


def main():
    page = open('templates/ldi_tests.html', encoding='utf-8').read()
    head = page[:page.index('<body>')]
    head = head.replace('<title>LDI Test Suite — 91/100 — Sedno Tech</title>', '<title>LDI — wyniki testów · Sedno Tech</title>')
    head = head.replace('<html lang="en">', '<html lang="pl">')
    moto, elektro = latest('moto'), latest('elektro')
    body = f'''<body>
<div class="container">

    <a href="{{{{ portfolio_url }}}}/ldi" class="back-link">← Architektura LDI</a>

    <div class="cmd-line">
        <span class="prompt">$</span>
        <span class="cmd"> python tests/run_scenarios.py all</span>
    </div>

    <div style="margin-bottom: 28px; padding: 16px 20px; background: #161b22; border: 1px solid #30363d; border-radius: 6px; font-size: 13px; color: #8b949e; line-height: 1.8;">
        <strong style="color:#c9d1d9;">Jak liczony jest wynik.</strong>
        Każde zapytanie przechodzi przez <code>analyze_query_intent()</code>; poziom pewności jest mapowany na decyzję:
        HIGH/MEDIUM = SPRZEDAŻ, LOW = STRACONY KLIENT (szum), NO_MATCH = ZAPYTANIE O ROZSZERZENIE OFERTY (utracony popyt).
        Zaliczone = decyzja zgodna z oczekiwaną. Scenariusze, wyniki i skrypty leżą w repozytorium (<code>tests/scenarios/</code>).
    </div>
{section('moto', moto) if moto else ''}

    <div style="height: 40px;"></div>
{section('elektro', elektro) if elektro else ''}

</div>
<script src="/static/site_tracker.js" defer></script>
</body>
</html>
'''
    open('templates/ldi_tests.html', 'w', encoding='utf-8').write(head + body)
    print('templates/ldi_tests.html ok —', moto and moto['meta'], elektro and elektro['meta'])


if __name__ == '__main__':
    main()
