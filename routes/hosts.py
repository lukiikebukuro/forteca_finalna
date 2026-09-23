"""
Routing po hoście: jedna aplikacja, dwie domeny.

- PORTFOLIO_HOST (sedno.tech)       — portfolio: /, /anima, /ldi (opis architektury), /privacy
- LDI_HOST       (utraconypopyt.pl) — produkt LDI: strona produktu, live demo, dashboardy, logowanie

Jedna usługa zamiast dwóch, bo baza to SQLite na dysku usługi: dwie usługi = dwie bazy,
radar P2 przestałby widzieć zapytania z demo.

Nieznane hosty (localhost, *.onrender.com) nie są przekierowywane — lokalny dev działa jak dawniej.
Przekierowujemy tylko GET/HEAD; POST po 301 gubi body.
"""

from flask import request, redirect, render_template
from config import PORTFOLIO_HOST, LDI_HOST, PORTFOLIO_URL, LDI_URL, BRAND_NAME, CONTACT_EMAIL

# Ścieżki, które na portfolio są przekierowywane na domenę LDI (stara ścieżka → nowa)
LDI_PATH_MAP = {
    '/ldi-readme': '/',
    '/live-demo': '/elektronika',
    '/demo': '/motoryzacja',
    '/demo-motobot.html': '/motoryzacja',
    '/motobot-prototype': '/motoryzacja',
    '/elektrobot-prototype': '/elektronika',
    '/ldi-tests': '/testy',
    '/ldi-landing': '/',
}

# Ścieżki (prefiksy) żyjące wyłącznie na domenie LDI — logowanie i panele.
# Sesja jest per domena, więc login i dashboardy muszą być w jednym miejscu.
LDI_ONLY_PREFIXES = (
    '/login', '/logout', '/unauthorized', '/dashboard',
    '/client-dashboard', '/admin-dashboard', '/debug-dashboard', '/site-analytics',
)

# Strony portfolio, które na domenie LDI odsyłamy z powrotem na portfolio
PORTFOLIO_ONLY_PATHS = ('/anima', '/ldi')


def _host():
    host = (request.host or '').split(':')[0].lower()
    return host[4:] if host.startswith('www.') else host


def is_ldi_host():
    return _host() == LDI_HOST


def is_portfolio_host():
    return _host() == PORTFOLIO_HOST


def _with_query(url):
    qs = request.query_string.decode('utf-8', 'ignore')
    return f'{url}?{qs}' if qs else url


def register_host_routing(app):

    @app.context_processor
    def inject_branding():
        # Zmienne dostępne w każdym szablonie — jedno miejsce prawdy dla nazwy, maila i domen
        return {
            'brand_name': BRAND_NAME,
            'contact_email': CONTACT_EMAIL,
            'portfolio_url': PORTFOLIO_URL,
            'ldi_url': LDI_URL,
        }

    @app.before_request
    def route_by_host():
        if request.method not in ('GET', 'HEAD'):
            return None
        path = request.path.rstrip('/') or '/'

        if is_portfolio_host():
            if path in LDI_PATH_MAP:
                return redirect(_with_query(LDI_URL + LDI_PATH_MAP[path]), code=301)
            if path.startswith(LDI_ONLY_PREFIXES):
                return redirect(_with_query(LDI_URL + request.path), code=301)
            return None

        if is_ldi_host():
            if path == '/':
                return render_template('ldi_home.html')
            if path in PORTFOLIO_ONLY_PATHS:
                return redirect(PORTFOLIO_URL + path, code=301)
            # Stare ścieżki (np. /live-demo) na nowej domenie też prowadzą na nowe
            if path in LDI_PATH_MAP and LDI_PATH_MAP[path] != path:
                return redirect(_with_query(LDI_PATH_MAP[path]), code=301)
            return None

        return None
