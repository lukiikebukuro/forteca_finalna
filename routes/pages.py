"""
Page Routes Blueprint
Plik: routes/pages.py

Contains:
- Static page routes (home, demo, tech, privacy)
- Auth routes (login, logout, unauthorized)
- Dashboard page routes (client, admin, debug)
- Motobot utility endpoints (health, lost-demand, analytics, debug)
- API endpoints (session-info, weekly-report PDF, opt-out)
"""

from flask import Blueprint, render_template, request, jsonify, session, redirect, url_for, flash, make_response
from flask_login import login_user, logout_user, login_required, current_user
from auth_manager import User, require_client_access, require_admin_access, require_debug_access, get_user_dashboard_route
from config import app, bot, LOST_DEMAND_LOG, ELEKTRO_BOT_AVAILABLE, DATABASE_NAME, DEBUG
from database import DatabaseManager, get_client_info
from utils import generate_pdf_html
from datetime import datetime
import os
import csv
import sqlite3

# ================================================================
# BLUEPRINT DEFINITION
# ================================================================

pages_bp = Blueprint('pages', __name__)

# ================================================================
# STATIC PAGE ROUTES
# ================================================================

@pages_bp.route('/')
def home():
    """Main landing page - wizytowka"""
    return render_template('index.html')


@pages_bp.route('/demo-motobot.html')
def demo_motobot():
    """Demo page with iframe to motobot"""
    return render_template('demo-motobot.html')


@pages_bp.route('/motobot-prototype')
def motobot_index():
    """Main page of motobot with bot interface"""
    return render_template('demo_page.html')


@pages_bp.route('/demo')
def demo_page():
    """Demo page with bot and dashboard split screen"""
    return render_template('demo_page.html')


@pages_bp.route('/elektrobot-prototype')
def elektrobot_index():
    """Main page of elektrobot with bot interface"""
    if not ELEKTRO_BOT_AVAILABLE:
        flash('Elektro bot is not available', 'error')
        return redirect(url_for('pages.motobot_index'))
    return render_template('demo_page_elektro.html')


@pages_bp.route('/live-demo')
def elektro_demo_page():
    """Elektro demo page with bot and dashboard split screen"""
    if not ELEKTRO_BOT_AVAILABLE:
        flash('Elektro bot is not available', 'error')
        return redirect(url_for('pages.demo_page'))
    return render_template('demo_page_elektro.html')


@pages_bp.route('/anima')
def anima_page():
    """ANIMA technical manifest page"""
    return render_template('anima.html')


@pages_bp.route('/ldi')
def ldi_page():
    """LDI technical architecture page"""
    return render_template('ldi.html')


@pages_bp.route('/ldi-tests')
def ldi_tests_page():
    """LDI test suite results — 91/100 scenarios"""
    return render_template('ldi_tests.html')


@pages_bp.route('/ldi-readme')
def ldi_readme_page():
    """LDI public sales page with embedded chat bot"""
    return render_template('ldi_readme.html')


@pages_bp.route('/tech')
def tech_docs():
    """Technical documentation page"""
    return render_template('tech.html')


@pages_bp.route('/dashboard')
def dashboard():
    """Glowna strona dashboardu"""
    return render_template('dashboard.html')


@pages_bp.route('/privacy')
def privacy_policy():
    """Polityka Prywatnosci - zgodnosc z RODO"""
    return render_template('privacy.html', now=datetime.now())


# ================================================================
# AUTH ROUTES
# ================================================================

@pages_bp.route('/login', methods=['GET', 'POST'])
def login():
    """Strona logowania - obsluguje GET (formularz) i POST (uwierzytelnienie)"""
    if request.method == 'GET':
        # Jesli uzytkownik juz zalogowany, przekieruj do dashboardu
        if current_user.is_authenticated:
            dashboard_route = get_user_dashboard_route()
            return redirect(url_for(dashboard_route))

        return render_template('login.html')

    elif request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')

        # Walidacja podstawowa
        if not username or not password:
            flash('Wprowadz nazwe uzytkownika i haslo', 'error')
            return render_template('login.html')

        # Uwierzytelnienie
        user = User.authenticate(username, password)

        if user:
            login_user(user, remember=True)
            flash(f'Zalogowano pomyslnie jako {user.username}', 'success')

            # Przekieruj do odpowiedniego dashboardu
            dashboard_route = get_user_dashboard_route()
            next_page = request.args.get('next')

            if next_page:
                return redirect(next_page)
            else:
                return redirect(url_for(dashboard_route))
        else:
            flash('Nieprawidlowa nazwa uzytkownika lub haslo', 'error')
            return render_template('login.html')


@pages_bp.route('/logout')
@login_required
def logout():
    """Wylogowanie uzytkownika"""
    username = current_user.username
    logout_user()
    flash('Zostales wylogowany', 'info')
    return redirect(url_for('pages.login'))


@pages_bp.route('/unauthorized')
def unauthorized():
    """Strona bledu dostepu"""
    return render_template('unauthorized.html'), 403


# ================================================================
# DASHBOARD PAGE ROUTES - 3 POZIOMY DOSTEPU
# ================================================================

@pages_bp.route('/client-dashboard')
@login_required
def client_dashboard():
    """POZIOM 1 - Kokpit Klienta (tylko wlasne dane)"""
    client_info = get_client_info(current_user.client_id)

    return render_template('client-dashboard.html',
                           user=current_user,
                           client=client_info)


@pages_bp.route('/admin-dashboard')
@require_admin_access
def admin_dashboard():
    """POZIOM 2 - Centrum Strategiczne (dane zagregowane + modul sprzedazowy)"""
    return render_template('admin-dashboard.html',
                           user=current_user)


@pages_bp.route('/debug-dashboard')
@require_debug_access
def debug_dashboard():
    """POZIOM 3 - Tryb Debug (surowe logi + telemetria)"""
    if not hasattr(current_user, 'role') or current_user.role != 'debug':
        flash('Access denied. Debug role required.', 'error')
        return redirect(url_for('pages.home'))

    return render_template('debug_dashboard.html',
                           user=current_user)


# ================================================================
# MOTOBOT UTILITY ENDPOINTS
# ================================================================

@pages_bp.route('/motobot-prototype/health')
def health_check():
    """Health check endpoint with system status"""
    return jsonify({
        'status': 'OK',
        'service': 'Universal Soldier E-commerce Bot v5.0 - Doktryna Cierpliwego Nasluchu',
        'version': '5.1-patient-listening-RODO',
        'features': {
            'intent_analysis': True,
            'lost_demand_tracking': True,
            'typo_correction': True,
            'confidence_scoring': True,
            'luxury_brand_detection': True,
            'precision_reward': True,
            'dashboard_integration': True,
            'real_time_websocket': True,
            'debounce_800ms': True,
            'rodo_compliant': True,
            'pii_scrubbing': True,
            'ip_hashing': True
        },
        'session_active': 'cart' in session
    })


@pages_bp.route('/motobot-prototype/report-lost-demand', methods=['POST'])
def report_lost_demand():
    """Endpoint to collect and save lost demand reports"""
    try:
        data = request.get_json()
        query = data.get('query', '')
        email = data.get('email', '')
        notify = data.get('notify', False)

        # Initialize CSV with headers if needed
        if not os.path.exists(LOST_DEMAND_LOG) or os.path.getsize(LOST_DEMAND_LOG) == 0:
            with open(LOST_DEMAND_LOG, 'w', newline='', encoding='utf-8') as csvfile:
                writer = csv.writer(csvfile)
                writer.writerow(['timestamp', 'query', 'email', 'notify', 'machine_filter'])

        # Log to CSV file
        with open(LOST_DEMAND_LOG, 'a', newline='', encoding='utf-8') as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow([
                datetime.now().isoformat(),
                query,
                email,
                notify,
                session.get('machine_filter', 'all')
            ])

        # Send special GA4 event
        ga4_event_data = {
            'event': 'search_lost_demand_confirmed',
            'params': {
                'query': query,
                'email_provided': bool(email),
                'notification_requested': notify,
                'priority': 'CRITICAL'
            }
        }
        bot.send_ga4_event(ga4_event_data)

        print(f"[LOST DEMAND] User confirmed: '{query}' | Email: {bool(email)}")

        return jsonify({
            'status': 'success',
            'message': 'Dziekujemy! Twoje zgloszenie pomoze nam ulepszyc oferte.'
        })

    except Exception as e:
        print(f"[ERROR] Report lost demand error: {e}")
        return jsonify({
            'status': 'error',
            'message': 'Wystapil blad podczas zapisywania zgloszenia.'
        }), 500


@pages_bp.route('/motobot-prototype/track-analytics', methods=['POST'])
def track_analytics():
    """Universal endpoint for tracking various analytics events"""
    try:
        data = request.get_json()
        event_type = data.get('event_type', '')
        event_data = data.get('event_data', {})

        ga4_event = {
            'event': event_type,
            'params': event_data
        }

        success = bot.send_ga4_event(ga4_event)

        return jsonify({
            'status': 'success' if success else 'failed',
            'event_type': event_type
        })

    except Exception as e:
        print(f"[ERROR] Track analytics error: {e}")
        return jsonify({'status': 'error', 'error': str(e)}), 500


# ================================================================
# MOTOBOT DEBUG ENDPOINTS
# ================================================================

@pages_bp.route('/motobot-prototype/debug/test-intent-analysis')
def test_intent_analysis():
    """Debug endpoint for testing intent analysis"""
    if app.debug:
        test_queries = [
            "klocki golf",
            "kloki glof",
            "klocki xyzz",
            "xyza123",
            "opony zimowe",
            "amortyzator ferrari",
            "filtr mann bmw",
            "amortyztor bilsten"
        ]

        results = {}
        for query in test_queries:
            analysis = bot.analyze_query_intent(query)
            results[query] = {
                'confidence_level': analysis['confidence_level'],
                'suggestion_type': analysis['suggestion_type'],
                'token_validity': analysis['token_validity'],
                'best_match_score': analysis['best_match_score'],
                'ga4_event': analysis['ga4_event'],
                'has_luxury': analysis.get('has_luxury_brand', False)
            }

        return jsonify({
            'test': 'Intent Analysis Test - Patient Listening v5.1',
            'results': results,
            'interpretation': {
                'HIGH': 'Show normal results',
                'MEDIUM': 'Show "Did you mean..." (typo)',
                'LOW': 'Show "We don\'t understand" (nonsense)',
                'NO_MATCH': 'Show "Product not in catalog" (LOST DEMAND!)'
            }
        })
    return jsonify({'error': 'Available only in debug mode'}), 403


@pages_bp.route('/motobot-prototype/debug/lost-demand-report')
def lost_demand_report():
    """Debug endpoint to view lost demand log"""
    if app.debug:
        try:
            lost_demands = []
            if os.path.exists(LOST_DEMAND_LOG):
                with open(LOST_DEMAND_LOG, 'r', encoding='utf-8') as csvfile:
                    reader = csv.reader(csvfile)
                    next(reader, None)
                    for row in reader:
                        if len(row) >= 5:
                            lost_demands.append({
                                'timestamp': row[0],
                                'query': row[1],
                                'email': row[2],
                                'notify': row[3],
                                'machine_filter': row[4]
                            })

            # Group by query for summary
            query_counts = {}
            for demand in lost_demands:
                query = demand['query'].lower()
                query_counts[query] = query_counts.get(query, 0) + 1

            top_queries = sorted(query_counts.items(), key=lambda x: x[1], reverse=True)[:10]

            return jsonify({
                'total_lost_demands': len(lost_demands),
                'unique_queries': len(query_counts),
                'recent_demands': lost_demands[-10:] if lost_demands else [],
                'top_missing_products': top_queries
            })
        except Exception as e:
            return jsonify({'error': str(e)}), 500
    return jsonify({'error': 'Available only in debug mode'}), 403


# ================================================================
# API ENDPOINTS
# ================================================================

@pages_bp.route('/api/auth/session-info')
def get_session_info():
    """Zwraca informacje o aktualnej sesji"""
    if current_user.is_authenticated:
        return jsonify({
            'authenticated': True,
            'username': current_user.username,
            'role': current_user.role,
            'client_id': current_user.client_id
        })
    else:
        return jsonify({
            'authenticated': False
        })


@pages_bp.route('/api/client/<int:client_id>/weekly-report.pdf')
@require_client_access
def get_weekly_pdf_report(client_id):
    """API - POZIOM 1: Pobierz cotygodniowy raport PDF dla klienta"""

    # Sprawdz czy user ma dostep do tego klienta
    if not current_user.has_access_to_client(client_id):
        return jsonify({'error': 'Brak dostepu'}), 403

    try:
        # Pobierz dane klienta
        client_info = get_client_info(client_id)
        if not client_info:
            return jsonify({'error': 'Klient nie znaleziony'}), 404

        # DEMO DATA - Elektronika Premium (High Volume)
        demo_data = {
            'client': client_info,
            'report_date': '13.10.2025',
            'total_lost_value': 82450,
            'total_products': 47,
            'total_volume_gross': 251150,
            'lost_products': [
                {'name': 'iPhone 15 Pro 256GB Natural', 'category': 'Smartfony', 'value': 97200, 'frequency': 18, 'unit_price': 5400},
                {'name': 'Laptop Dell XPS 15 (64GB RAM)', 'category': 'Laptopy', 'value': 64400, 'frequency': 7, 'unit_price': 9200},
                {'name': 'Dron DJI Mini 4 Pro', 'category': 'Drony', 'value': 38250, 'frequency': 9, 'unit_price': 4250},
                {'name': 'Samsung S24 Ultra (Kremowy)', 'category': 'Smartfony', 'value': 30500, 'frequency': 5, 'unit_price': 6100},
                {'name': 'Karta RTX 4080 Super', 'category': 'Komponenty PC', 'value': 20800, 'frequency': 4, 'unit_price': 5200},
            ],
            'recommendations': [
                'KRYTYCZNE: Natychmiastowe domowienie Apple - trend wzrostowy na iPhone 15 Pro (18 zapytan/tydzien)',
                'Wprowadzenie konfiguracji B2B dla Dell XPS (64GB RAM) - segment biznesowy wysokomarowy',
                'Rozszerzenie oferty Dronow - sezonowy wzrost zainteresowania (Q4)',
            ]
        }

        # Generuj PDF HTML
        html_content = generate_pdf_html(demo_data)

        response = make_response(html_content)
        response.headers['Content-Type'] = 'text/html'
        response.headers['Content-Disposition'] = f'inline; filename="raport_utraconych_okazji_{client_id}.html"'

        return response

    except Exception as e:
        print(f"[API ERROR] PDF generation failed: {e}")
        return jsonify({'status': 'error', 'message': str(e)}), 500


@pages_bp.route('/api/opt-out', methods=['POST'])
def api_opt_out():
    """API endpoint dla opt-out uzytkownikow"""
    try:
        # W przyszlosci: zapisz opt-out w bazie per IP/session
        # Na razie: obslugiwane przez localStorage w JS
        return jsonify({
            'status': 'success',
            'message': 'Tracking disabled successfully'
        })
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500
