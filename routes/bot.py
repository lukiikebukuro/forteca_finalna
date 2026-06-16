"""
Bot routes blueprint - dual-bot e-commerce system.
MotoBot (automotive) + ElektroBot (electronics).
Handles: bot start, bot send, search suggestions, query analysis (TCD).
"""

import sqlite3
import time
import uuid
import traceback
from datetime import datetime

from flask import Blueprint, request, jsonify, session

from config import (
    app, limiter, socketio,
    moto_bot, elektro_bot, ELEKTRO_BOT_AVAILABLE,
    bot,
    MOTO_DECISION_MAPPING, ELEKTRO_DECISION_MAPPING,
    DATABASE_NAME,
    ldi_reward_calc  # P3: LDI Reward Calculator
)
from reward_engine import semantic_validator, MissingFeatureExtractor
from database import (
    DatabaseManager, QueryIntentManager,
    save_company_data, save_hot_lead, save_log_entry,
    get_visitor_context
)
from privacy import scrub_pii
from utils import extract_category_from_query, calculate_lost_value_internal, log_lost_demand


# ========================================
# BLUEPRINT
# ========================================

bot_bp = Blueprint('bot', __name__)


# ========================================
# MOTO BOT START
# ========================================

@bot_bp.route('/motobot-prototype/bot/start', methods=['POST'])
@limiter.limit("20/minute")
def bot_start():
    """Initialize bot session - MOTO"""
    try:
        session.permanent = True
        session['cart'] = []
        session['context'] = None
        session['machine_filter'] = None

        # Get initial greeting
        initial_response = moto_bot.get_initial_greeting()

        return jsonify({'reply': initial_response})

    except Exception as e:
        print(f"[ERROR] Moto bot start error: {e}")
        app.logger.error(f"Bot start error: {e}", exc_info=True)
        return jsonify({
            'reply': {
                'text_message': f'Wystapil blad podczas inicjalizacji: {str(e)}',
                'buttons': [
                    {'text': 'Sprobuj ponownie', 'action': 'restart'}
                ]
            }
        }), 500


# ========================================
# ELEKTRO BOT START
# ========================================

@bot_bp.route('/elektrobot-prototype/bot/start', methods=['POST'])
@limiter.limit("20/minute")
def elektro_bot_start():
    """Initialize bot session - ELEKTRO"""
    if not ELEKTRO_BOT_AVAILABLE:
        return jsonify({'error': 'Elektro bot not available'}), 503

    try:
        session.permanent = True
        session['cart'] = []
        session['context'] = None
        session['machine_filter'] = None

        # Get initial greeting
        initial_response = elektro_bot.get_initial_greeting()

        return jsonify({'reply': initial_response})

    except Exception as e:
        print(f"[ERROR] Elektro bot start error: {e}")
        app.logger.error(f"Elektro bot start error: {e}", exc_info=True)
        return jsonify({
            'reply': {
                'text_message': f'Wystapil blad podczas inicjalizacji: {str(e)}',
                'buttons': [
                    {'text': 'Sprobuj ponownie', 'action': 'restart'}
                ]
            }
        }), 500


# ========================================
# MOTO BOT SEND
# ========================================

@bot_bp.route('/motobot-prototype/bot/send', methods=['POST'])
@limiter.limit("100/minute")
def bot_send():
    """Handle user messages - MOTO"""
    try:
        data = request.get_json()
        user_message = data.get('message', '')
        button_action = data.get('button_action', '')

        print(f"[DEBUG] Moto Message: {user_message}, Action: {button_action}")
        app.logger.info(f"Moto received: '{user_message}', Action: '{button_action}'")

        # Process button action or text message
        if button_action:
            reply = moto_bot.handle_button_action(button_action)
        elif user_message:
            reply = moto_bot.process_message(user_message)
        else:
            return jsonify({'error': 'No message or action provided'}), 400

        return jsonify({'reply': reply})

    except Exception as e:
        print(f"[ERROR] Moto bot send error: {e}")
        app.logger.error(f"Moto bot send error: {e}", exc_info=True)
        traceback.print_exc()
        return jsonify({
            'reply': {
                'text_message': 'Wystapil blad podczas przetwarzania zadania.',
                'buttons': [
                    {'text': 'Powrot do menu', 'action': 'main_menu'}
                ]
            }
        }), 500


# ========================================
# ELEKTRO BOT SEND
# ========================================

@bot_bp.route('/elektrobot-prototype/bot/send', methods=['POST'])
@limiter.limit("100/minute")
def elektro_bot_send():
    """Handle user messages - ELEKTRO"""
    if not ELEKTRO_BOT_AVAILABLE:
        return jsonify({'error': 'Elektro bot not available'}), 503

    try:
        data = request.get_json()
        user_message = data.get('message', '')
        button_action = data.get('button_action', '')

        print(f"[DEBUG] Elektro Message: {user_message}, Action: {button_action}")
        app.logger.info(f"Elektro received: '{user_message}', Action: '{button_action}'")

        # Process button action or text message
        if button_action:
            reply = elektro_bot.handle_button_action(button_action)
        elif user_message:
            reply = elektro_bot.process_message(user_message)
        else:
            return jsonify({'error': 'No message or action provided'}), 400

        return jsonify({'reply': reply})

    except Exception as e:
        print(f"[ERROR] Elektro bot send error: {e}")
        app.logger.error(f"Elektro bot send error: {e}", exc_info=True)
        traceback.print_exc()
        return jsonify({
            'reply': {
                'text_message': 'Wystapil blad podczas przetwarzania zadania.',
                'buttons': [
                    {'text': 'Powrot do menu', 'action': 'main_menu'}
                ]
            }
        }), 500


# ========================================
# MOTO SEARCH SUGGESTIONS
# ========================================

@bot_bp.route('/motobot-prototype/search-suggestions', methods=['POST'])
@limiter.limit("100/minute")
def search_suggestions():
    """Real-time search suggestions - MOTO"""
    try:
        data = request.get_json()
        query = data.get('query', '').strip()
        search_type = data.get('type', 'products')

        # Minimum 2 characters to search
        if len(query) < 2:
            return jsonify({'suggestions': [], 'confidence_level': 'NONE'})

        suggestions = []
        confidence_level = 'HIGH'
        ga4_event = None

        if search_type == 'faq':
            # FAQ search
            faq_results = moto_bot.get_fuzzy_faq_matches(query, limit=5)
            for faq, score in faq_results:
                suggestions.append({
                    'id': faq['id'],
                    'text': faq['question'],
                    'type': 'faq',
                    'score': int(score),
                    'category': faq.get('category', 'FAQ'),
                    'question': faq['question'],
                    'answer': faq['answer']
                })

            confidence_level = 'HIGH' if suggestions else 'NO_MATCH'

        else:
            # Search products with intent analysis
            machine_filter = session.get('machine_filter')

            result = moto_bot.get_fuzzy_product_matches(
                query, machine_filter, limit=6, analyze_intent=True
            )

            if isinstance(result, tuple) and len(result) == 4:
                # New format with analysis
                products, confidence_level, suggestion_type, analysis = result

                # Determine GA4 event
                ga4_event_data = moto_bot.determine_ga4_event(analysis)
                if ga4_event_data:
                    ga4_event = ga4_event_data['event']
                    moto_bot.send_ga4_event(ga4_event_data)

                # Prepare suggestions
                for product, score in products:
                    stock_status = 'available' if product['stock'] > 10 else 'limited' if product['stock'] > 0 else 'out'
                    suggestions.append({
                        'id': product['id'],
                        'text': product['name'],
                        'type': 'product',
                        'score': int(score),
                        'price': f"{product['price']:.2f} zl",
                        'stock': product['stock'],
                        'stock_status': stock_status,
                        'brand': product['brand']
                    })

                # Log lost demand if needed
                if confidence_level == 'NO_MATCH':
                    log_lost_demand(query, analysis)

        print(f"[MOTO SUGGESTIONS] Query: '{query}' | Type: {search_type} | Confidence: {confidence_level} | GA4: {ga4_event}")

        return jsonify({
            'suggestions': suggestions,
            'query': query,
            'confidence_level': confidence_level,
            'ga4_event': ga4_event
        })

    except Exception as e:
        print(f"[ERROR] Moto search suggestions error: {e}")
        app.logger.error(f"Moto search suggestions error: {e}", exc_info=True)
        traceback.print_exc()
        return jsonify({'suggestions': [], 'error': str(e)}), 200


# ========================================
# ELEKTRO SEARCH SUGGESTIONS
# ========================================

@bot_bp.route('/elektrobot-prototype/search-suggestions', methods=['POST'])
@limiter.limit("100/minute")
def elektro_search_suggestions():
    """Real-time search suggestions - ELEKTRO"""
    if not ELEKTRO_BOT_AVAILABLE:
        return jsonify({'suggestions': [], 'error': 'Elektro bot not available'}), 503

    try:
        data = request.get_json()
        query = data.get('query', '').strip()
        search_type = data.get('type', 'products')

        # Minimum 2 characters to search
        if len(query) < 2:
            return jsonify({'suggestions': [], 'confidence_level': 'NONE'})

        suggestions = []
        confidence_level = 'HIGH'
        ga4_event = None

        if search_type == 'faq':
            # FAQ search
            faq_results = elektro_bot.get_fuzzy_faq_matches(query, limit=5)
            for faq, score in faq_results:
                suggestions.append({
                    'id': faq['id'],
                    'text': faq['question'],
                    'type': 'faq',
                    'score': int(score),
                    'category': faq.get('category', 'FAQ'),
                    'question': faq['question'],
                    'answer': faq['answer']
                })

            confidence_level = 'HIGH' if suggestions else 'NO_MATCH'

        else:
            # Search products with intent analysis
            machine_filter = session.get('machine_filter')

            result = elektro_bot.get_fuzzy_product_matches(
                query, machine_filter, limit=6, analyze_intent=True
            )

            if isinstance(result, tuple) and len(result) == 4:
                # New format with analysis
                products, confidence_level, suggestion_type, analysis = result

                # Determine GA4 event
                ga4_event_data = elektro_bot.determine_ga4_event(analysis)
                if ga4_event_data:
                    ga4_event = ga4_event_data['event']
                    elektro_bot.send_ga4_event(ga4_event_data)

                # Prepare suggestions
                for product, score in products:
                    stock_status = 'available' if product['stock'] > 10 else 'limited' if product['stock'] > 0 else 'out'
                    suggestions.append({
                        'id': product['id'],
                        'text': product['name'],
                        'type': 'product',
                        'score': int(score),
                        'price': f"{product['price']:.2f} zl",
                        'stock': product['stock'],
                        'stock_status': stock_status,
                        'brand': product['brand']
                    })

                # Log lost demand if needed
                if confidence_level == 'NO_MATCH':
                    log_lost_demand(query, analysis)

        print(f"[ELEKTRO SUGGESTIONS] Query: '{query}' | Type: {search_type} | Confidence: {confidence_level} | GA4: {ga4_event}")

        return jsonify({
            'suggestions': suggestions,
            'query': query,
            'confidence_level': confidence_level,
            'ga4_event': ga4_event
        })

    except Exception as e:
        print(f"[ERROR] Elektro search suggestions error: {e}")
        app.logger.error(f"Elektro search suggestions error: {e}", exc_info=True)
        traceback.print_exc()
        return jsonify({'suggestions': [], 'error': str(e)}), 200


# ========================================
# MOTO ANALYZE QUERY (TCD - Doktryna Cierpliwego Nasluchu)
# ========================================

@bot_bp.route('/motobot-prototype/api/analyze_query', methods=['POST'])
@limiter.limit("100/minute")
def analyze_query():
    """
    MOTO VERSION - Doktryna Cierpliwego Nasluchu
    Called after 800ms pause - sends event to TCD
    """
    request_id = str(uuid.uuid4())[:8]

    try:
        data = request.get_json()
        query = data.get('query', '').strip()
        search_type = data.get('type', 'products')

        # Receive geolocation data from frontend (if available)
        visitor_city = data.get('city', 'Unknown')
        visitor_country = data.get('country', 'Unknown')
        visitor_org = data.get('org', 'Unknown')

        # PASSIVE RADAR: Receive session_id
        session_id = data.get('session_id', None)

        print(f"[MOTO FINAL ANALYSIS][REQ:{request_id}] Query: '{query}' | Type: {search_type} | Geo: {visitor_city}, {visitor_country} | Session: {session_id}")

        # RODO: Sanitize query
        sanitized_query = scrub_pii(query)
        if sanitized_query != query:
            print(f"[RODO] PII scrubbed in analyze_query")
            app.logger.warning(f"PII scrubbed in analyze_query")

        if len(sanitized_query) < 2:
            return jsonify({
                'status': 'success',
                'message': 'Query too short'
            })

        # Analyze query
        machine_filter = session.get('machine_filter')

        if search_type == 'faq':
            # FAQ - usually HIGH confidence
            confidence_level = 'HIGH'
            category = 'faq'
        else:
            # Products - full analysis
            result = bot.get_fuzzy_product_matches(
                sanitized_query, machine_filter, limit=6, analyze_intent=True
            )

            if isinstance(result, tuple) and len(result) == 4:
                products, confidence_level, suggestion_type, analysis = result
                category = extract_category_from_query(sanitized_query)
            else:
                confidence_level = 'HIGH'
                category = 'unknown'

        # Map confidence -> decision (MOTO rules)
        decision_mapping = MOTO_DECISION_MAPPING
        decision = decision_mapping.get(confidence_level, 'ODFILTROWANE')

        # Calculate value only for lost opportunities
        potential_value = 0
        if decision == 'UTRACONE OKAZJE':
            potential_value = calculate_lost_value_internal(sanitized_query, source='moto')

        # SAVE TO DATABASE
        event_id = DatabaseManager.add_event(
            sanitized_query,
            decision,
            'Finalne zapytanie uzytkownika (MOTO)',
            category,
            'moto',
            potential_value,
            f'Analiza po 800ms pauzy - confidence: {confidence_level}'
        )

        # === PERSISTENT STORAGE (MOTO) ===
        session_id = request.cookies.get('visitor_session_id')
        organization = 'Unknown Visitor'
        city = country = 'Unknown'
        if session_id:
            visitor_ctx = get_visitor_context(session_id)
            if visitor_ctx and visitor_ctx != 'Unknown':
                parts = visitor_ctx.split(', ')
                organization = parts[0] if len(parts) >= 1 else organization
                city = parts[1] if len(parts) >= 2 else city
                country = parts[2] if len(parts) >= 3 else country
        company_data = save_company_data(organization, city, country, sanitized_query, decision)
        if company_data and company_data['engagement_score'] >= 30 and decision == 'ZNALEZIONE PRODUKTY':
            save_hot_lead(organization, sanitized_query, company_data['engagement_score'])
        save_log_entry(decision, organization, sanitized_query)

        # === P3: CALCULATE REWARD SIGNAL & SAVE TO query_intents (MOTO) ===
        best_match_score = 0
        matched_product_id = None
        if search_type != 'faq' and isinstance(result, tuple) and len(result) == 4:
            products_list = result[0]
            if products_list and len(products_list) > 0:
                best_match_score = int(products_list[0][1]) if products_list[0][1] else 0
                matched_product_id = str(products_list[0][0].get('id', '')) if isinstance(products_list[0][0], dict) else None

        reward_data = {
            'session_id': session_id or f'moto_{request_id}',
            'original_query': sanitized_query,
            'confidence_level': confidence_level,
            'was_lost_demand': decision == 'UTRACONE OKAZJE',
            'clicked_alternative': False,
            'query_refinement_count': 0,
            'time_to_first_click': 0.0,
            'session_duration': 0.0,
            'bounce': False,
            'added_to_cart': False,
            'purchased': False,
            'cart_value': 0.0
        }
        reward_score = ldi_reward_calc.calculate_from_dict(reward_data)

        # === SEMANTIC VALIDATION: Check if query is AI_READY ===
        is_valid, validation_reason = semantic_validator.validate(sanitized_query, confidence_level)
        ai_ready = is_valid
        if not is_valid:
            print(f"[SEMANTIC][MOTO] Query rejected: '{sanitized_query}' -> {validation_reason}")

        missing_attrs = MissingFeatureExtractor.extract(sanitized_query) if confidence_level == 'NO_MATCH' else []

        try:
            QueryIntentManager.add_query_intent({
                'session_id': session_id or f'moto_{request_id}',
                'query_text': sanitized_query,
                'confidence_level': confidence_level,
                'suggestion_type': category,
                'best_match_score': best_match_score,
                'clicked_alternative': False,
                'query_refinement_count': 0,
                'time_to_first_click': None,
                'session_duration': None,
                'bounce': False,
                'added_to_cart': False,
                'purchased': False,
                'cart_value': 0.0,
                'reward_score': reward_score,
                'missing_attributes': missing_attrs,
                'matched_product_id': matched_product_id,
                'ai_ready': ai_ready
            })
            print(f"[P3][MOTO] QueryIntent saved: reward={reward_score:.4f}, confidence={confidence_level}, missing={missing_attrs}, ai_ready={ai_ready}")
        except Exception as p3_error:
            print(f"[P3][MOTO] Failed to save QueryIntent: {p3_error}")
            app.logger.error(f"[P3] QueryIntent save failed: {p3_error}")

        # SEND VIA WEBSOCKET TO TCD
        server_ts_ms = int(time.time() * 1000)
        event_data = {
            'id': event_id,
            'timestamp': datetime.now().strftime('%H:%M:%S'),
            'query_text': sanitized_query,
            'decision': decision,
            'details': 'Finalne zapytanie uzytkownika (MOTO)',
            'category': category,
            'potential_value': potential_value,
            'explanation': f'Analiza po 800ms pauzy - confidence: {confidence_level}',
            'server_sent_at': server_ts_ms
        }

        # Format data for live_feed_update
        feed_data = {
            'timestamp': datetime.now().strftime('%H:%M:%S'),
            'query': sanitized_query,
            'classification': decision,
            'estimatedValue': potential_value,
            'city': visitor_city,
            'country': visitor_country,
            'organization': visitor_org,
            'sessionId': session_id,
            'anonymous': True,
            'source': 'moto'
        }

        # PASSIVE RADAR: UPDATE STATUS IN DB
        if session_id:
            try:
                conn = sqlite3.connect(DATABASE_NAME)
                cursor = conn.cursor()

                cursor.execute('''
                    UPDATE visitor_sessions
                    SET radar_status = 'Pisze',
                        last_activity = CURRENT_TIMESTAMP
                    WHERE session_id = ?
                ''', (session_id,))

                conn.commit()
                conn.close()
                print(f"[PASSIVE RADAR] Status updated to 'Pisze' for session {session_id}")

            except Exception as db_error:
                print(f"[PASSIVE RADAR] Error updating status: {db_error}")

        # SEND TO DASHBOARD (broadcast to both rooms)
        print(f"[WS EMIT][MOTO][REQ:{request_id}] live_feed_update id={event_id} sent_at={server_ts_ms} city={visitor_city}")
        print(f"[SESSION DEBUG] Sending feed_data with sessionId = {session_id}")
        app.logger.info(f"[WS EMIT][MOTO] live_feed_update id={event_id} sent_at={server_ts_ms}")

        socketio.emit('live_feed_update', feed_data, room='client_demo')
        socketio.emit('live_feed_update', feed_data, room='admin_dashboard')

        print(f"[MOTO FINAL ANALYSIS][REQ:{request_id}] Saved to TCD: {sanitized_query} -> {decision} (value: {potential_value})")

        return jsonify({
            'status': 'success',
            'decision': decision,
            'confidence_level': confidence_level,
            'event_id': event_id
        })

    except Exception as e:
        print(f"[ERROR] Final analysis error: {e}")
        app.logger.error(f"Final analysis error: {e}", exc_info=True)
        traceback.print_exc()
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500


# ========================================
# ELEKTRO ANALYZE QUERY (TCD - Doktryna Cierpliwego Nasluchu)
# ========================================

@bot_bp.route('/elektrobot-prototype/api/analyze_query', methods=['POST'])
@limiter.limit("100/minute")
def elektro_analyze_query():
    """
    ELEKTRO VERSION - Doktryna Cierpliwego Nasluchu
    Called after 800ms pause - sends event to TCD
    """
    request_id = str(uuid.uuid4())[:8]

    try:
        data = request.get_json()
        query = data.get('query', '').strip()
        search_type = data.get('type', 'products')

        # Receive geolocation data from frontend (if available)
        visitor_city = data.get('city', 'Unknown')
        visitor_country = data.get('country', 'Unknown')
        visitor_org = data.get('org', 'Unknown')

        # PASSIVE RADAR: Receive session_id
        session_id = data.get('session_id', None)

        print(f"[ELEKTRO FINAL ANALYSIS][REQ:{request_id}] Query: '{query}' | Type: {search_type} | Geo: {visitor_city}, {visitor_country} | Session: {session_id}")

        # RODO: Sanitize query
        sanitized_query = scrub_pii(query)
        if sanitized_query != query:
            print(f"[RODO][REQ:{request_id}] PII scrubbed in elektro_analyze_query")
            app.logger.warning(f"PII scrubbed in elektro_analyze_query")

        if len(sanitized_query) < 2:
            return jsonify({
                'status': 'success',
                'message': 'Query too short'
            })

        # Analysis via ELEKTRO bot
        if ELEKTRO_BOT_AVAILABLE and elektro_bot:
            result = elektro_bot.get_fuzzy_product_matches(
                sanitized_query, None, limit=6, analyze_intent=True
            )

            if isinstance(result, tuple) and len(result) == 4:
                products, confidence_level, suggestion_type, analysis = result
                category = 'elektronika'
            else:
                confidence_level = 'HIGH'
                category = 'elektronika'
        else:
            # Fallback to moto
            confidence_level = 'HIGH'
            category = 'unknown'

        # Map confidence -> decision (ELEKTRO rules)
        decision_mapping = ELEKTRO_DECISION_MAPPING
        decision = decision_mapping.get(confidence_level, 'ZNALEZIONE PRODUKTY')

        # Calculate value for lost opportunities
        potential_value = 0
        if decision == 'UTRACONE OKAZJE':
            potential_value = calculate_lost_value_internal(sanitized_query, source='elektro')

        # SAVE TO DATABASE
        event_id = DatabaseManager.add_event(
            sanitized_query,
            decision,
            'Finalne zapytanie uzytkownika (ELEKTRO)',
            category,
            'elektro',
            potential_value,
            f'Analiza po 800ms pauzy - confidence: {confidence_level}'
        )

        # === PERSISTENT STORAGE (ELEKTRO) ===
        session_id = request.cookies.get('visitor_session_id')
        organization = visitor_org if visitor_org != 'Unknown' else 'Unknown Visitor'
        city = visitor_city if visitor_city != 'Unknown' else 'Unknown'
        country = visitor_country if visitor_country != 'Unknown' else 'Unknown'
        if session_id:
            visitor_ctx = get_visitor_context(session_id)
            if visitor_ctx and visitor_ctx != 'Unknown':
                parts = visitor_ctx.split(', ')
                organization = parts[0] if len(parts) >= 1 else organization
                city = parts[1] if len(parts) >= 2 else city
                country = parts[2] if len(parts) >= 3 else country
        company_data = save_company_data(organization, city, country, sanitized_query, decision)
        if company_data and company_data['engagement_score'] >= 30 and decision == 'ZNALEZIONE PRODUKTY':
            save_hot_lead(organization, sanitized_query, company_data['engagement_score'])
        save_log_entry(decision, organization, sanitized_query)

        # === P3: CALCULATE REWARD SIGNAL & SAVE TO query_intents (ELEKTRO) ===
        best_match_score = 0
        matched_product_id = None
        if isinstance(result, tuple) and len(result) == 4:
            products_list = result[0]
            if products_list and len(products_list) > 0:
                best_match_score = int(products_list[0][1]) if products_list[0][1] else 0
                matched_product_id = str(products_list[0][0].get('id', '')) if isinstance(products_list[0][0], dict) else None

        reward_data = {
            'session_id': session_id or f'elektro_{request_id}',
            'original_query': sanitized_query,
            'confidence_level': confidence_level,
            'was_lost_demand': decision == 'UTRACONE OKAZJE',
            'clicked_alternative': False,
            'query_refinement_count': 0,
            'time_to_first_click': 0.0,
            'session_duration': 0.0,
            'bounce': False,
            'added_to_cart': False,
            'purchased': False,
            'cart_value': 0.0
        }
        reward_score = ldi_reward_calc.calculate_from_dict(reward_data)

        # === SEMANTIC VALIDATION: Check if query is AI_READY ===
        is_valid, validation_reason = semantic_validator.validate(sanitized_query, confidence_level)
        ai_ready = is_valid
        if not is_valid:
            print(f"[SEMANTIC][ELEKTRO] Query rejected: '{sanitized_query}' -> {validation_reason}")

        missing_attrs_e = MissingFeatureExtractor.extract(sanitized_query) if confidence_level == 'NO_MATCH' else []

        try:
            QueryIntentManager.add_query_intent({
                'session_id': session_id or f'elektro_{request_id}',
                'query_text': sanitized_query,
                'confidence_level': confidence_level,
                'suggestion_type': category,
                'best_match_score': best_match_score,
                'clicked_alternative': False,
                'query_refinement_count': 0,
                'time_to_first_click': None,
                'session_duration': None,
                'bounce': False,
                'added_to_cart': False,
                'purchased': False,
                'cart_value': 0.0,
                'reward_score': reward_score,
                'missing_attributes': missing_attrs_e,
                'matched_product_id': matched_product_id,
                'ai_ready': ai_ready
            })
            print(f"[P3][ELEKTRO] QueryIntent saved: reward={reward_score:.4f}, confidence={confidence_level}, missing={missing_attrs_e}, ai_ready={ai_ready}")
            # Zapamiętaj ostatni NO_MATCH session_id dla Gold signal
            if confidence_level == 'NO_MATCH':
                session['last_no_match_qi_session'] = session_id or f'elektro_{request_id}'
                session['last_no_match_query'] = sanitized_query
                session.modified = True
        except Exception as p3_error:
            print(f"[P3][ELEKTRO] Failed to save QueryIntent: {p3_error}")
            app.logger.error(f"[P3] QueryIntent save failed: {p3_error}")

        # SEND VIA WEBSOCKET TO TCD
        event_data = {
            'id': event_id,
            'timestamp': datetime.now().strftime('%H:%M:%S'),
            'query_text': sanitized_query,
            'decision': decision,
            'details': 'Finalne zapytanie uzytkownika (ELEKTRO)',
            'category': category,
            'potential_value': potential_value,
            'explanation': f'Analiza po 800ms pauzy - confidence: {confidence_level}'
        }

        # Format data for live_feed_update
        feed_data = {
            'timestamp': datetime.now().strftime('%H:%M:%S'),
            'query': sanitized_query,
            'classification': decision,
            'estimatedValue': potential_value,
            'city': visitor_city,
            'country': visitor_country,
            'organization': visitor_org,
            'sessionId': session_id,
            'anonymous': True,
            'source': 'elektro'
        }

        # PASSIVE RADAR: UPDATE STATUS IN DB (ELEKTRO)
        if session_id:
            try:
                conn = sqlite3.connect(DATABASE_NAME)
                cursor = conn.cursor()

                cursor.execute('''
                    UPDATE visitor_sessions
                    SET radar_status = 'Pisze',
                        last_activity = CURRENT_TIMESTAMP
                    WHERE session_id = ?
                ''', (session_id,))

                conn.commit()
                conn.close()
                print(f"[PASSIVE RADAR][ELEKTRO] Status updated to 'Pisze' for session {session_id}")

            except Exception as db_error:
                print(f"[PASSIVE RADAR][ELEKTRO] Error updating status: {db_error}")

        # SEND TO DASHBOARD (broadcast to both rooms)
        server_ts_ms = int(time.time() * 1000)
        event_data['server_sent_at'] = server_ts_ms
        print(f"[WS EMIT][ELEKTRO][REQ:{request_id}] live_feed_update id={event_id} sent_at={server_ts_ms} city={visitor_city}")
        app.logger.info(f"[WS EMIT][ELEKTRO] live_feed_update id={event_id} sent_at={server_ts_ms}")

        socketio.emit('live_feed_update', feed_data, room='client_demo')
        socketio.emit('live_feed_update', feed_data, room='admin_dashboard')

        print(f"[ELEKTRO FINAL ANALYSIS][REQ:{request_id}] Saved to TCD: {sanitized_query} -> {decision} (value: {potential_value})")

        return jsonify({
            'status': 'success',
            'decision': decision,
            'confidence_level': confidence_level,
            'event_id': event_id
        })

    except Exception as e:
        print(f"[ERROR] Elektro final analysis error: {e}")
        app.logger.error(f"Elektro final analysis error: {e}", exc_info=True)
        traceback.print_exc()
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500
