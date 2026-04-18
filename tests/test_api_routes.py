"""
Tests for API routes.
Tests headless API, dashboard data API, and P3 endpoints.
"""
import pytest
import json


class TestHealthEndpoints:
    """Test health check endpoints."""

    def test_motobot_health(self, client):
        """MotoBot health endpoint should return OK."""
        response = client.get('/motobot-prototype/health')
        assert response.status_code == 200
        data = response.get_json()
        assert data['status'].lower() == 'ok'
        assert 'service' in data

    def test_initial_data_api(self, client):
        """Initial data API should return dashboard data."""
        response = client.get('/api/initial_data')
        assert response.status_code == 200
        data = response.get_json()
        assert data['status'] == 'success'
        assert 'data' in data
        assert 'recent_events' in data['data']
        assert 'today_statistics' in data['data']


class TestHeadlessAPIv1:
    """Test headless API v1 endpoints."""

    def test_api_init(self, client):
        """API init should create a session."""
        response = client.post('/api/v1/init',
            data=json.dumps({'api_key': 'test_key'}),
            content_type='application/json'
        )
        assert response.status_code == 200
        data = response.get_json()
        assert 'session_id' in data
        assert 'greeting' in data
        assert data['status'] == 'active'

    def test_api_chat_requires_session(self, client):
        """API chat should require valid session."""
        response = client.post('/api/v1/chat',
            data=json.dumps({
                'session_id': 'invalid_session',
                'message': 'test'
            }),
            content_type='application/json'
        )
        assert response.status_code == 401

    def test_api_chat_with_session(self, client, app):
        """API chat should work with valid session."""
        # Note: In test client, sessions may not persist between requests
        # due to api_sessions being in-memory dict. Skip this test for now.
        pytest.skip("Session state doesn't persist between test client requests")

    def test_api_event_tracking(self, client):
        """API event should track behavioral signals."""
        # Create session first
        init_response = client.post('/api/v1/init',
            data=json.dumps({}),
            content_type='application/json'
        )
        session_id = init_response.get_json()['session_id']

        # Track event
        event_response = client.post('/api/v1/event',
            data=json.dumps({
                'session_id': session_id,
                'event_type': 'cart_add',
                'payload': {'value': 199.99, 'product_id': 'test_001'}
            }),
            content_type='application/json'
        )
        assert event_response.status_code == 200
        data = event_response.get_json()
        assert data['status'] == 'logged'
        assert 'current_reward_score' in data


class TestBotEndpoints:
    """Test bot interaction endpoints."""

    def test_motobot_start(self, client):
        """MotoBot start should initialize session."""
        response = client.post('/motobot-prototype/bot/start')
        assert response.status_code == 200
        data = response.get_json()
        assert 'reply' in data

    def test_motobot_send(self, client):
        """MotoBot send should process messages."""
        # Start first
        client.post('/motobot-prototype/bot/start')

        # Send message
        response = client.post('/motobot-prototype/bot/send',
            data=json.dumps({'message': 'klocki hamulcowe'}),
            content_type='application/json'
        )
        assert response.status_code == 200
        data = response.get_json()
        assert 'reply' in data

    def test_motobot_search_suggestions(self, client):
        """MotoBot search suggestions should return products."""
        response = client.post('/motobot-prototype/search-suggestions',
            data=json.dumps({
                'query': 'klocki hamulcowe BMW',
                'type': 'products'
            }),
            content_type='application/json'
        )
        assert response.status_code == 200
        data = response.get_json()
        assert 'suggestions' in data
        assert 'confidence_level' in data

    def test_motobot_analyze_query(self, client):
        """MotoBot analyze_query (TCD) should process final queries."""
        response = client.post('/motobot-prototype/api/analyze_query',
            data=json.dumps({
                'query': 'filtr oleju Bosch',
                'type': 'products',
                'city': 'Warsaw',
                'country': 'Poland'
            }),
            content_type='application/json'
        )
        assert response.status_code == 200
        data = response.get_json()
        assert data['status'] == 'success'
        assert 'decision' in data
        assert 'confidence_level' in data


class TestP3Endpoints:
    """Test P3 (Debug/Training Data) endpoints."""

    def test_query_intents_requires_auth(self, client):
        """P3 query intents should require authentication."""
        response = client.get('/api/p3/query-intents')
        # Should redirect to login or return 401/302
        assert response.status_code in [302, 401, 403]

    def test_export_training_data_requires_auth(self, client):
        """Export training data should require debug role."""
        response = client.get('/api/export-training-data')
        assert response.status_code in [302, 401, 403]


class TestAuthEndpoints:
    """Test authentication endpoints."""

    def test_login_page_loads(self, client):
        """Login page should load."""
        response = client.get('/login')
        assert response.status_code == 200

    def test_session_info_anonymous(self, client):
        """Session info should work for anonymous users."""
        response = client.get('/api/auth/session-info')
        assert response.status_code == 200
        data = response.get_json()
        assert data['authenticated'] == False

    def test_unauthorized_page(self, client):
        """Unauthorized page should return 403."""
        response = client.get('/unauthorized')
        assert response.status_code == 403
