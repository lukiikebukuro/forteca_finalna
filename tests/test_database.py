"""
Tests for database managers.
Tests DatabaseManager, QueryIntentManager, and AdminDashboardStateManager.
"""
import pytest
import sqlite3
from datetime import datetime


class TestDatabaseManager:
    """Test suite for DatabaseManager."""

    def test_add_event(self, app_context):
        """DatabaseManager should add events."""
        from database import DatabaseManager

        event_id = DatabaseManager.add_event(
            query_text='test query',
            decision='ZNALEZIONE PRODUKTY',
            details='Test details',
            category='test',
            brand_type='moto',
            potential_value=0,
            explanation='Test event'
        )
        assert event_id > 0, "Event should be created with positive ID"

    def test_get_recent_events(self, app_context):
        """DatabaseManager should retrieve recent events."""
        from database import DatabaseManager

        events = DatabaseManager.get_recent_events(limit=10)
        assert isinstance(events, list)
        # Should return list of dicts
        if events:
            assert 'id' in events[0]
            assert 'query_text' in events[0]
            assert 'decision' in events[0]

    def test_get_today_statistics(self, app_context):
        """DatabaseManager should return today's statistics."""
        from database import DatabaseManager

        stats = DatabaseManager.get_today_statistics()
        assert isinstance(stats, dict)
        assert 'UTRACONE OKAZJE' in stats
        assert 'ZNALEZIONE PRODUKTY' in stats
        assert 'ODFILTROWANE' in stats

    def test_deduplication_window(self, app_context):
        """DatabaseManager should deduplicate events in 5s window."""
        from database import DatabaseManager
        import time

        # Add first event
        id1 = DatabaseManager.add_event(
            'unique_test_query_dedup',
            'ZNALEZIONE PRODUKTY',
            'Test dedup',
            'test',
            'moto',
            100,
            'Dedup test'
        )

        # Try to add same event immediately - should be deduped
        id2 = DatabaseManager.add_event(
            'unique_test_query_dedup',
            'ZNALEZIONE PRODUKTY',
            'Test dedup',
            'test',
            'moto',
            100,
            'Dedup test'
        )

        # Should return same ID (deduped)
        assert id1 == id2, "Duplicate event should return same ID"


class TestQueryIntentManager:
    """Test suite for QueryIntentManager (P3)."""

    def test_init_table(self, app_context):
        """QueryIntentManager should initialize table."""
        from database import QueryIntentManager

        # Should not raise
        QueryIntentManager.init_table()

    def test_add_query_intent(self, app_context):
        """QueryIntentManager should add query intent records."""
        from database import QueryIntentManager

        record_id = QueryIntentManager.add_query_intent({
            'session_id': f'pytest_{datetime.now().strftime("%H%M%S%f")}',
            'query_text': 'test query for pytest',
            'confidence_level': 'HIGH',
            'suggestion_type': 'product',
            'best_match_score': 95,
            'clicked_alternative': True,
            'reward_score': 0.5,
        })
        assert record_id > 0, "Record should be created with positive ID"

    def test_get_training_data(self, app_context):
        """QueryIntentManager should retrieve training data."""
        from database import QueryIntentManager

        data = QueryIntentManager.get_training_data(limit=100)
        assert isinstance(data, list)
        # Each record should have expected structure
        if data:
            record = data[0]
            assert 'query' in record
            assert 'reward_signal' in record
            assert 'score' in record['reward_signal']

    def test_training_data_format_for_export(self, app_context):
        """Training data should be in JSONL-compatible format."""
        from database import QueryIntentManager
        import json

        data = QueryIntentManager.get_training_data(limit=10)
        for record in data:
            # Should be JSON serializable
            json_str = json.dumps(record)
            assert len(json_str) > 0

    def test_session_consolidation(self, app_context):
        """Session consolidation: same session should UPDATE instead of INSERT."""
        from database import QueryIntentManager
        import sqlite3
        from config import DATABASE_NAME

        # Unique test session
        test_session = f'pytest_consolidation_{datetime.now().strftime("%H%M%S%f")}'

        # Simulate typing sequence: first query
        QueryIntentManager.add_query_intent({
            'session_id': test_session,
            'query_text': 'komp',
            'confidence_level': 'MEDIUM',
            'reward_score': 0.1,
            'ai_ready': True
        })

        # Simulate typing sequence: refined query (should UPDATE, not INSERT)
        QueryIntentManager.add_query_intent({
            'session_id': test_session,
            'query_text': 'komputer',
            'confidence_level': 'HIGH',
            'reward_score': 0.2,
            'ai_ready': True
        })

        # Check database
        conn = sqlite3.connect(DATABASE_NAME)
        cursor = conn.cursor()
        cursor.execute(
            "SELECT query_text, query_refinement_count FROM query_intents WHERE session_id = ?",
            (test_session,)
        )
        rows = cursor.fetchall()
        conn.close()

        assert len(rows) == 1, f"Expected 1 record (consolidation), got {len(rows)}"
        assert rows[0][0] == 'komputer', "Final query should be stored"
        assert rows[0][1] >= 1, "Refinement count should be >= 1"

    def test_ai_ready_flag_stored(self, app_context):
        """AI_READY flag should be stored correctly."""
        from database import QueryIntentManager
        import sqlite3
        from config import DATABASE_NAME

        test_session = f'pytest_aiready_{datetime.now().strftime("%H%M%S%f")}'

        QueryIntentManager.add_query_intent({
            'session_id': test_session,
            'query_text': 'valid query',
            'confidence_level': 'HIGH',
            'reward_score': 0.5,
            'ai_ready': True
        })

        conn = sqlite3.connect(DATABASE_NAME)
        cursor = conn.cursor()
        cursor.execute(
            "SELECT ai_ready FROM query_intents WHERE session_id = ?",
            (test_session,)
        )
        row = cursor.fetchone()
        conn.close()

        assert row is not None, "Record should exist"
        assert row[0] == 1, "AI_READY should be 1 (True)"

    def test_ai_ready_filter(self, app_context):
        """get_training_data should filter by ai_ready when requested."""
        from database import QueryIntentManager

        all_data = QueryIntentManager.get_training_data(limit=100, ai_ready_only=False)
        clean_data = QueryIntentManager.get_training_data(limit=100, ai_ready_only=True)

        # Clean data should be subset of all data
        assert len(clean_data) <= len(all_data)

    def test_get_stats(self, app_context):
        """get_stats should return statistics dictionary."""
        from database import QueryIntentManager

        stats = QueryIntentManager.get_stats()

        assert 'total_intents' in stats
        assert 'ai_ready_count' in stats
        assert 'ai_ready_percentage' in stats
        assert 'avg_reward' in stats
        assert 'gold_signals' in stats
        assert 'bounce_rate' in stats


class TestAdminDashboardStateManager:
    """Test suite for AdminDashboardStateManager."""

    def test_init_table(self, app_context):
        """AdminDashboardStateManager should initialize table."""
        from database import AdminDashboardStateManager

        # Should not raise
        AdminDashboardStateManager.init_table()

    def test_save_and_get_state(self, app_context):
        """AdminDashboardStateManager should save and retrieve state."""
        from database import AdminDashboardStateManager

        test_data = {
            'test_key': 'test_value',
            'nested': {'a': 1, 'b': 2},
            'list': [1, 2, 3]
        }

        # Save state
        AdminDashboardStateManager.save_state('pytest_test_state', test_data)

        # Retrieve state
        retrieved = AdminDashboardStateManager.get_state('pytest_test_state')
        assert retrieved == test_data

        # Cleanup
        AdminDashboardStateManager.delete_state('pytest_test_state')

    def test_get_nonexistent_state(self, app_context):
        """Getting nonexistent state should return None."""
        from database import AdminDashboardStateManager

        result = AdminDashboardStateManager.get_state('nonexistent_key_12345')
        assert result is None


class TestPersistentStorage:
    """Test persistent storage functions."""

    def test_save_company_data(self, app_context):
        """save_company_data should create/update company records."""
        from database import save_company_data

        result = save_company_data(
            'Test Company Pytest',
            'Warsaw',
            'Poland',
            'test query',
            'ZNALEZIONE PRODUKTY'
        )
        assert result is not None
        assert 'name' in result
        assert 'engagement_score' in result

    def test_save_log_entry(self, app_context):
        """save_log_entry should create log records."""
        from database import save_log_entry

        result = save_log_entry(
            'ZNALEZIONE PRODUKTY',
            'Test Company',
            'test query'
        )
        assert result is True

    def test_get_log_history(self, app_context):
        """get_log_history should retrieve logs."""
        from database import get_log_history

        logs = get_log_history(limit=10)
        assert isinstance(logs, list)
