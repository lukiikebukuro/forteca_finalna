"""
Pytest configuration and fixtures for LDI test suite.
"""
import pytest
import sys
import os

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


@pytest.fixture(scope='session')
def app():
    """Create application for testing."""
    from app import app as flask_app
    flask_app.config['TESTING'] = True
    flask_app.config['WTF_CSRF_ENABLED'] = False
    return flask_app


@pytest.fixture(scope='session')
def client(app):
    """Create test client."""
    return app.test_client()


@pytest.fixture(scope='session')
def moto_bot():
    """MotoBot instance for testing."""
    from config import moto_bot
    return moto_bot


@pytest.fixture(scope='session')
def elektro_bot():
    """ElektroBot instance for testing."""
    from config import elektro_bot
    return elektro_bot


@pytest.fixture(scope='session')
def ldi_reward_calc():
    """LDI Reward Calculator for testing."""
    from config import ldi_reward_calc
    return ldi_reward_calc


@pytest.fixture
def app_context(app):
    """Application context for database operations."""
    with app.app_context():
        yield
