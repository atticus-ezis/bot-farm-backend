import pytest
from uuid import UUID

from django.urls import reverse
from rest_framework.test import APIClient
from django.core.cache import cache

# Enable database access for all tests in this directory
pytestmark = pytest.mark.django_db(transaction=True)


@pytest.fixture(autouse=True)
def enable_db_access_for_all_tests(db):
    """
    Ensure database access is enabled for all tests.
    The db fixture ensures each test runs in a transaction that's rolled back.
    """
    pass


@pytest.fixture
def api_client():
    return APIClient()


@pytest.fixture(autouse=True)
def clear_cache():
    """Clear cache before each test to ensure test isolation."""
    cache.clear()
    yield
    cache.clear()


# Test data fixtures for contact-bot and other API tests
@pytest.fixture
def no_xss_submission_data():
    """Fixture providing valid submission data."""
    return {
        "name": "John Doe",
        "email": "john@example.com",
        "message": "Hello, this is a test message",
    }


@pytest.fixture
def xss_submission_data():
    """Fixture providing valid submission data."""
    return {
        "name": "John Doe",
        "email": "john@example.com",
        "message": "I hope this message doesn't contain any XSS <script>alert('XSS')</script> attacks",
    }


@pytest.fixture
def minimal_submission_data():
    """Fixture providing minimal required submission data (only message)."""
    return {
        "message": "Minimal test message",
    }


@pytest.fixture
def request_headers():
    """Fixture providing common HTTP headers for testing."""
    return {
        "HTTP_USER_AGENT": "Mozilla/5.0 (Test Browser)",
        "HTTP_REFERER": "https://example.com/contact",
        "HTTP_ACCEPT_LANGUAGE": "en-US,en;q=0.9",
        "REMOTE_ADDR": "192.168.1.100",
    }


@pytest.fixture
def x_forwarded_for_headers():
    """Fixture providing headers with X-Forwarded-For (proxy scenario)."""
    return {
        "HTTP_X_FORWARDED_FOR": "203.0.113.1, 198.51.100.2",
        "REMOTE_ADDR": "10.0.0.1",
    }


@pytest.fixture
def honeypot_url():
    """Fixture providing the honeypot endpoint URL."""
    return reverse("honeypot")


@pytest.fixture
def test_correlation_token():
    """Fixture providing a test correlation token UUID."""
    return UUID("12345678-1234-5678-1234-567812345678")


@pytest.fixture
def sample_post_data(test_correlation_token):
    """Fixture providing sample POST data for honeypot tests."""
    return {
        "ctoken": str(test_correlation_token),
        "username": "testuser",
        "message": "Hello world",
        "comment": "Test comment",
    }


@pytest.fixture
def clean_post_data(test_correlation_token):
    """Fixture providing clean POST data without XSS."""
    return {
        "ctoken": str(test_correlation_token),
        "username": "normal_user",
        "message": "This is a normal message with no malicious content",
        "comment": "Regular comment here",
        "content": "Some content text",
    }
