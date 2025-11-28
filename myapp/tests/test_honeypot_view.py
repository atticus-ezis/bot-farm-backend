"""
Simplified tests for HoneypotView.
"""

import pytest
from rest_framework import status

from myapp.models import BotEvent, AttackType


@pytest.mark.django_db
class TestHoneypotView:
    """Simplified tests for HoneypotView."""

    def test_log_event_creates_bot_event(
        self, api_client, request_headers, honeypot_url
    ):
        """Test _log_event correctly saves GET request into BotEvent."""
        query_params = {"email": "test@example.com", "message": "Hello"}
        response = api_client.get(honeypot_url, query_params, **request_headers)

        assert response.status_code == status.HTTP_200_OK
        assert BotEvent.objects.count() == 1

        bot_event = BotEvent.objects.first()
        assert bot_event.method == "GET"
        assert bot_event.email == "test@example.com"
        assert bot_event.ip_address == "192.168.1.100"
        assert bot_event.attack_attempted is False

    def test_log_event_creates_attack_when_detected(
        self, api_client, request_headers, honeypot_url
    ):
        """Test _log_event creates AttackType when attacks are detected."""
        malicious_param = "<script>alert('XSS')</script>"
        response = api_client.get(
            honeypot_url, {"username": malicious_param}, **request_headers
        )

        assert response.status_code == status.HTTP_200_OK
        bot_event = BotEvent.objects.first()
        assert bot_event.attack_attempted is True

        attacks = AttackType.objects.filter(bot_event=bot_event)
        assert attacks.count() > 0
        assert attacks.filter(pattern="script_tag").exists()

    def test_post_request_saves_correctly(
        self, api_client, request_headers, honeypot_url, test_correlation_token
    ):
        """Test POST request correctly saves into BotEvent."""
        post_data = {
            "ctoken": str(test_correlation_token),
            "email": "user@example.com",
            "message": "Test message",
        }
        response = api_client.post(honeypot_url, data=post_data, **request_headers)

        assert response.status_code == status.HTTP_200_OK
        bot_event = BotEvent.objects.first()
        assert bot_event.method == "POST"
        assert bot_event.correlation_token == test_correlation_token
        assert bot_event.email == "user@example.com"

    def test_honeypot_view_saves_all_metadata(
        self, api_client, comprehensive_headers, honeypot_url
    ):
        """Test HoneypotView saves all metadata fields correctly."""
        response = api_client.get(honeypot_url, **comprehensive_headers)

        assert response.status_code == status.HTTP_200_OK
        bot_event = BotEvent.objects.first()

        assert bot_event.ip_address == "192.168.1.100"
        assert bot_event.agent == "Mozilla/5.0 (Test Browser)"
        assert bot_event.referer == "example.com"
        assert bot_event.language == "en-US"
        assert "US" in bot_event.geo_location
        assert "New York" in bot_event.geo_location
