"""
Simplified tests for all views - ensure they return data when present.
"""

import pytest
from rest_framework import status

from myapp.models import BotEvent, AttackType
from myapp.tests.factories import BotEventFactory, AttackTypeFactory


@pytest.mark.django_db
class TestViews:
    """Test all views return data when present and important filters work."""

    def test_snapshot_view_returns_data(self, api_client):
        """Test SnapShotView returns data when present."""
        bot_event = BotEventFactory()
        AttackTypeFactory(bot_event=bot_event)

        response = api_client.get("/api/snapshot/")
        assert response.status_code == status.HTTP_200_OK
        assert response.data["total_events"] == 1
        assert response.data["total_injection_attempts"] == 1
        assert response.data["total_ips"] == 1

    def test_bot_event_list_returns_data(self, api_client):
        """Test BotEventViewSet list returns data when present."""
        BotEventFactory()
        BotEventFactory()

        response = api_client.get("/api/bot-events/")
        assert response.status_code == status.HTTP_200_OK
        assert len(response.data["results"]) == 2

    def test_bot_event_detail_returns_data(self, api_client):
        """Test BotEventViewSet retrieve returns data when present."""
        bot_event = BotEventFactory(attack_attempted=True)
        AttackTypeFactory(bot_event=bot_event)

        response = api_client.get(f"/api/bot-events/{bot_event.id}/")
        assert response.status_code == status.HTTP_200_OK
        assert response.data["id"] == str(bot_event.id)
        assert response.data["attack_count"] == 1

    def test_attack_type_list_returns_data(self, api_client):
        """Test AttackTypeViewSet list returns data when present."""
        bot_event = BotEventFactory(attack_attempted=True)
        AttackTypeFactory(bot_event=bot_event)
        AttackTypeFactory(bot_event=bot_event)

        response = api_client.get("/api/attacks/")
        assert response.status_code == status.HTTP_200_OK
        assert len(response.data["results"]) == 2

    def test_attack_type_detail_returns_data(self, api_client):
        """Test AttackTypeViewSet retrieve returns data when present."""
        bot_event = BotEventFactory()
        attack = AttackTypeFactory(bot_event=bot_event)

        response = api_client.get(f"/api/attacks/{attack.id}/")
        assert response.status_code == status.HTTP_200_OK
        assert response.data["id"] == str(attack.id)

    def test_aggregate_path_list_returns_data(self, api_client):
        """Test AggregatePathList returns data when present."""
        BotEventFactory(request_path="/contact/")
        BotEventFactory(request_path="/contact/")

        response = api_client.get("/api/aggregate-paths/")
        assert response.status_code == status.HTTP_200_OK
        assert len(response.data["results"]) > 0

    def test_aggregate_ip_list_returns_data(self, api_client):
        """Test AggregateIPViewSet list returns data when present."""
        BotEventFactory(ip_address="192.168.1.1")
        BotEventFactory(ip_address="192.168.1.1")

        response = api_client.get("/api/aggregate-ips/")
        assert response.status_code == status.HTTP_200_OK
        assert len(response.data["results"]) > 0

    def test_aggregate_ip_detail_returns_data(self, api_client):
        """Test AggregateIPViewSet retrieve returns data when present."""
        ip = "192.168.1.1"
        BotEventFactory(ip_address=ip)
        BotEventFactory(ip_address=ip)

        response = api_client.get(f"/api/aggregate-ips/{ip}/")
        assert response.status_code == status.HTTP_200_OK
        assert response.data["ip_address"] == ip
        assert response.data["traffic_count"] == 2


@pytest.mark.django_db
class TestImportantFilters:
    """Test important filters used by frontend."""

    def test_bot_event_filter_by_attack_categories(self, api_client):
        """Test BotEvent filter by attack_categories (used by frontend)."""
        bot_event1 = BotEventFactory(attack_attempted=True)
        bot_event2 = BotEventFactory(attack_attempted=True)
        AttackTypeFactory(bot_event=bot_event1, category=AttackType.AttackCategory.XSS)
        AttackTypeFactory(bot_event=bot_event2, category=AttackType.AttackCategory.SQLI)

        response = api_client.get("/api/bot-events/", {"attack_categories": "XSS"})
        assert response.status_code == status.HTTP_200_OK
        assert len(response.data["results"]) >= 1

    def test_bot_event_filter_by_method(self, api_client):
        """Test BotEvent filter by method (used by frontend)."""
        BotEventFactory(method=BotEvent.MethodChoice.GET.value)
        BotEventFactory(method=BotEvent.MethodChoice.POST.value)

        response = api_client.get("/api/bot-events/", {"method": "GET"})
        assert response.status_code == status.HTTP_200_OK
        assert all(event["method"] == "GET" for event in response.data["results"])

    def test_bot_event_filter_by_attack_attempted(self, api_client):
        """Test BotEvent filter by attack_attempted (used by frontend)."""
        BotEventFactory(attack_attempted=True)
        BotEventFactory(attack_attempted=False)

        response = api_client.get("/api/bot-events/", {"attack_attempted": "true"})
        assert response.status_code == status.HTTP_200_OK
        assert all(
            event["attack_attempted"] is True for event in response.data["results"]
        )

    def test_bot_event_filter_by_event_category(self, api_client):
        """Test BotEvent filter by event_category (used by frontend)."""
        BotEventFactory.create_scan_event()
        BotEventFactory.create_spam_event()
        bot_event = BotEventFactory(attack_attempted=True)
        AttackTypeFactory(bot_event=bot_event)

        response = api_client.get("/api/bot-events/", {"event_category": "scan"})
        assert response.status_code == status.HTTP_200_OK
        assert all(
            event["event_category"] == "scan" for event in response.data["results"]
        )

    def test_attack_type_filter_by_category(self, api_client):
        """Test AttackType filter by category (used by frontend)."""
        bot_event = BotEventFactory(attack_attempted=True)
        AttackTypeFactory(bot_event=bot_event, category=AttackType.AttackCategory.XSS)
        AttackTypeFactory(bot_event=bot_event, category=AttackType.AttackCategory.SQLI)

        response = api_client.get("/api/attacks/", {"attack_categories": "XSS"})
        assert response.status_code == status.HTTP_200_OK
        assert all(attack["category"] == "XSS" for attack in response.data["results"])
