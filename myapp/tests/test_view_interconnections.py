"""
Tests for view interconnections and filter linking.

These tests verify that filters used to link between views work correctly.
Based on serializer comments indicating relationships between views.
"""

import pytest
from rest_framework import status
from myapp.models import AttackType
from myapp.tests.factories import BotEventFactory, AttackTypeFactory
from myapp.enums import MethodChoice


@pytest.mark.django_db
class TestViewInterconnections:
    """Test filters that link between different views."""

    def test_snapshot_to_attack_list_by_category(self, api_client):
        """Test: Snapshot category -> Attack List filtered by category."""
        # Create attacks with different categories
        bot_event1 = BotEventFactory(attack_attempted=True)
        bot_event2 = BotEventFactory(attack_attempted=True)

        AttackTypeFactory(bot_event=bot_event1, category=AttackType.AttackCategory.XSS)
        AttackTypeFactory(bot_event=bot_event1, category=AttackType.AttackCategory.XSS)
        AttackTypeFactory(bot_event=bot_event2, category=AttackType.AttackCategory.SQLI)

        # Get snapshot
        response = api_client.get("/api/snapshot/")
        assert response.status_code == status.HTTP_200_OK

        categories = response.data["attack_category_snapshot"]
        assert len(categories) > 0

        # Test linking: category -> Attack List
        xss_category = next((c for c in categories if c["category"] == "XSS"), None)
        if xss_category:
            attack_list_response = api_client.get("/api/attacks/", {"category": "XSS"})
            assert attack_list_response.status_code == status.HTTP_200_OK
            assert all(
                attack["category"] == "XSS"
                for attack in attack_list_response.data["results"]
            )

    def test_snapshot_to_ip_analytics_list(self, api_client):
        """Test: Snapshot total_ips -> IP Analytics List (no filter)."""
        BotEventFactory(ip_address="192.168.1.1")
        BotEventFactory(ip_address="192.168.1.2")
        BotEventFactory(ip_address="192.168.1.1")  # Duplicate IP

        response = api_client.get("/api/snapshot/")
        assert response.status_code == status.HTTP_200_OK
        assert response.data["total_ips"] == 2

        # Test linking: total_ips -> IP Analytics List
        ip_list_response = api_client.get("/api/aggregate-ips/")
        assert ip_list_response.status_code == status.HTTP_200_OK
        assert len(ip_list_response.data["results"]) == 2

    def test_path_analytics_to_bot_event_list_by_request_path(self, api_client):
        """Test: Path Analytics request_path -> Bot Event List filtered by request_path."""
        path = "/contact/"
        BotEventFactory(request_path=path)
        BotEventFactory(request_path=path)
        BotEventFactory(request_path="/other/")

        # Get path analytics
        response = api_client.get("/api/aggregate-paths/")
        assert response.status_code == status.HTTP_200_OK

        path_data = next(
            (p for p in response.data["results"] if p["request_path"] == path), None
        )
        assert path_data is not None
        assert path_data["traffic_count"] == 2

        # Test linking: request_path -> Bot Event List
        bot_list_response = api_client.get("/api/bot-events/", {"request_path": path})
        assert bot_list_response.status_code == status.HTTP_200_OK
        assert len(bot_list_response.data["results"]) == 2
        assert all(
            event["request_path"] == path for event in bot_list_response.data["results"]
        )

    def test_path_analytics_to_bot_event_list_with_scan_bot(self, api_client):
        """Test: Path Analytics scan_count -> Bot Event List with scan_bot=true."""
        path = "/contact/"
        # Create scan bots (GET, no attack, no data)
        BotEventFactory(
            request_path=path,
            method=MethodChoice.GET.value,
            attack_attempted=False,
            data=None,
        )
        BotEventFactory(
            request_path=path,
            method=MethodChoice.GET.value,
            attack_attempted=False,
            data={},
        )
        BotEventFactory(
            request_path=path,
            method=MethodChoice.POST.value,
            attack_attempted=False,
        )  # Not a scan bot

        # Get path analytics
        response = api_client.get("/api/aggregate-paths/")
        path_data = next(
            (p for p in response.data["results"] if p["request_path"] == path), None
        )
        assert path_data["scan_count"] == 2

        # Test linking: scan_count -> Bot Event List with scan_bot filter
        bot_list_response = api_client.get(
            "/api/bot-events/", {"request_path": path, "scan_bot": "true"}
        )
        assert bot_list_response.status_code == status.HTTP_200_OK
        assert len(bot_list_response.data["results"]) == 2
        assert all(
            event["method"] == "GET" for event in bot_list_response.data["results"]
        )

    def test_path_analytics_to_bot_event_list_with_spam_bot(self, api_client):
        """Test: Path Analytics spam_count -> Bot Event List with spam_bot=true."""
        path = "/contact/"
        # Create spam bots (POST, no attack, has data)
        BotEventFactory(
            request_path=path,
            method=MethodChoice.POST.value,
            attack_attempted=False,
            data={"email": "spam@example.com"},
        )
        BotEventFactory(
            request_path=path,
            method=MethodChoice.POST.value,
            attack_attempted=False,
            data={"message": "spam"},
        )
        BotEventFactory(
            request_path=path,
            method=MethodChoice.GET.value,
            attack_attempted=False,
        )  # Not a spam bot

        # Get path analytics
        response = api_client.get("/api/aggregate-paths/")
        path_data = next(
            (p for p in response.data["results"] if p["request_path"] == path), None
        )
        assert path_data["spam_count"] == 2

        # Test linking: spam_count -> Bot Event List with spam_bot filter
        bot_list_response = api_client.get(
            "/api/bot-events/", {"request_path": path, "spam_bot": "true"}
        )
        assert bot_list_response.status_code == status.HTTP_200_OK
        assert len(bot_list_response.data["results"]) == 2
        assert all(
            event["method"] == "POST" for event in bot_list_response.data["results"]
        )

    def test_path_analytics_to_attack_list_by_request_path(self, api_client):
        """Test: Path Analytics attack_count -> Attack List filtered by request_path."""
        path = "/contact/"
        bot_event = BotEventFactory(request_path=path, attack_attempted=True)
        AttackTypeFactory(bot_event=bot_event)
        AttackTypeFactory(bot_event=bot_event)

        # Get path analytics
        response = api_client.get("/api/aggregate-paths/")
        path_data = next(
            (p for p in response.data["results"] if p["request_path"] == path), None
        )
        assert path_data["attack_count"] == 2  # One bot event with 2 attacks

        # Test linking: attack_count -> Attack List by request_path
        attack_list_response = api_client.get("/api/attacks/", {"request_path": path})
        assert attack_list_response.status_code == status.HTTP_200_OK
        assert len(attack_list_response.data["results"]) == 2
        assert all(
            attack["request_path"] == path
            for attack in attack_list_response.data["results"]
        )

    def test_path_analytics_to_attack_list_by_category(self, api_client):
        """Test: Path Analytics most_popular_attack -> Attack List filtered by category."""
        path = "/contact/"
        bot_event = BotEventFactory(request_path=path, attack_attempted=True)
        AttackTypeFactory(bot_event=bot_event, category=AttackType.AttackCategory.XSS)
        AttackTypeFactory(bot_event=bot_event, category=AttackType.AttackCategory.XSS)
        AttackTypeFactory(bot_event=bot_event, category=AttackType.AttackCategory.SQLI)

        # Get path analytics
        response = api_client.get("/api/aggregate-paths/")
        path_data = next(
            (p for p in response.data["results"] if p["request_path"] == path), None
        )
        assert path_data["most_popular_attack"] == "XSS"

        # Test linking: most_popular_attack -> Attack List by category
        attack_list_response = api_client.get("/api/attacks/", {"category": "XSS"})
        assert attack_list_response.status_code == status.HTTP_200_OK
        assert all(
            attack["category"] == "XSS"
            for attack in attack_list_response.data["results"]
        )

    def test_ip_analytics_list_to_detail_by_ip_address(self, api_client):
        """Test: IP Analytics List ip_address -> IP Analytics Detail (lookup by ip_address)."""
        ip = "192.168.1.1"
        BotEventFactory(ip_address=ip)
        BotEventFactory(ip_address=ip)

        # Get IP list
        response = api_client.get("/api/aggregate-ips/")
        assert response.status_code == status.HTTP_200_OK
        ip_data = next(
            (i for i in response.data["results"] if i["ip_address"] == ip), None
        )
        assert ip_data is not None

        # Test linking: ip_address -> IP Analytics Detail
        detail_response = api_client.get(f"/api/aggregate-ips/{ip}/")
        assert detail_response.status_code == status.HTTP_200_OK
        assert detail_response.data["ip_address"] == ip
        assert detail_response.data["traffic_count"] == 2

    def test_ip_analytics_list_to_bot_event_list_by_ip_address(self, api_client):
        """Test: IP Analytics List traffic_count -> Bot Event List filtered by ip_address."""
        ip = "192.168.1.1"
        BotEventFactory(ip_address=ip)
        BotEventFactory(ip_address=ip)
        BotEventFactory(ip_address="192.168.1.2")

        # Get IP list
        response = api_client.get("/api/aggregate-ips/")
        ip_data = next(
            (i for i in response.data["results"] if i["ip_address"] == ip), None
        )
        assert ip_data["traffic_count"] == 2

        # Test linking: traffic_count -> Bot Event List by ip_address
        bot_list_response = api_client.get("/api/bot-events/", {"ip_address": ip})
        assert bot_list_response.status_code == status.HTTP_200_OK
        assert len(bot_list_response.data["results"]) == 2
        assert all(
            event["ip_address"] == ip for event in bot_list_response.data["results"]
        )

    def test_ip_analytics_list_to_attack_list_by_ip_address(self, api_client):
        """Test: IP Analytics List attack_count -> Attack List filtered by ip_address."""
        ip = "192.168.1.1"
        bot_event = BotEventFactory(ip_address=ip, attack_attempted=True)
        AttackTypeFactory(bot_event=bot_event)
        AttackTypeFactory(bot_event=bot_event)

        # Get IP list
        response = api_client.get("/api/aggregate-ips/")
        ip_data = next(
            (i for i in response.data["results"] if i["ip_address"] == ip), None
        )
        assert ip_data["attack_count"] == 2  # One bot event with 2 attacks

        # Test linking: attack_count -> Attack List by ip_address
        attack_list_response = api_client.get("/api/attacks/", {"ip_address": ip})
        assert attack_list_response.status_code == status.HTTP_200_OK
        assert len(attack_list_response.data["results"]) == 2

    def test_ip_analytics_list_to_attack_list_by_category(self, api_client):
        """Test: IP Analytics List attack_categories -> Attack List filtered by category."""
        ip = "192.168.1.1"
        bot_event = BotEventFactory(ip_address=ip, attack_attempted=True)
        AttackTypeFactory(bot_event=bot_event, category=AttackType.AttackCategory.XSS)
        AttackTypeFactory(bot_event=bot_event, category=AttackType.AttackCategory.SQLI)

        # Get IP list
        response = api_client.get("/api/aggregate-ips/")
        ip_data = next(
            (i for i in response.data["results"] if i["ip_address"] == ip), None
        )
        assert "XSS" in ip_data["attack_categories"]
        assert "SQLI" in ip_data["attack_categories"]

        # Test linking: attack_categories -> Attack List by category
        attack_list_response = api_client.get("/api/attacks/", {"category": "XSS"})
        assert attack_list_response.status_code == status.HTTP_200_OK
        assert all(
            attack["category"] == "XSS"
            for attack in attack_list_response.data["results"]
        )

    def test_bot_event_list_to_detail_by_id(self, api_client):
        """Test: Bot Event List id -> Bot Event Detail (lookup by id)."""
        bot_event = BotEventFactory()
        AttackTypeFactory(bot_event=bot_event)

        # Get bot event list
        response = api_client.get("/api/bot-events/")
        assert response.status_code == status.HTTP_200_OK
        event_data = next(
            (e for e in response.data["results"] if e["id"] == str(bot_event.id)), None
        )
        assert event_data is not None

        # Test linking: id -> Bot Event Detail
        detail_response = api_client.get(f"/api/bot-events/{bot_event.id}/")
        assert detail_response.status_code == status.HTTP_200_OK
        assert detail_response.data["id"] == str(bot_event.id)
        assert detail_response.data["attack_count"] == 1

    def test_bot_event_list_to_ip_analytics_detail_by_ip_address(self, api_client):
        """Test: Bot Event List ip_address -> IP Analytics Detail (lookup by ip_address)."""
        ip = "192.168.1.1"
        bot_event = BotEventFactory(ip_address=ip)

        # Get bot event list
        response = api_client.get("/api/bot-events/")
        event_data = next(
            (
                e
                for e in response.data["results"]
                if e["ip_address"] == bot_event.ip_address
            ),
            None,
        )
        assert event_data is not None

        # Test linking: ip_address -> IP Analytics Detail
        detail_response = api_client.get(f"/api/aggregate-ips/{bot_event.ip_address}/")
        assert detail_response.status_code == status.HTTP_200_OK
        assert detail_response.data["ip_address"] == bot_event.ip_address

    def test_bot_event_list_to_attack_list_by_bot_event_id(self, api_client):
        """Test: Bot Event List attack_count -> Attack List filtered by bot_event_id."""
        bot_event = BotEventFactory(attack_attempted=True)
        AttackTypeFactory(bot_event=bot_event)
        AttackTypeFactory(bot_event=bot_event)

        # Get bot event list
        response = api_client.get("/api/bot-events/")
        event_data = next(
            (e for e in response.data["results"] if e["id"] == str(bot_event.id)), None
        )
        assert event_data["attack_count"] == 2

        # Test linking: attack_count -> Attack List by bot_event_id
        attack_list_response = api_client.get(
            "/api/attacks/", {"bot_event_id": str(bot_event.id)}
        )
        assert attack_list_response.status_code == status.HTTP_200_OK
        assert len(attack_list_response.data["results"]) == 2
        assert all(
            attack["bot_event_id"] == str(bot_event.id)
            for attack in attack_list_response.data["results"]
        )

    def test_bot_event_list_to_attack_list_by_category(self, api_client):
        """Test: Bot Event List attack_categories -> Attack List filtered by category."""
        bot_event = BotEventFactory(attack_attempted=True)
        AttackTypeFactory(bot_event=bot_event, category=AttackType.AttackCategory.XSS)
        AttackTypeFactory(bot_event=bot_event, category=AttackType.AttackCategory.SQLI)

        # Get bot event list
        response = api_client.get("/api/bot-events/")
        event_data = next(
            (e for e in response.data["results"] if e["id"] == str(bot_event.id)), None
        )
        assert "XSS" in event_data["attack_categories"]
        assert "SQLI" in event_data["attack_categories"]

        # Test linking: attack_categories -> Attack List by category
        attack_list_response = api_client.get("/api/attacks/", {"category": "XSS"})
        assert attack_list_response.status_code == status.HTTP_200_OK
        assert all(
            attack["category"] == "XSS"
            for attack in attack_list_response.data["results"]
        )

    def test_attack_list_to_bot_event_detail_by_bot_event_id(self, api_client):
        """Test: Attack List bot_event_id -> Bot Event Detail (lookup by bot_event_id)."""
        bot_event = BotEventFactory()
        attack = AttackTypeFactory(bot_event=bot_event)

        # Get attack list
        response = api_client.get("/api/attacks/")
        assert response.status_code == status.HTTP_200_OK
        attack_data = next(
            (a for a in response.data["results"] if a["id"] == str(attack.id)), None
        )
        assert attack_data is not None
        assert attack_data["bot_event_id"] == str(bot_event.id)

        # Test linking: bot_event_id -> Bot Event Detail
        detail_response = api_client.get(f"/api/bot-events/{bot_event.id}/")
        assert detail_response.status_code == status.HTTP_200_OK
        assert detail_response.data["id"] == str(bot_event.id)

    def test_attack_list_to_bot_event_list_by_request_path(self, api_client):
        """Test: Attack List request_path -> Bot Event List filtered by request_path."""
        path = "/contact/"
        bot_event = BotEventFactory(request_path=path)
        AttackTypeFactory(bot_event=bot_event)

        # Get attack list
        response = api_client.get("/api/attacks/")
        attack_data = next(
            (a for a in response.data["results"] if a["request_path"] == path), None
        )
        assert attack_data is not None

        # Test linking: request_path -> Bot Event List
        bot_list_response = api_client.get("/api/bot-events/", {"request_path": path})
        assert bot_list_response.status_code == status.HTTP_200_OK
        assert all(
            event["request_path"] == path for event in bot_list_response.data["results"]
        )

    def test_attack_list_to_ip_analytics_detail_by_ip_address(self, api_client):
        """Test: Attack List ip_address -> IP Analytics Detail (lookup by ip_address)."""
        ip = "192.168.1.1"
        bot_event = BotEventFactory(ip_address=ip)
        AttackTypeFactory(bot_event=bot_event)

        # Get attack list
        response = api_client.get("/api/attacks/")
        attack_data = next(
            (a for a in response.data["results"] if a["ip_address"] == ip), None
        )
        assert attack_data is not None

        # Test linking: ip_address -> IP Analytics Detail
        detail_response = api_client.get(f"/api/aggregate-ips/{ip}/")
        assert detail_response.status_code == status.HTTP_200_OK
        assert detail_response.data["ip_address"] == ip

    def test_ip_analytics_sort_by_email_count_ascending(self, api_client):
        """Test: IP Analytics List sorted by email_count ascending."""
        # Create IPs with different email counts
        ip1 = "192.168.1.1"
        ip2 = "192.168.1.2"
        ip3 = "192.168.1.3"

        # IP1: 3 emails
        BotEventFactory(ip_address=ip1, email="email1@example.com")
        BotEventFactory(ip_address=ip1, email="email2@example.com")
        BotEventFactory(ip_address=ip1, email="email3@example.com")

        # IP2: 1 email
        BotEventFactory(ip_address=ip2, email="email4@example.com")

        # IP3: 2 emails
        BotEventFactory(ip_address=ip3, email="email5@example.com")
        BotEventFactory(ip_address=ip3, email="email6@example.com")

        # Get sorted list
        response = api_client.get("/api/aggregate-ips/", {"ordering": "email_count"})
        assert response.status_code == status.HTTP_200_OK

        results = response.data["results"]
        email_counts = [
            ip["email_count"] for ip in results if ip["ip_address"] in [ip1, ip2, ip3]
        ]

        # Verify ascending order
        assert email_counts == sorted(email_counts)
        assert email_counts[0] == 1  # IP2
        assert email_counts[1] == 2  # IP3
        assert email_counts[2] == 3  # IP1

    def test_ip_analytics_sort_by_email_count_descending(self, api_client):
        """Test: IP Analytics List sorted by email_count descending."""
        # Create IPs with different email counts
        ip1 = "192.168.1.1"
        ip2 = "192.168.1.2"
        ip3 = "192.168.1.3"

        # IP1: 3 emails
        BotEventFactory(ip_address=ip1, email="email1@example.com")
        BotEventFactory(ip_address=ip1, email="email2@example.com")
        BotEventFactory(ip_address=ip1, email="email3@example.com")

        # IP2: 1 email
        BotEventFactory(ip_address=ip2, email="email4@example.com")

        # IP3: 2 emails
        BotEventFactory(ip_address=ip3, email="email5@example.com")
        BotEventFactory(ip_address=ip3, email="email6@example.com")

        # Get sorted list
        response = api_client.get("/api/aggregate-ips/", {"ordering": "-email_count"})
        assert response.status_code == status.HTTP_200_OK

        results = response.data["results"]
        email_counts = [
            ip["email_count"] for ip in results if ip["ip_address"] in [ip1, ip2, ip3]
        ]

        # Verify descending order
        assert email_counts == sorted(email_counts, reverse=True)
        assert email_counts[0] == 3  # IP1
        assert email_counts[1] == 2  # IP3
        assert email_counts[2] == 1  # IP2

    def test_ip_analytics_search_by_email(self, api_client):
        """Test: IP Analytics List search by email address."""
        # Create IPs with different emails
        ip1 = "192.168.1.1"
        ip2 = "192.168.1.2"
        ip3 = "192.168.1.3"

        # IP1 uses "test@example.com"
        BotEventFactory(ip_address=ip1, email="test@example.com")
        BotEventFactory(ip_address=ip1, email="other@example.com")

        # IP2 uses "test@example.com" as well
        BotEventFactory(ip_address=ip2, email="test@example.com")

        # IP3 uses different email
        BotEventFactory(ip_address=ip3, email="different@example.com")

        # Search for "test@example.com"
        response = api_client.get("/api/aggregate-ips/", {"search": "test@example.com"})
        assert response.status_code == status.HTTP_200_OK

        results = response.data["results"]
        found_ips = [ip["ip_address"] for ip in results]

        # Should find IP1 and IP2
        assert ip1 in found_ips
        assert ip2 in found_ips
        assert ip3 not in found_ips

        # Verify email_count is correct (list serializer only includes email_count, not email list)
        for ip_data in results:
            if ip_data["ip_address"] == ip1:
                assert ip_data["email_count"] == 2  # IP1 has 2 distinct emails
            elif ip_data["ip_address"] == ip2:
                assert ip_data["email_count"] == 1  # IP2 has 1 email

        # Verify emails_used contains the searched email in detail view
        detail1 = api_client.get(f"/api/aggregate-ips/{ip1}/")
        assert detail1.status_code == status.HTTP_200_OK
        assert "test@example.com" in detail1.data["email"]

        detail2 = api_client.get(f"/api/aggregate-ips/{ip2}/")
        assert detail2.status_code == status.HTTP_200_OK
        assert "test@example.com" in detail2.data["email"]

    def test_ip_analytics_search_by_email_partial(self, api_client):
        """Test: IP Analytics List search by partial email address."""
        ip1 = "192.168.1.1"
        ip2 = "192.168.1.2"

        # IP1 uses "test@example.com"
        BotEventFactory(ip_address=ip1, email="test@example.com")

        # IP2 uses "testing@example.com"
        BotEventFactory(ip_address=ip2, email="testing@example.com")

        # Search for partial "test"
        response = api_client.get("/api/aggregate-ips/", {"search": "test"})
        assert response.status_code == status.HTTP_200_OK

        results = response.data["results"]
        found_ips = [ip["ip_address"] for ip in results]

        # Should find both IP1 and IP2 (partial match)
        assert ip1 in found_ips
        assert ip2 in found_ips

    def test_ip_analytics_search_by_ip_address(self, api_client):
        """Test: IP Analytics List search by IP address."""
        ip1 = "192.168.1.1"
        ip2 = "192.168.1.2"
        ip3 = "10.0.0.1"

        BotEventFactory(ip_address=ip1)
        BotEventFactory(ip_address=ip2)
        BotEventFactory(ip_address=ip3)

        # Search for "192.168"
        response = api_client.get("/api/aggregate-ips/", {"search": "192.168"})
        assert response.status_code == status.HTTP_200_OK

        results = response.data["results"]
        found_ips = [ip["ip_address"] for ip in results]

        # Should find IP1 and IP2 (partial match)
        assert ip1 in found_ips
        assert ip2 in found_ips
        assert ip3 not in found_ips

    def test_ip_analytics_search_by_referer(self, api_client):
        """Test: IP Analytics List search by referer."""
        ip1 = "192.168.1.1"
        ip2 = "192.168.1.2"
        ip3 = "10.0.0.1"  # Use different IP range to avoid partial matches

        # Set referer directly (domain only, as stored in DB)
        # Use a unique search term to avoid false matches
        unique_term = "testreferer123.com"
        BotEventFactory(ip_address=ip1, referer=unique_term)
        BotEventFactory(ip_address=ip2, referer=unique_term)
        BotEventFactory(ip_address=ip3, referer="completelydifferent.com")

        # Search for the unique term
        response = api_client.get("/api/aggregate-ips/", {"search": unique_term})
        assert response.status_code == status.HTTP_200_OK

        results = response.data["results"]
        found_ips = [ip["ip_address"] for ip in results]

        # Should find IP1 and IP2
        assert ip1 in found_ips
        assert ip2 in found_ips
        assert ip3 not in found_ips

        # Verify referer in detail view (list serializer doesn't include referer)
        detail1 = api_client.get(f"/api/aggregate-ips/{ip1}/")
        assert detail1.status_code == status.HTTP_200_OK
        assert detail1.data["referer"] == unique_term

    def test_ip_analytics_search_combines_ip_referer_email(self, api_client):
        """Test: IP Analytics List search combines IP, referer, and email with OR logic."""
        ip1 = "192.168.1.1"
        ip2 = "192.168.1.2"
        ip3 = "192.168.1.3"
        ip4 = "10.0.0.1"

        # IP1: matches by email
        BotEventFactory(
            ip_address=ip1, email="test@example.com", referer="https://other.com"
        )

        # IP2: matches by referer
        BotEventFactory(
            ip_address=ip2,
            email="different@example.com",
            referer="https://test.com/page",
        )

        # IP3: matches by IP address (contains "192.168.1.3" but search for "test" won't match)
        # Let's make IP3 match by having "test" in a different field
        BotEventFactory(
            ip_address=ip3, email="other@example.com", referer="https://other.com"
        )

        # IP4: no match
        BotEventFactory(
            ip_address=ip4, email="other@example.com", referer="https://other.com"
        )

        # Search for "test" - should match IP1 (email), IP2 (referer)
        response = api_client.get("/api/aggregate-ips/", {"search": "test"})
        assert response.status_code == status.HTTP_200_OK

        results = response.data["results"]
        found_ips = [ip["ip_address"] for ip in results]

        # Should find IP1 (email match) and IP2 (referer match)
        assert ip1 in found_ips
        assert ip2 in found_ips
        # IP3 and IP4 should not match
        assert ip3 not in found_ips
        assert ip4 not in found_ips

    def test_ip_analytics_multiple_emails_per_ip(self, api_client):
        """Test: IP Analytics correctly aggregates multiple emails per IP."""
        ip = "192.168.1.1"

        # Create multiple events with different emails for the same IP
        BotEventFactory(ip_address=ip, email="email1@example.com")
        BotEventFactory(ip_address=ip, email="email2@example.com")
        BotEventFactory(ip_address=ip, email="email3@example.com")
        BotEventFactory(ip_address=ip, email="email1@example.com")  # Duplicate email

        # Get IP detail
        response = api_client.get(f"/api/aggregate-ips/{ip}/")
        assert response.status_code == status.HTTP_200_OK

        data = response.data
        assert data["ip_address"] == ip
        # email_count counts all email occurrences (not distinct), so 4 events = 4
        assert data["email_count"] == 4
        # emails_used (serialized as "email") contains distinct emails
        assert (
            len(data["email"]) == 3
        )  # Serializer exposes as "email" (sourced from "emails_used")
        assert "email1@example.com" in data["email"]
        assert "email2@example.com" in data["email"]
        assert "email3@example.com" in data["email"]

    def test_ip_analytics_search_and_sort_combined(self, api_client):
        """Test: IP Analytics List search combined with email_count sorting."""
        ip1 = "192.168.1.1"
        ip2 = "192.168.1.2"
        ip3 = "192.168.1.3"

        # IP1: 2 emails, contains "test"
        BotEventFactory(ip_address=ip1, email="test@example.com")
        BotEventFactory(ip_address=ip1, email="other@example.com")

        # IP2: 1 email, contains "test"
        BotEventFactory(ip_address=ip2, email="test@example.com")

        # IP3: 3 emails, doesn't contain "test"
        BotEventFactory(ip_address=ip3, email="different@example.com")
        BotEventFactory(ip_address=ip3, email="another@example.com")
        BotEventFactory(ip_address=ip3, email="third@example.com")

        # Search for "test" and sort by email_count descending
        response = api_client.get(
            "/api/aggregate-ips/", {"search": "test", "ordering": "-email_count"}
        )
        assert response.status_code == status.HTTP_200_OK

        results = response.data["results"]
        found_ips = [ip["ip_address"] for ip in results]

        # Should only find IP1 and IP2 (both contain "test")
        assert ip1 in found_ips
        assert ip2 in found_ips
        assert ip3 not in found_ips

        # Verify sorting: IP1 (2 emails) should come before IP2 (1 email)
        ip1_index = found_ips.index(ip1)
        ip2_index = found_ips.index(ip2)
        assert ip1_index < ip2_index

        # Verify email counts
        ip1_data = next(ip for ip in results if ip["ip_address"] == ip1)
        ip2_data = next(ip for ip in results if ip["ip_address"] == ip2)
        assert ip1_data["email_count"] == 2
        assert ip2_data["email_count"] == 1
