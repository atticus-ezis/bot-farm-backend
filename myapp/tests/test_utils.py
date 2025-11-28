"""
Simplified tests for utility functions.
"""

import pytest
from myapp.utils import extract_meta_data, extract_email_from_payload, extract_attacks


@pytest.mark.django_db
class TestUtils:
    """Test utility functions work as expected."""

    def test_extract_meta_data(self):
        """Test extract_meta_data extracts all metadata correctly."""
        meta = {
            "HTTP_USER_AGENT": "Mozilla/5.0",
            "HTTP_REFERER": "https://example.com/page",
            "HTTP_ACCEPT_LANGUAGE": "en-US,en;q=0.9",
            "HTTP_X_FORWARDED_FOR": "192.168.1.100",
            "HTTP_CF_IPCOUNTRY": "US",
            "HTTP_CF_IPCITY": "New York",
            "HTTP_ORIGIN": "https://example.com",
        }

        result = extract_meta_data(meta)

        assert result["ip_address"] == "192.168.1.100"
        assert result["agent"] == "Mozilla/5.0"
        assert result["referer"] == "example.com"
        assert result["lang"] == "en-US"
        assert result["geo_location"] == "US, New York"
        assert result["origin"] == "https://example.com"

    def test_extract_email_from_payload(self):
        """Test extract_email_from_payload extracts email from various fields."""
        # Test email in 'email' field
        payload = {"email": "user@example.com", "message": "Hello"}
        assert extract_email_from_payload(payload) == "user@example.com"

        # Test email in 'message' field
        payload = {"message": "Contact me at admin@test.com for more info"}
        assert extract_email_from_payload(payload) == "admin@test.com"

        # Test email in 'comment' field
        payload = {"comment": "Email: support@company.org"}
        assert extract_email_from_payload(payload) == "support@company.org"

        # Test no email
        payload = {"message": "No email here"}
        assert extract_email_from_payload(payload) is None

    def test_extract_attacks(self):
        """Test extract_attacks detects various attack patterns."""
        # Test XSS detection
        xss_value = "<script>alert('XSS')</script>"
        attacks = extract_attacks(xss_value)
        assert len(attacks) > 0
        assert any(pattern == "script_tag" for pattern, _, _ in attacks)

        # Test SQL injection detection
        sqli_value = "admin' OR '1'='1"
        attacks = extract_attacks(sqli_value)
        assert len(attacks) > 0
        assert any(pattern == "or_1_equals_1" for pattern, _, _ in attacks)

        # Test multiple attacks
        multi_value = "<script>alert(1)</script> AND admin' OR '1'='1"
        attacks = extract_attacks(multi_value)
        assert len(attacks) >= 2

        # Test no attacks
        clean_value = "This is a normal message"
        attacks = extract_attacks(clean_value)
        assert len(attacks) == 0
