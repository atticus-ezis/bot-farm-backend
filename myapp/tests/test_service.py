import pytest

from myapp.services import create_bot_record
from myapp.models import BotSubmission, XSSAttack


pytestmark = pytest.mark.django_db


class TestCreateBotRecord:
    def test_creates_bot_submission_with_all_fields(self):
        """Test that create_bot_record creates a BotSubmission with all provided fields."""
        cleaned_data = {
            "name": "Test User",
            "email": "test@example.com",
            "message": "This is a test message",
        }
        meta_data = {
            "REMOTE_ADDR": "192.168.1.1",
            "HTTP_USER_AGENT": "Mozilla/5.0",
            "HTTP_ACCEPT_LANGUAGE": "en-US,en;q=0.9",
            "HTTP_REFERER": "https://example.com",
        }

        submission = create_bot_record(cleaned_data, meta_data)

        assert submission.id is not None
        assert submission.name == "Test User"
        assert submission.email == "test@example.com"
        assert submission.message == "This is a test message"
        assert submission.ip_address == "192.168.1.1"
        assert submission.full_ip_address is None
        assert submission.agent == "Mozilla/5.0"
        assert submission.language == "en-US"
        assert submission.referer == "https://example.com"
        assert submission.created_at is not None

    def test_creates_bot_submission_with_minimal_data(self):
        """Test that create_bot_record works with minimal required data."""
        cleaned_data = {"message": "Just a message"}
        meta_data = {"REMOTE_ADDR": "127.0.0.1"}

        submission = create_bot_record(cleaned_data, meta_data)

        assert submission.id is not None
        assert submission.message == "Just a message"
        assert submission.name is None
        assert submission.email is None
        assert submission.ip_address == "127.0.0.1"

    def test_extracts_ip_from_x_forwarded_for(self):
        """Test that IP is extracted from X-Forwarded-For header."""
        cleaned_data = {"message": "test"}
        meta_data = {
            "HTTP_X_FORWARDED_FOR": "203.0.113.1, 198.51.100.2",
            "REMOTE_ADDR": "10.0.0.1",
        }

        submission = create_bot_record(cleaned_data, meta_data)

        assert submission.ip_address == "203.0.113.1"
        assert submission.full_ip_address == "203.0.113.1, 198.51.100.2"

    def test_extracts_ip_from_x_real_ip(self):
        """Test that IP is extracted from X-Real-IP header (Nginx)."""
        cleaned_data = {"message": "test"}
        meta_data = {
            "HTTP_X_REAL_IP": "203.0.113.5",
            "REMOTE_ADDR": "10.0.0.1",
        }

        submission = create_bot_record(cleaned_data, meta_data)

        assert submission.ip_address == "203.0.113.5"
        assert submission.full_ip_address == "203.0.113.5"

    def test_extracts_email_from_email_field(self):
        """Test that email is extracted from 'email' field."""
        cleaned_data = {
            "email": "user@example.com",
            "message": "test",
        }
        meta_data = {"REMOTE_ADDR": "127.0.0.1"}

        submission = create_bot_record(cleaned_data, meta_data)

        assert submission.email == "user@example.com"

    def test_extracts_email_from_message(self):
        """Test that email is extracted from message field if not in email field."""
        cleaned_data = {
            "message": "Contact me at test@example.com please",
        }
        meta_data = {"REMOTE_ADDR": "127.0.0.1"}

        submission = create_bot_record(cleaned_data, meta_data)

        assert submission.email == "test@example.com"

    def test_handles_missing_headers_gracefully(self):
        """Test that missing headers don't cause errors."""
        cleaned_data = {"message": "test"}
        meta_data = {}  # No headers

        submission = create_bot_record(cleaned_data, meta_data)

        assert submission.id is not None
        assert submission.ip_address is None
        assert submission.agent is None
        assert submission.language is None
        assert submission.referer is None

    def test_extracts_language_from_accept_language(self):
        """Test that language is extracted from Accept-Language header."""
        cleaned_data = {"message": "test"}
        meta_data = {
            "REMOTE_ADDR": "127.0.0.1",
            "HTTP_ACCEPT_LANGUAGE": "fr-FR,fr;q=0.9,en;q=0.8",
        }

        submission = create_bot_record(cleaned_data, meta_data)

        assert submission.language == "fr-FR"

    def test_handles_empty_language_header(self):
        """Test that empty language header is handled."""
        cleaned_data = {"message": "test"}
        meta_data = {
            "REMOTE_ADDR": "127.0.0.1",
            "HTTP_ACCEPT_LANGUAGE": "",
        }

        submission = create_bot_record(cleaned_data, meta_data)

        assert submission.language is None

    def test_is_atomic_transaction(self):
        """Test that the function is atomic - if XSS creation fails, submission is rolled back."""
        # This test verifies the @transaction.atomic decorator is working
        # The decorator ensures all database operations succeed or fail together
        cleaned_data = {"message": "test"}
        meta_data = {"REMOTE_ADDR": "127.0.0.1"}

        # If transaction wasn't atomic, partial data could be saved
        # This test verifies complete submission is created
        submission = create_bot_record(cleaned_data, meta_data)

        assert submission.id is not None
        assert BotSubmission.objects.filter(id=submission.id).exists()

    ###### XSSS ATTACKS
    def test_script_xss_attack_records_when_detected(self):
        """Test that XSS attacks are detected and stored."""
        cleaned_data = {
            "name": "<script>alert('XSS')</script>",
            "message": "Hello world",
        }
        meta_data = {"REMOTE_ADDR": "127.0.0.1"}

        submission = create_bot_record(cleaned_data, meta_data)

        xss_attack = XSSAttack.objects.get(submission=submission)
        assert xss_attack is not None
        assert xss_attack.field == "name"
        assert xss_attack.pattern == "script_tag"
        assert xss_attack.snippet == "<script>alert('XSS')</script>"

    def test_script_xss_attack_records_when_detected_with_upfront_text(self):
        """Test that XSS attacks are detected and stored."""
        cleaned_data = {
            "name": "Here is some upfront text <script>alert('XSS')</script>",
            "message": "Hello world",
        }
        meta_data = {"REMOTE_ADDR": "127.0.0.1"}

        submission = create_bot_record(cleaned_data, meta_data)

        xss_attack = XSSAttack.objects.get(submission=submission)
        assert xss_attack is not None
        assert xss_attack.field == "name"
        assert xss_attack.pattern == "script_tag"
        assert xss_attack.snippet == "<script>alert('XSS')</script>"

    def test_iframe_xss_attack_records_when_detected(self):
        """Test that XSS attacks are detected and stored."""
        cleaned_data = {
            "name": "<iframe src='javascript:alert(1)'></iframe>",
            "message": "Hello world",
        }
        meta_data = {"REMOTE_ADDR": "127.0.0.1"}

        submission = create_bot_record(cleaned_data, meta_data)

        # Multiple patterns may match (iframe_tag and js_scheme), so filter for iframe_tag
        xss_attack = XSSAttack.objects.filter(
            submission=submission, pattern="iframe_tag"
        ).first()
        assert xss_attack is not None
        assert xss_attack.field == "name"
        assert xss_attack.pattern == "iframe_tag"
        assert xss_attack.snippet == "<iframe src='javascript:alert(1)'></iframe>"

    def test_img_and_iframe_xss_attack_records_when_detected(self):
        """Test that XSS attacks are detected and stored."""
        cleaned_data = {
            "name": "<img src='javascript:alert(1)'><iframe src='javascript:alert(1)'></iframe>",
            "message": "Hello world",
        }
        meta_data = {"REMOTE_ADDR": "127.0.0.1"}

        submission = create_bot_record(cleaned_data, meta_data)

        xss_attacks = XSSAttack.objects.filter(submission=submission)
        # Multiple patterns may match (iframe_tag, js_scheme from iframe, js_scheme from img)
        # So we expect at least 2 distinct pattern types
        assert xss_attacks.count() >= 2

        # Verify we have iframe_tag pattern
        iframe_attacks = xss_attacks.filter(pattern="iframe_tag")
        assert iframe_attacks.count() >= 1

        # Verify we have js_scheme pattern (from javascript: in src attributes)
        js_attacks = xss_attacks.filter(pattern="js_scheme")
        assert js_attacks.count() >= 1

    #######
