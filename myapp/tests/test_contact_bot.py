# from django.urls import reverse
# from django.test import override_settings
# from rest_framework import status

# from myapp.models import XSSAttack


# class TestContactBotEndpoint:
#     """Test suite for the contact-bot API endpoint."""

#     def test_successful_submission_with_all_fields(
#         self, api_client, valid_submission_data, request_headers
#     ):
#         """Test successful submission with all fields provided."""
#         response = api_client.post(
#             reverse("contact-bot"),
#             data=valid_submission_data,
#             **request_headers,
#         )

#         assert response.status_code == status.HTTP_200_OK
#         assert BotSubmission.objects.count() == 1

#         submission = BotSubmission.objects.first()
#         assert submission.name == "John Doe"
#         assert submission.email == "john@example.com"
#         assert submission.message == "Hello, this is a test message"
#         assert submission.ip_address == "192.168.1.100"
#         assert submission.agent == "Mozilla/5.0 (Test Browser)"
#         assert submission.referer == "https://example.com/contact"
#         # Language extraction only gets the first language code
#         assert submission.language == "en-US"

#     def test_successful_submission_with_minimal_data(
#         self, api_client, minimal_submission_data, request_headers
#     ):
#         """Test successful submission with only required field (message)."""
#         response = api_client.post(
#             reverse("contact-bot"),
#             data=minimal_submission_data,
#             **request_headers,
#         )

#         assert response.status_code == status.HTTP_200_OK
#         assert BotSubmission.objects.count() == 1

#         submission = BotSubmission.objects.first()
#         assert submission.message == "Minimal test message"
#         assert submission.name is None or submission.name == ""
#         assert submission.email is None or submission.email == ""

#     def test_submission_missing_required_field(self, api_client, request_headers):
#         """Test that submission fails when required field (message) is missing."""
#         response = api_client.post(
#             reverse("contact-bot"),
#             data={"name": "John", "email": "john@example.com"},
#             **request_headers,
#         )

#         assert response.status_code == status.HTTP_400_BAD_REQUEST
#         assert "message" in response.data
#         assert BotSubmission.objects.count() == 0

#     def test_submission_with_invalid_email(self, api_client, request_headers):
#         """Test that submission fails with invalid email format."""
#         response = api_client.post(
#             reverse("contact-bot"),
#             data={
#                 "name": "John",
#                 "email": "not-an-email",
#                 "message": "Test message",
#             },
#             **request_headers,
#         )

#         assert response.status_code == status.HTTP_400_BAD_REQUEST
#         assert "email" in response.data
#         assert BotSubmission.objects.count() == 0

#     def test_submission_extracts_ip_from_x_forwarded_for(
#         self, api_client, valid_submission_data, x_forwarded_for_headers
#     ):
#         """Test that IP is correctly extracted from X-Forwarded-For header."""
#         response = api_client.post(
#             reverse("contact-bot"),
#             data=valid_submission_data,
#             **x_forwarded_for_headers,
#         )

#         assert response.status_code == status.HTTP_200_OK
#         submission = BotSubmission.objects.first()
#         # Should extract first IP from X-Forwarded-For
#         assert submission.ip_address == "203.0.113.1"
#         assert "203.0.113.1" in submission.full_ip_address

#     def test_submission_without_headers(self, api_client, valid_submission_data):
#         """Test submission when no headers are provided."""
#         response = api_client.post(
#             reverse("contact-bot"),
#             data=valid_submission_data,
#         )

#         assert response.status_code == status.HTTP_200_OK
#         submission = BotSubmission.objects.first()
#         # Should handle missing headers gracefully
#         assert submission.name == "John Doe"
#         assert submission.email == "john@example.com"

#     def test_submission_detects_xss_attack(self, api_client, request_headers):
#         """Test that XSS attacks are detected and recorded."""
#         malicious_data = {
#             "name": "Evil User",
#             "email": "evil@example.com",
#             "message": "Hello <script>alert('XSS')</script> world",
#         }

#         response = api_client.post(
#             reverse("contact-bot"),
#             data=malicious_data,
#             **request_headers,
#         )

#         assert response.status_code == status.HTTP_200_OK
#         submission = BotSubmission.objects.first()

#         # Check that XSS attack was detected
#         xss_attacks = XSSAttack.objects.filter(submission=submission)
#         assert xss_attacks.count() >= 1

#         script_attack = xss_attacks.filter(pattern="script_tag").first()
#         assert script_attack is not None
#         assert script_attack.field == "message"
#         assert "<script>" in script_attack.snippet.lower()

#     def test_submission_detects_multiple_xss_patterns(
#         self, api_client, request_headers
#     ):
#         """Test that multiple XSS patterns are detected."""
#         malicious_data = {
#             "name": "<iframe src='javascript:alert(1)'></iframe>",
#             "message": "Test <img src='x' onerror='alert(1)'>",
#         }

#         response = api_client.post(
#             reverse("contact-bot"),
#             data=malicious_data,
#             **request_headers,
#         )

#         assert response.status_code == status.HTTP_200_OK
#         submission = BotSubmission.objects.first()

#         xss_attacks = XSSAttack.objects.filter(submission=submission)
#         assert xss_attacks.count() >= 2

#         # Should detect iframe in name
#         iframe_attack = xss_attacks.filter(field="name", pattern="iframe_tag").first()
#         assert iframe_attack is not None

#         # Should detect img onerror in message
#         img_attack = xss_attacks.filter(field="message", pattern="img_onerror").first()
#         assert img_attack is not None

#     @override_settings(CONTACT_BOT_ENABLED=False)
#     def test_endpoint_disabled_returns_error(
#         self, api_client, valid_submission_data, request_headers
#     ):
#         """Test that endpoint returns error when CONTACT_BOT_ENABLED is False."""
#         response = api_client.post(
#             reverse("contact-bot"),
#             data=valid_submission_data,
#             **request_headers,
#         )

#         assert response.status_code == status.HTTP_400_BAD_REQUEST
#         assert "error" in response.data
#         assert "disabled" in response.data["error"].lower()
#         assert BotSubmission.objects.count() == 0

#     def test_submission_extracts_email_from_message(self, api_client, request_headers):
#         """Test that email is extracted from message body when not in email field."""
#         data = {
#             "name": "Test User",
#             "message": "Contact me at user@example.com for more info",
#         }

#         response = api_client.post(
#             reverse("contact-bot"),
#             data=data,
#             **request_headers,
#         )

#         assert response.status_code == status.HTTP_200_OK
#         submission = BotSubmission.objects.first()
#         assert submission.email == "user@example.com"

#     def test_submission_with_empty_optional_fields(self, api_client, request_headers):
#         """Test submission with empty optional fields."""
#         data = {
#             "name": "",
#             "email": "",
#             "phone": "",
#             "message": "Only message is required",
#         }

#         response = api_client.post(
#             reverse("contact-bot"),
#             data=data,
#             **request_headers,
#         )

#         assert response.status_code == status.HTTP_200_OK
#         submission = BotSubmission.objects.first()
#         assert submission.message == "Only message is required"

#     def test_submission_with_blank_message_fails(self, api_client, request_headers):
#         """Test that blank message fails validation."""
#         response = api_client.post(
#             reverse("contact-bot"),
#             data={"name": "John", "email": "john@example.com", "message": ""},
#             **request_headers,
#         )

#         assert response.status_code == status.HTTP_400_BAD_REQUEST
#         assert "message" in response.data
#         assert BotSubmission.objects.count() == 0
