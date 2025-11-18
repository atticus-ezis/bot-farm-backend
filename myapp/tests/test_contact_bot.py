from django.test import override_settings
from django.urls import reverse
from rest_framework import status
from rest_framework.test import APITestCase

from myapp.models import BotSubmission


class ContactBotEndpointTests(APITestCase):
    def test_submission_is_created_with_headers(self):
        response = self.client.post(
            reverse('contact-bot'),
            data={
                'name': 'Test Bot',
                'email': 'bot@example.com',
                'message': 'Hello world',
            },
            HTTP_USER_AGENT='pytest-agent',
            HTTP_REFERER='https://example.com',
            REMOTE_ADDR='203.0.113.10',
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        submission = BotSubmission.objects.get()
        self.assertEqual(submission.ip_address, '203.0.113.10')
        self.assertIn('email-detected', submission.detection_tags)
        self.assertEqual(submission.user_agent, 'pytest-agent')

    def test_honeypot_adds_tag(self):
        self.client.post(
            reverse('contact-bot'),
            data={
                'name': 'Sneaky',
                'email': 'sneaky@example.com',
                'middle_name': 'Bot',
            },
            REMOTE_ADDR='198.51.100.5',
        )

        submission = BotSubmission.objects.get()
        self.assertIn('honeypot-hit', submission.detection_tags)

    @override_settings(CONTACT_BOT_ENABLED=False)
    def test_endpoint_can_be_disabled(self):
        response = self.client.post(reverse('contact-bot'), data={'email': 'off@example.com'})
        self.assertEqual(response.status_code, 404)
        self.assertEqual(BotSubmission.objects.count(), 0)
