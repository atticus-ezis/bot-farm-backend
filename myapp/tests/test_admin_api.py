from django.contrib.auth import get_user_model
from django.urls import reverse
from rest_framework import status
from rest_framework.test import APITestCase

from myapp.models import BotSubmission


class AdminAPITests(APITestCase):
    def setUp(self):
        self.user = get_user_model().objects.create_superuser('admin', 'admin@example.com', 'password123')
        self.list_url = reverse('submission-list')

    def test_requires_authentication(self):
        response = self.client.get(self.list_url)
        self.assertIn(response.status_code, (status.HTTP_401_UNAUTHORIZED, status.HTTP_403_FORBIDDEN))

    def test_list_returns_data(self):
        self.client.login(username='admin', password='password123')
        BotSubmission.objects.create(
            email_submitted='bot@example.com',
            raw_body='payload',
            ip_address='203.0.113.7',
            detection_tags=['honeypot-hit'],
        )
        response = self.client.get(self.list_url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['count'], 1)

    def test_filter_by_tag(self):
        self.client.login(username='admin', password='password123')
        BotSubmission.objects.create(
            email_submitted='first@example.com',
            raw_body='payload',
            ip_address='203.0.113.1',
            detection_tags=['honeypot-hit'],
        )
        BotSubmission.objects.create(
            email_submitted='second@example.com',
            raw_body='payload',
            ip_address='203.0.113.2',
            detection_tags=['other'],
        )
        response = self.client.get(self.list_url, {'tag': 'honeypot-hit'})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['count'], 1)
        self.assertEqual(response.data['results'][0]['email_preview'], 'first@example.com')

    def test_export_csv(self):
        self.client.login(username='admin', password='password123')
        BotSubmission.objects.create(
            email_submitted='export@example.com',
            raw_body='payload',
            ip_address='203.0.113.9',
        )
        response = self.client.get(reverse('submission-export'))
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response['Content-Type'], 'text/csv')
