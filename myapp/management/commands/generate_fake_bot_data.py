from django.core.management.base import BaseCommand
from myapp.models import BotEvent, AttackType
from myapp.tests.factories import BotEventFactory, AttackTypeFactory
import random


class Command(BaseCommand):
    help = "Generate fake bot data"

    def add_arguments(self, parser):
        parser.add_argument(
            "--bots", type=int, default=100, help="Number of bots to generate"
        )

        parser.add_argument(
            "--attacks",
            type=float,
            default=0.3,
            help="Percentage of bots that will attempt attacks",
        )

    def _create_scan_event(self, ip=None):
        """Create a scan event (no data, no attack)."""
        return BotEventFactory.create_scan_event(ip_address=ip)

    def _create_spam_event(self, ip=None):
        """Create a spam event (with data, no attack)."""
        return BotEventFactory.create_spam_event(ip_address=ip)

    def _create_attack_event(self, ip=None, num_attacks=None):
        """Create an attack event with 1-3 attacks."""
        if num_attacks is None:
            num_attacks = random.randint(1, 3)

        bot_event = BotEventFactory(ip_address=ip)
        # Create attacks - AttackTypeFactory's post_generation hook handles all updates
        for _ in range(num_attacks):
            AttackTypeFactory(bot_event=bot_event)

        return bot_event

    def handle(self, *args, **options):
        num_bots = options["bots"]
        attack_rate = options["attacks"]

        self.stdout.write(
            f"Creating {num_bots} bots with {attack_rate * 100}% attack rate"
        )

        common_ips = ["192.168.1.1", "10.0.0.1", "172.16.0.1", "203.0.113.1"]

        for i in range(num_bots):
            # 30% chance to use a common IP (creates aggregation opportunities)
            ip = random.choice(common_ips) if random.random() < 0.3 else None

            # Determine event type based on probabilities
            if random.random() < attack_rate:
                self._create_attack_event(ip=ip)

            elif random.random() < 0.4:
                self._create_scan_event(ip=ip)

            else:
                self._create_spam_event(ip=ip)

            if (i + 1) % 10 == 0:
                self.stdout.write(f"Created {i + 1}/{num_bots} bots...")

        self.stdout.write(
            self.style.SUCCESS(
                f"\nSuccessfully created {num_bots} bot events!\n"
                f"Total BotEvents: {BotEvent.objects.count()}\n"
                f"Total Attacks: {AttackType.objects.count()}\n"
                f"Events with attacks: {BotEvent.objects.filter(attack_attempted=True).count()}\n"
                f"Scan events: {BotEvent.objects.filter(event_category=BotEvent.EventCategory.SCAN).count()}\n"
                f"Spam events: {BotEvent.objects.filter(event_category=BotEvent.EventCategory.SPAM).count()}\n"
                f"Attack events: {BotEvent.objects.filter(event_category=BotEvent.EventCategory.ATTACK).count()}"
            )
        )
