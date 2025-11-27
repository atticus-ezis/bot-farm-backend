import factory
import random
from uuid import uuid4
from django.utils import timezone
from datetime import timedelta
from faker import Faker

from myapp.models import BotEvent, AttackType
from myapp.enums import TargetFields

fake = Faker()


# email shouldn't exist if data is none
class BotEventFactory(factory.django.DjangoModelFactory):
    """Factory for creating BotEvent instances."""

    class Meta:
        model = BotEvent

    id = factory.LazyFunction(uuid4)
    method = factory.Iterator(
        [
            BotEvent.MethodChoice.GET.value,
            BotEvent.MethodChoice.POST.value,
            BotEvent.MethodChoice.PUT.value,
            BotEvent.MethodChoice.PATCH.value,
            BotEvent.MethodChoice.DELETE.value,
        ]
    )
    request_path = factory.Faker("uri_path")
    ip_address = factory.Faker("ipv4")
    email = factory.LazyAttribute(
        lambda obj: (
            obj.data_details.get("email")
            if obj.data_details
            and isinstance(obj.data_details, dict)
            and "email" in obj.data_details
            else None
        )
    )
    geo_location = factory.Faker("country_code")
    agent = factory.Faker("user_agent")
    referer = factory.Faker("url")
    origin = factory.Faker("url")
    language = factory.Faker("language_code")
    correlation_token = factory.LazyFunction(uuid4)
    attack_attempted = False
    # Default to no data (use create_scan_event or create_spam_event for specific types)
    # data_details can be explicitly set, or defaults to None for scan events
    data_details = None
    # Derived fields based on data_details
    data_present = factory.LazyAttribute(
        lambda obj: obj.data_details is not None and obj.data_details != {}
    )
    field_count = factory.LazyAttribute(
        lambda obj: len(obj.data_details) if obj.data_details else 0
    )
    target_fields = factory.LazyAttribute(
        lambda obj: list(obj.data_details.keys()) if obj.data_details else None
    )
    created_at = factory.LazyFunction(
        lambda: timezone.now() - timedelta(days=random.randint(0, 30))
    )

    @factory.post_generation
    def set_event_category(self, create, extracted, **kwargs):
        """Set event category after BotEvent is created."""
        if create:
            self.set_category()

    @classmethod
    def create_scan_event(cls, **kwargs):
        """Create a scan event (no data, no attack).

        Usage:
            BotEventFactory.create_scan_event(ip_address="192.168.1.1")
        """
        return cls.create(
            data_details=None,
            attack_attempted=False,
            **kwargs,
        )

    @classmethod
    def create_spam_event(cls, **kwargs):
        """Create a spam event (with data, no attack).

        Usage:
            BotEventFactory.create_spam_event(ip_address="192.168.1.1")
        """
        random_message = fake.sentence()
        spam_email = kwargs.pop("email", None) or fake.email()
        spam_data = {
            "email": spam_email,
            "message": random_message,
        }
        return cls.create(
            data_details=spam_data,
            attack_attempted=False,
            **kwargs,
        )


class AttackTypeFactory(factory.django.DjangoModelFactory):
    """Factory for creating AttackType instances.

    Automatically updates the bot_event's data fields (data_details, target_fields, etc.)
    to include this attack's information, matching real-world behavior.
    """

    class Meta:
        model = AttackType

    id = factory.LazyFunction(uuid4)
    bot_event = factory.SubFactory(BotEventFactory)
    target_field = factory.Iterator([field.value for field in TargetFields])
    pattern = factory.Iterator(
        ["script_tag", "img_onerror", "or_1_equals_1", "union_select", "etc_passwd"]
    )
    category = factory.Iterator(
        [
            AttackType.AttackCategory.XSS,
            AttackType.AttackCategory.SQLI,
            AttackType.AttackCategory.LFI,
            AttackType.AttackCategory.CMD,
            AttackType.AttackCategory.TRAVERSAL,
            AttackType.AttackCategory.SSTI,
        ]
    )
    raw_value = factory.Faker("text", max_nb_chars=200)
    # full_value is the complete field value that contained the attack
    # For factory purposes, we'll use a realistic attack payload
    full_value = factory.LazyAttribute(
        lambda obj: f'<img src=x onerror="{obj.raw_value}">'
        if obj.pattern in ["img_onerror", "script_tag"]
        else obj.raw_value
    )
    created_at = factory.LazyFunction(
        lambda: timezone.now() - timedelta(days=random.randint(0, 30))
    )

    @factory.post_generation
    def update_bot_event_data(self, create, extracted, **kwargs):
        """Update bot_event's data fields to include this attack's information.

        For bot events with attacks, data_details will contain the attack payloads,
        matching real-world behavior where params contain the malicious values.
        """
        if not create:
            return

        # Initialize data_details if needed
        if self.bot_event.data_details is None:
            self.bot_event.data_details = {}

        # Add this attack's target_field and full_value to the data_details
        # This matches real-world behavior where params contain the attack payloads
        self.bot_event.data_details[self.target_field] = self.full_value

        # Update target_fields array to include this attack's field
        if self.bot_event.target_fields is None:
            self.bot_event.target_fields = []
        if self.target_field not in self.bot_event.target_fields:
            self.bot_event.target_fields.append(self.target_field)

        # Update field_count
        self.bot_event.field_count = len(self.bot_event.target_fields)

        # Ensure data_present is True when attacks exist
        self.bot_event.data_present = True

        # Mark as attack attempted
        self.bot_event.attack_attempted = True

        # Set event category (will set to 'attack' since attack_attempted=True)
        # set_category saves by default, but we'll save all fields together
        self.bot_event.set_category(save=False)

        # Save the updated bot_event
        self.bot_event.save(
            update_fields=[
                "data_present",
                "field_count",
                "target_fields",
                "data_details",
                "attack_attempted",
                "event_category",
            ]
        )
