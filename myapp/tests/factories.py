import factory
import random
from uuid import uuid4
from django.utils import timezone
from datetime import timedelta
from faker import Faker

from myapp.models import BotEvent, AttackType
from myapp.enums import MethodChoice, TargetFields

fake = Faker()


# email shouldn't exist if data is none
class BotEventFactory(factory.django.DjangoModelFactory):
    """Factory for creating BotEvent instances."""

    class Meta:
        model = BotEvent

    id = factory.LazyFunction(uuid4)
    method = factory.Iterator([MethodChoice.GET.value, MethodChoice.POST.value])
    request_path = factory.Faker("uri_path")
    ip_address = factory.Faker("ipv4")
    email = factory.LazyAttribute(
        lambda obj: fake.email() if obj.data is not None else None
    )
    geo_location = factory.Faker("country_code")
    agent = factory.Faker("user_agent")
    referer = factory.Faker("url")
    origin = factory.Faker("url")
    language = factory.Faker("language_code")
    data = factory.Dict({"test": "data"})
    correlation_token = factory.LazyFunction(uuid4)
    attack_attempted = False
    created_at = factory.LazyFunction(
        lambda: timezone.now() - timedelta(days=random.randint(0, 30))
    )


class AttackTypeFactory(factory.django.DjangoModelFactory):
    """Factory for creating AttackType instances.

    Automatically updates the bot_event's data field to include
    the attack's target_field and raw_value, matching real-world behavior.
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
    created_at = factory.LazyFunction(
        lambda: timezone.now() - timedelta(days=random.randint(0, 30))
    )

    @factory.post_generation
    def update_bot_event_data(self, create, extracted, **kwargs):
        """Update bot_event's data field to include this attack's target_field and raw_value.

        For bot events with attacks, data will contain only the attack payloads,
        matching real-world behavior where params contain the malicious values.
        """
        if not create:
            return

        # Initialize data as empty dict if it's None or contains only test data
        # This ensures data only contains attack-related fields when attacks exist
        if self.bot_event.data is None or self.bot_event.data == {"test": "data"}:
            self.bot_event.data = {}

        # Add this attack's target_field and raw_value to the data
        # This matches real-world behavior where params contain the attack payloads
        self.bot_event.data[self.target_field] = self.raw_value

        # Mark as attack attempted
        self.bot_event.attack_attempted = True

        # Save the updated bot_event
        self.bot_event.save(update_fields=["data", "attack_attempted"])
