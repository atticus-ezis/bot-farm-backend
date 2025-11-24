import factory
import random
from uuid import uuid4
from django.utils import timezone
from datetime import timedelta

from myapp.models import BotEvent, AttackType
from myapp.enums import MethodChoice


class BotEventFactory(factory.django.DjangoModelFactory):
    """Factory for creating BotEvent instances."""

    class Meta:
        model = BotEvent

    id = factory.LazyFunction(uuid4)
    method = factory.Iterator([MethodChoice.GET.value, MethodChoice.POST.value])
    request_path = factory.Faker("uri_path")
    ip_address = factory.Faker("ipv4")
    email = factory.Faker("email")
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
    """Factory for creating AttackType instances."""

    class Meta:
        model = AttackType

    id = factory.LazyFunction(uuid4)
    bot_event = factory.SubFactory(BotEventFactory)
    target_field = factory.Faker("word")
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
