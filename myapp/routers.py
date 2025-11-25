from rest_framework import routers
from .views import BotEventViewSet, AggregateIPViewSet, AttackTypeViewSet

router = routers.DefaultRouter()
router.register(r"bot-events", BotEventViewSet, basename="bot-event")
router.register(r"aggregate-ips", AggregateIPViewSet, basename="aggregate-ip")
router.register(r"attacks", AttackTypeViewSet, basename="attack")
