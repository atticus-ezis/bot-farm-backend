# from django_filters import rest_framework as filters

# from .models import BotSubmission, XSSAttack


# class BotSubmissionFilter(filters.FilterSet):
#     ip_address = filters.CharFilter(field_name="ip_address", lookup_expr="icontains")
#     email = filters.CharFilter(field_name="email", lookup_expr="icontains")
#     # Use ChoiceFilter for pattern to enable dropdown with valid choices
#     pattern = filters.ChoiceFilter(
#         field_name="xss_attacks__pattern",
#         distinct=True,
#     )
#     start_date = filters.DateFilter(field_name="created_at", lookup_expr="gte")
#     end_date = filters.DateFilter(field_name="created_at", lookup_expr="lte")
#     language = filters.ChoiceFilter(field_name="language")
#     agent = filters.ChoiceFilter(field_name="agent")

#     def __init__(self, *args, **kwargs):
#         super().__init__(*args, **kwargs)
#         # Set choices dynamically for dropdown support
#         # Language choices from distinct database values
#         language_choices = (
#             BotSubmission.objects.values_list("language", flat=True)
#             .distinct()
#             .exclude(language__isnull=True)
#             .exclude(language="")
#             .order_by("language")
#         )
#         self.filters["language"].extra["choices"] = [
#             (lang, lang) for lang in language_choices
#         ]

#         # Agent choices from distinct database values
#         agent_choices = (
#             BotSubmission.objects.values_list("agent", flat=True)
#             .distinct()
#             .exclude(agent__isnull=True)
#             .exclude(agent="")
#             .order_by("agent")
#         )
#         self.filters["agent"].extra["choices"] = [
#             (agent, agent) for agent in agent_choices
#         ]
#         # Pattern choices from distinct database values (only patterns that exist)
#         pattern_choices = (
#             XSSAttack.objects.values_list("pattern", flat=True)
#             .distinct()
#             .exclude(pattern__isnull=True)
#             .exclude(pattern="")
#             .order_by("pattern")
#         )
#         # Map pattern values to their human-readable labels from XSS_PATTERN_CHOICES
#         from .utils import XSS_PATTERN_CHOICES

#         pattern_label_map = {choice[0]: choice[1] for choice in XSS_PATTERN_CHOICES}
#         self.filters["pattern"].extra["choices"] = [
#             (pattern, pattern_label_map.get(pattern, pattern))
#             for pattern in pattern_choices
#         ]

#     class Meta:
#         model = BotSubmission
#         fields = [
#             "ip_address",
#             "email",
#             "language",
#             "agent",
#             "pattern",
#             "start_date",
#             "end_date",
#         ]
