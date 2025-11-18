from rest_framework.throttling import SimpleRateThrottle


class BotSubmissionRateThrottle(SimpleRateThrottle):
    scope = 'contact_bot'

    def get_cache_key(self, request, view):
        return self.get_ident(request)
