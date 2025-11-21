# myapp/views.py

from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import AllowAny
from uuid import uuid4
from .enums import AttackCategory
from .models import BotEvent, AttackType
from .utils import extract_attacks, extract_meta_data, extract_email_from_payload


class BotSummaryView(APIView):
    """
    Returns a summary of the analytics data.
    """

    def get(self, request):
        total_events = BotEvent.objects.count()
        total_unique_ips = BotEvent.objects.values("ip_address").distinct().count()

        total_attacks = AttackType.objects.count()
        total_xss_attempts = AttackType.objects.filter(
            category=AttackCategory.XSS
        ).count()
        total_sqli_attempts = AttackType.objects.filter(
            category=AttackCategory.SQLI
        ).count()
        total_lfi_attempts = AttackType.objects.filter(
            category=AttackCategory.LFI
        ).count()
        total_cmd_attempts = AttackType.objects.filter(
            category=AttackCategory.CMD
        ).count()
        return Response(
            {
                "total_bot_traffic": total_events,
                "total_unique_ips": total_unique_ips,
                "total_attacks": total_attacks,
                "total_xss_attempts": total_xss_attempts,
                "total_sqli_attempts": total_sqli_attempts,
                "total_lfi_attempts": total_lfi_attempts,
                "total_cmd_attempts": total_cmd_attempts,
            },
            status=status.HTTP_200_OK,
        )


class HoneypotView(APIView):
    """
    Logs GET and POST bot activity, detects XSS, and correlates follow-up requests.
    """

    permission_classes = [AllowAny]

    def _log_event(self, request, method_type, ctoken):
        params = request.GET if method_type == "GET" else request.data

        meta_data = extract_meta_data(request.META)
        email = extract_email_from_payload(params)

        # Create main BotEvent
        bot_event = BotEvent.objects.create(
            method=method_type,
            ip_address=meta_data["ip_address"],
            geo_location=meta_data["geo_location"],
            agent=meta_data["agent"],
            referer=meta_data["referer"],
            language=meta_data["lang"],
            request_path=request.path,
            data=params,
            correlation_token=ctoken,
            email=email,
        )

        # Detect attacks in all fields
        attacks_found = False
        for key, value in params.items():
            attack_list = extract_attacks(value)
            if attack_list:
                for attack in attack_list:
                    pattern, category, match = attack
                    AttackType.objects.create(
                        bot_event=bot_event,
                        target_field=key,
                        pattern=pattern,
                        raw_value=match,
                        category=category.value,  # Convert enum to string value
                    )
                attacks_found = True

        # Only set attack_attempted if XSS was actually detected
        if attacks_found:
            bot_event.attack_attempted = True
            bot_event.save(update_fields=["attack_attempted"])

    def get(self, request):
        # Create a correlation token
        ctoken = uuid4()

        self._log_event(request, "GET", ctoken)

        html = f"""
        <html><body>
            <h3>Loading...</h3>
            <form id='hp' method='POST'>
                <input type="hidden" name="ctoken" value="{ctoken}">
                <input name="username">
                <input name="message">
                <input name="comment">
                <textarea name="content"></textarea>
                <button type="submit">Submit</button>
            </form>
            <script>
            setTimeout(() => document.getElementById('hp').submit(), 300);
            </script>
        </body></html>
        """

        return Response(html, content_type="text/html", status=200)

    #
    # POST → logs XSS in posted form data, correlates via ctoken
    #
    def post(self, request):
        ctoken = request.data.get("ctoken")

        self._log_event(request, "POST", ctoken)

        return Response({"status": "ok"}, status=status.HTTP_200_OK)
