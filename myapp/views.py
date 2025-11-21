# myapp/views.py

from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from uuid import uuid4

from .models import BotEvent, XSSAttack
from .utils import extract_xss, extract_meta_data, extract_email_from_payload


class HoneypotView(APIView):
    """
    Logs GET and POST bot activity, detects XSS, and correlates follow-up requests.
    """

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

        # Detect XSS in all fields
        for key, value in params.items():
            pattern_name, raw_value = extract_xss(value)
            if pattern_name:
                XSSAttack.objects.create(
                    bot_event=bot_event,
                    field=key,
                    pattern=pattern_name,
                    raw_value=raw_value,
                )
            bot_event.xss_attempted = True
            bot_event.save(update_fields=["xss_attempted"])

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
