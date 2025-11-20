from drf_yasg import openapi

contact_bot_post_schema = {
    "operation_summary": "Submit contact form data",
    "operation_description": (
        "Accepts form submission data from contact forms. "
        "This endpoint is rate-limited and may return 404 if the contact bot is disabled. "
        "All form fields are accepted and processed. The endpoint detects honeypot fields "
        "and extracts email addresses from the payload."
    ),
    "request_body": openapi.Schema(
        type=openapi.TYPE_OBJECT,
        description="Form data fields (accepts any form fields)",
        properties={
            "name": openapi.Schema(
                type=openapi.TYPE_STRING,
                description="Name of the submitter",
            ),
            "email": openapi.Schema(
                type=openapi.TYPE_STRING,
                description="Email address of the submitter",
            ),
            "message": openapi.Schema(
                type=openapi.TYPE_STRING,
                description="Message content",
            ),
        },
        example={
            "name": "John Doe",
            "email": "john@example.com",
            "message": "Hello, this is a test message",
        },
    ),
    "responses": {
        200: openapi.Response(
            description="Submission successful",
            examples={
                "text/html": {
                    "value": "<html><body>Thanks for your submission.</body></html>"
                }
            },
        ),
        404: openapi.Response(
            description="Contact bot is disabled",
            examples={"text/html": {"value": "<html><body>offline</body></html>"}},
        ),
        429: openapi.Response(
            description="Rate limit exceeded",
        ),
    },
    "tags": ["Contact Bot"],
}
