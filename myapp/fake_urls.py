# myapp/fake_urls.py
"""
List of fake URL paths used as honeypots to catch bots.
These paths are commonly scanned by bots and automated tools.
"""

FAKE_URLS = [
    "contact/",
    "api/contact/",
    "contact/submit/",
    "submit-form/",
    "api/message/",
    "send-message/",
    "company/",
    "feedback/",
    "support-ticket/",
    "api/v1/comments/",
    "api/v1/reviews/",
    "api/v1/profile/update/",
    "submit-feedback/",
    "post/create/",
    "upload/",
    "upload/image/",
    "phpinfo.php",
    "adminer.php",
    "debug.php",
    "login.php",
    "dashboard.php",
    "api/admin/",
    "api/v1/admin/login/",
    "api/v1/user/create/",
    "api/v1/user/update/",
    "api/v1/messages/",
    "api/v1/submit/",
    ".git/",
    "backup/",
    "old/",
    "test/",
    "dev/",
    "admin-login/",
    "cp/",  # control panel
    "dashboard/login/",
    "adminpanel/",
    "search/",
    "api/search/",
    "query/",
    "lookup/",
    "filter/",
]
