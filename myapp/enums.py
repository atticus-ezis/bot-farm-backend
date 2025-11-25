from enum import Enum


class AttackCategory(Enum):
    XSS = "XSS"
    SQLI = "SQLI"
    LFI = "LFI"
    CMD = "CMD"
    TRAVERSAL = "TRAVERSAL"
    SSTI = "SSTI"
    OTHER = "OTHER"


class MethodChoice(Enum):
    GET = "GET"
    POST = "POST"


class TargetFields(Enum):
    """Common form field names that bots might target.

    Includes honeypot form fields and common contact form fields
    that automated scripts frequently attempt to fill.
    """

    # Honeypot form fields (from HoneypotView)
    USERNAME = "username"
    MESSAGE = "message"
    COMMENT = "comment"
    CONTENT = "content"

    # Fields checked in email extraction (from utils.py)
    BODY = "body"
    DESCRIPTION = "description"

    # Common contact form fields that bots frequently target
    EMAIL = "email"
    NAME = "name"
    SUBJECT = "subject"
    PHONE = "phone"
    WEBSITE = "website"
    COMPANY = "company"
    TITLE = "title"
    ADDRESS = "address"
    CITY = "city"
    COUNTRY = "country"

    # Additional common fields
    FIRST_NAME = "first_name"
    LAST_NAME = "last_name"
    FULL_NAME = "full_name"
    CONTACT_EMAIL = "contact_email"
    E_MAIL = "e-mail"
    EMAIL_ADDRESS = "email_address"
    PHONE_NUMBER = "phone_number"
    MOBILE = "mobile"
    URL = "url"
    LINK = "link"
    HOMEPAGE = "homepage"
    NOTES = "notes"
    FEEDBACK = "feedback"
    INQUIRY = "inquiry"
    QUESTION = "question"
    TEXT = "text"
    INPUT = "input"
    FIELD = "field"
