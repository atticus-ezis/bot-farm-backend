import re
from typing import Any, Dict
from urllib.parse import urlparse

from .patterns import ATTACK_PATTERNS


EMAIL_REGEX = re.compile(r"([A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,})", re.IGNORECASE)


def extract_email_from_payload(payload: Dict[str, Any]) -> str | None:
    """
    Extract email address from request payload (GET or POST data).
    Checks common email field names first, then searches in message/body fields.
    """
    # Check common email field names first
    for key in ("email", "email_submitted", "contact_email", "e-mail", "email_address"):
        value = payload.get(key)
        if value:
            # Handle QueryDict (can return list)
            if isinstance(value, list):
                value = value[0] if value else None
            if value:
                match = EMAIL_REGEX.search(str(value))
                if match:
                    return match.group(1).lower()

    # Check message/body fields for embedded emails
    # These match the form fields in HoneypotView
    for key in ("message", "content", "comment", "username", "body", "description"):
        value = payload.get(key)
        if value:
            # Handle QueryDict (can return list)
            if isinstance(value, list):
                value = value[0] if value else None
            if value:
                match = EMAIL_REGEX.search(str(value))
                if match:
                    return match.group(1).lower()

    return None


def get_bot_agent(meta: Dict[str, Any]) -> str | None:
    return meta.get("HTTP_USER_AGENT")


def get_bot_language(meta: Dict[str, Any]) -> str | None:
    raw_value = meta.get("HTTP_ACCEPT_LANGUAGE")
    if not raw_value:
        return None
    return raw_value.split(",")[0].strip()


def get_bot_referer(meta: Dict[str, Any]) -> str | None:
    raw_url = meta.get("HTTP_REFERER")
    if not raw_url:
        return None
    try:
        parsed = urlparse(raw_url.strip())
        domain = parsed.netloc
        # Remove port if present (e.g., "example.com:8080" -> "example.com")
        if ":" in domain:
            domain = domain.split(":")[0]
        return domain if domain else None
    except Exception:
        return None


def get_bot_origin(meta: Dict[str, Any]) -> str | None:
    origin = meta.get("HTTP_ORIGIN")
    if origin:
        return origin.strip()
    host = meta.get("HTTP_HOST")
    if host:
        return host.strip()
    return None


def get_bot_ip(meta: Dict[str, Any]) -> str | None:
    # Standard proxies (check both X-Forwarded-For and Forwarded-For)
    forwarded_for = meta.get("HTTP_X_FORWARDED_FOR") or meta.get("HTTP_FORWARDED_FOR")
    if forwarded_for and forwarded_for.strip():
        # Extract first IP, strip spaces
        ip = forwarded_for.split(",")[0].strip()
        if ip:  # Ensure we got a valid IP
            return ip

    # Nginx sets this
    real_ip = meta.get("HTTP_X_REAL_IP")
    if real_ip:
        return real_ip.strip()

    # Some setups use this
    client_ip = meta.get("HTTP_CLIENT_IP")
    if client_ip:
        return client_ip.strip()

    # Fallback to REMOTE_ADDR
    remote_addr = meta.get("REMOTE_ADDR")
    if remote_addr:
        return remote_addr.strip()

    return None


def get_email(cleaned_data: Dict[str, Any]) -> str | None:
    if cleaned_data.get("email"):
        return cleaned_data.get("email")
    else:
        body = cleaned_data.get("message")
        if body:
            match = EMAIL_REGEX.search(body)
            if match:
                return match.group(1).lower()
    return None


def build_geo_from_headers(meta: Dict[str, Any]) -> Dict[str, Any] | None:
    country = meta.get("HTTP_CF_IPCOUNTRY") or meta.get("HTTP_X_APPENGINE_COUNTRY")
    city = meta.get("HTTP_CF_IPCITY")
    if not country and not city:
        return None
    geo = {"country": country}
    if city:
        geo["city"] = city
    return geo


def extract_attacks(value: str):
    """
    Extract all types of attacks from value.
    Returns list of (pattern_name, category, matched_text) tuples.
    """
    if not isinstance(value, str):
        return []
    findings = []
    for name, category, regex in ATTACK_PATTERNS:
        match = regex.search(value)
        if match:
            findings.append((name, category, match.group(0)))
    return findings


def extract_meta_data(meta: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "ip_address": get_bot_ip(meta),
        "agent": get_bot_agent(meta),
        "referer": get_bot_referer(meta),
        "lang": get_bot_language(meta),
        "geo_location": build_geo_from_headers(meta),
        "origin": get_bot_origin(meta),
    }
