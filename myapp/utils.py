import html
import re
from typing import Any, Dict, Iterable


EMAIL_REGEX = re.compile(r'([A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,})', re.IGNORECASE)


def sanitize_text(value: Any) -> str:
    if value is None:
        return ''
    text = str(value)
    return html.escape(text.strip())


def sanitize_body(raw_bytes: bytes | str) -> str:
    if isinstance(raw_bytes, bytes):
        decoded = raw_bytes.decode('utf-8', errors='replace')
    else:
        decoded = raw_bytes
    return sanitize_text(decoded)


def extract_email_from_payload(payload: Dict[str, Any]) -> str | None:
    for key in ('email', 'email_submitted', 'contact_email'):
        if payload.get(key):
            match = EMAIL_REGEX.search(str(payload[key]))
            if match:
                return match.group(1).lower()

    body = payload.get('raw_body')
    if body:
        match = EMAIL_REGEX.search(body)
        if match:
            return match.group(1).lower()
    return None


def collect_headers(meta: Dict[str, Any]) -> Dict[str, Any]:
    headers: Dict[str, Any] = {}
    for key, value in meta.items():
        if not key.startswith('HTTP_') and key not in {'CONTENT_TYPE', 'CONTENT_LENGTH'}:
            continue
        headers[key] = str(value)
    return headers


def get_client_ip(meta: Dict[str, Any]) -> tuple[str, str | None]:
    forwarded_for = meta.get('HTTP_X_FORWARDED_FOR') or meta.get('HTTP_FORWARDED_FOR')
    client_ip = ''
    if forwarded_for:
        parts = [part.strip() for part in forwarded_for.split(',') if part.strip()]
        if parts:
            client_ip = parts[0]
    client_ip = client_ip or meta.get('REMOTE_ADDR', '') or ''
    return client_ip, forwarded_for


def build_geo_from_headers(meta: Dict[str, Any]) -> Dict[str, Any] | None:
    country = meta.get('HTTP_CF_IPCOUNTRY') or meta.get('HTTP_X_APPENGINE_COUNTRY')
    city = meta.get('HTTP_CF_IPCITY')
    if not country and not city:
        return None
    geo = {'country': country}
    if city:
        geo['city'] = city
    return geo


def has_honeypot_hit(payload: Dict[str, Any]) -> bool:
    return any(payload.get(field) for field in ('middle_name', 'company'))


def summarize_tags(submissions: Iterable['BotSubmission']) -> Dict[str, int]:
    counts: Dict[str, int] = {}
    for submission in submissions:
        for tag in submission.detection_tags or []:
            counts[tag] = counts.get(tag, 0) + 1
    return counts
