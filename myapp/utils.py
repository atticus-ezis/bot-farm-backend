import html
import re
from typing import TYPE_CHECKING, Any, Dict, Iterable, List

if TYPE_CHECKING:
    from .models import BotSubmission


EMAIL_REGEX = re.compile(r"([A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,})", re.IGNORECASE)


def sanitize_text(value: Any) -> str:
    if value is None:
        return ""
    text = str(value)
    return html.escape(text.strip())


def sanitize_body(raw_bytes: bytes | str) -> str:
    if isinstance(raw_bytes, bytes):
        decoded = raw_bytes.decode("utf-8", errors="replace")
    else:
        decoded = raw_bytes
    return sanitize_text(decoded)


def extract_email_from_payload(payload: Dict[str, Any]) -> str | None:
    for key in ("email", "email_submitted", "contact_email"):
        if payload.get(key):
            match = EMAIL_REGEX.search(str(payload[key]))
            if match:
                return match.group(1).lower()

    body = payload.get("raw_body")
    if body:
        match = EMAIL_REGEX.search(body)
        if match:
            return match.group(1).lower()
    return None


# {
#     'HTTP_USER_AGENT': 'Mozilla/5.0...',
#     'HTTP_REFERER': 'https://example.com',
#     'HTTP_X_FORWARDED_FOR': '1.2.3.4',
#     'HTTP_ACCEPT_LANGUAGE': 'en-US,en;q=0.9',
#     'CONTENT_TYPE': 'application/x-www-form-urlencoded',
#     'CONTENT_LENGTH': '123',
#     'PATH_INFO': '/api/contact-bot/',  # ← Skipped
#     'REMOTE_ADDR': '5.6.7.8',  # ← Skipped
#     'SERVER_NAME': 'localhost',  # ← Skipped
# }


def collect_headers(meta: Dict[str, Any]) -> Dict[str, Any]:
    headers: Dict[str, Any] = {}
    for key, value in meta.items():
        if key not in {
            "CONTENT_TYPE",
            "CONTENT_LENGTH",
            "PATH_INFO",
            "REMOTE_ADDR",
            "SERVER_NAME",
        }:
            headers[key] = str(value)

    return headers


def get_bot_agent(meta: Dict[str, Any]) -> str | None:
    return meta.get("HTTP_USER_AGENT")


def get_bot_language(meta: Dict[str, Any]) -> str | None:
    raw_value = meta.get("HTTP_ACCEPT_LANGUAGE")
    if not raw_value:
        return None
    return raw_value.split(",")[0].strip()


def get_bot_referer(meta: Dict[str, Any]) -> str | None:
    return meta.get("HTTP_REFERER")


def get_client_ip(meta: Dict[str, Any]) -> tuple[str, str | None]:
    # Standard proxies (check both X-Forwarded-For and Forwarded-For)
    forwarded_for = meta.get("HTTP_X_FORWARDED_FOR") or meta.get("HTTP_FORWARDED_FOR")
    if forwarded_for and forwarded_for.strip():
        # Extract first IP, strip spaces
        ip = forwarded_for.split(",")[0].strip()
        if ip:  # Ensure we got a valid IP
            return ip, forwarded_for

    # Nginx sets this
    real_ip = meta.get("HTTP_X_REAL_IP")
    if real_ip:
        return real_ip.strip(), real_ip

    # Some setups use this
    client_ip = meta.get("HTTP_CLIENT_IP")
    if client_ip:
        return client_ip.strip(), client_ip

    # Fallback to REMOTE_ADDR
    remote_addr = meta.get("REMOTE_ADDR")
    if remote_addr:
        return remote_addr.strip(), None

    return None, None


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


def has_honeypot_hit(payload: Dict[str, Any]) -> bool:
    return any(payload.get(field) for field in ("middle_name", "company"))


def summarize_tags(submissions: Iterable["BotSubmission"]) -> Dict[str, int]:
    counts: Dict[str, int] = {}
    for submission in submissions:
        for tag in submission.detection_tags or []:
            counts[tag] = counts.get(tag, 0) + 1
    return counts


# Patterns to detect common XSS vectors


# -----------------------------------------
# 1) XSS Pattern Definitions
# -----------------------------------------

_PATTERNS = [
    ("script_tag", re.compile(r"<\s*script\b", re.IGNORECASE)),
    ("iframe_tag", re.compile(r"<\s*iframe\b", re.IGNORECASE)),
    ("img_onerror", re.compile(r"<\s*img\b[^>]*\bonerror\s*=", re.IGNORECASE)),
    (
        "event_handler",
        re.compile(r"\bon[a-z\-]+\s*=", re.IGNORECASE),
    ),  # onclick=, onerror=, etc.
    ("js_scheme", re.compile(r"javascript\s*:", re.IGNORECASE)),
    ("data_html", re.compile(r"data:\s*text/html", re.IGNORECASE)),
    ("css_expression", re.compile(r"expression\s*\(", re.IGNORECASE)),  # old IE
    (
        "meta_refresh",
        re.compile(r"<\s*meta\b[^>]*http-equiv=['\"]?refresh", re.IGNORECASE),
    ),
    ("object_embed", re.compile(r"<\s*(object|embed|applet)\b", re.IGNORECASE)),
    ("svg_tag", re.compile(r"<\s*svg\b", re.IGNORECASE)),
]

# -----------------------------------------
# 2) Extract the Full Enclosing HTML Element
# -----------------------------------------


def extract_full_element(text: str, match_pos: int) -> str:
    """
    Given a position inside a tag or attribute, return the full HTML element.
    E.g., matching 'onclick=' inside:
        <div onclick="alert(1)">Hi</div>
    returns:
        "<div onclick="alert(1)">Hi</div>"
    """
    # Find the opening "<"
    start = text.rfind("<", 0, match_pos)
    if start == -1:
        return text[match_pos:]  # fallback

    # Find end of the opening tag
    open_end = text.find(">", start)
    if open_end == -1:
        return text[start:]  # incomplete tag

    opening_tag = text[start : open_end + 1]

    # Extract tag name
    tag_name_match = re.match(r"<\s*([a-zA-Z0-9]+)", opening_tag)
    if not tag_name_match:
        return opening_tag

    tag_name = tag_name_match.group(1).lower()

    # Closing tag search
    closing_pattern = re.compile(rf"</\s*{tag_name}\s*>", re.IGNORECASE)
    closing_match = closing_pattern.search(text, open_end + 1)

    if closing_match:
        return text[start : closing_match.end()]

    # No closing tag found → return just the opening tag
    return opening_tag


# -----------------------------------------
# 3) Main XSS Scanner
# -----------------------------------------


def scan_xss(cleaned_data: Dict[str, Any]) -> List[dict]:
    """
    Scan each field in cleaned_data for common XSS vectors.

    Returns list of:
        { field, pattern, snippet }
    where snippet is the *full HTML element* containing the malicious payload.
    """
    findings = []

    for field, value in cleaned_data.items():
        if not value:
            continue

        text = str(value)
        if not text:
            continue

        for pattern_name, pattern in _PATTERNS:
            for match in pattern.finditer(text):
                pos = match.start()
                matched_text = match.group(0)

                # If HTML-like content exists, try full element extraction
                if "<" in text:
                    snippet = extract_full_element(text, pos)
                else:
                    snippet = matched_text

                findings.append(
                    {
                        "field": field,
                        "pattern": pattern_name,
                        "snippet": snippet,
                    }
                )

    return findings
