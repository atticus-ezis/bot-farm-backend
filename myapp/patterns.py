"""
Attack pattern definitions for detecting various security vulnerabilities.

Each pattern is a tuple of (pattern_name, AttackCategory, compiled_regex).
"""

import re

from .enums import AttackCategory

# Attack patterns for all categories
ATTACK_PATTERNS = [
    # XSS Patterns
    (
        "script_tag",
        AttackCategory.XSS,
        re.compile(r"<\s*script\b[^>]*>.*?</script>", re.IGNORECASE | re.DOTALL),
    ),
    (
        "iframe_tag",
        AttackCategory.XSS,
        re.compile(r"<\s*iframe\b[^>]*>.*?</iframe>", re.IGNORECASE | re.DOTALL),
    ),
    (
        "img_onerror",
        AttackCategory.XSS,
        re.compile(r"<\s*img\b[^>]*\bonerror\s*=[^>]*>", re.IGNORECASE),
    ),
    (
        "event_handler",
        AttackCategory.XSS,
        re.compile(r"<[^>]*\bon[a-z\-]+\s*=[^>]*>", re.IGNORECASE),
    ),
    ("js_scheme", AttackCategory.XSS, re.compile(r"javascript\s*:", re.IGNORECASE)),
    ("data_html", AttackCategory.XSS, re.compile(r"data:\s*text/html", re.IGNORECASE)),
    (
        "css_expression",
        AttackCategory.XSS,
        re.compile(r"expression\s*\(", re.IGNORECASE),
    ),
    (
        "meta_refresh",
        AttackCategory.XSS,
        re.compile(r"<\s*meta\b[^>]*http-equiv=['\"]?refresh", re.IGNORECASE),
    ),
    (
        "object_embed",
        AttackCategory.XSS,
        re.compile(r"<\s*(object|embed|applet)\b[^>]*>", re.IGNORECASE),
    ),
    ("svg_tag", AttackCategory.XSS, re.compile(r"<\s*svg\b[^>]*>", re.IGNORECASE)),
    # SQL Injection Patterns
    (
        "union_select",
        AttackCategory.SQLI,
        re.compile(r"\bunion\s+select\b", re.IGNORECASE),
    ),
    (
        "or_1_equals_1",
        AttackCategory.SQLI,
        re.compile(r"\bor\s+['\"]?1['\"]?\s*=\s*['\"]?1['\"]?", re.IGNORECASE),
    ),
    (
        "sql_comment",
        AttackCategory.SQLI,
        re.compile(r"--\s*$|/\*.*?\*/", re.IGNORECASE | re.DOTALL),
    ),
    (
        "drop_table",
        AttackCategory.SQLI,
        re.compile(r"\bdrop\s+table\b", re.IGNORECASE),
    ),
    (
        "exec_sp",
        AttackCategory.SQLI,
        re.compile(r"\bexec\s*\(|\bexecute\s*\(|xp_cmdshell", re.IGNORECASE),
    ),
    (
        "information_schema",
        AttackCategory.SQLI,
        re.compile(r"information_schema|sys\.|mysql\.", re.IGNORECASE),
    ),
    # Local File Inclusion Patterns
    (
        "etc_passwd",
        AttackCategory.LFI,
        re.compile(r"\.\./.*?etc/passwd|\.\.\\\.\.\\etc\\passwd", re.IGNORECASE),
    ),
    (
        "proc_self",
        AttackCategory.LFI,
        re.compile(r"\.\./.*?proc/self|\.\.\\\.\.\\proc\\self", re.IGNORECASE),
    ),
    (
        "windows_path",
        AttackCategory.LFI,
        re.compile(r"\.\.\\\.\.\\|\.\./\.\./", re.IGNORECASE),
    ),
    (
        "php_wrapper",
        AttackCategory.LFI,
        re.compile(r"php://(filter|input|expect|data)", re.IGNORECASE),
    ),
    (
        "file_wrapper",
        AttackCategory.LFI,
        re.compile(r"file://|file:///", re.IGNORECASE),
    ),
    # Command Injection Patterns
    (
        "pipe_command",
        AttackCategory.CMD,
        re.compile(r"[;&|`]\s*(ls|cat|whoami|id|uname|pwd|dir)", re.IGNORECASE),
    ),
    (
        "command_chaining",
        AttackCategory.CMD,
        re.compile(r"[;&|`]\s*$|&&|\|\|", re.IGNORECASE),
    ),
    (
        "subshell",
        AttackCategory.CMD,
        re.compile(r"\$\([^)]+\)|`[^`]+`", re.IGNORECASE),
    ),
    (
        "nc_listener",
        AttackCategory.CMD,
        re.compile(r"nc\s+-l|netcat\s+-l|ncat\s+-l", re.IGNORECASE),
    ),
    (
        "reverse_shell",
        AttackCategory.CMD,
        re.compile(r"bash\s+-i|sh\s+-i|/bin/(sh|bash)\s+-i", re.IGNORECASE),
    ),
    # Path Traversal Patterns
    (
        "dot_dot_slash",
        AttackCategory.TRAVERSAL,
        re.compile(r"\.\./\.\./|\.\.\\\.\.\\", re.IGNORECASE),
    ),
    (
        "absolute_path",
        AttackCategory.TRAVERSAL,
        re.compile(r"^/(etc|usr|var|home|root|windows|system32)", re.IGNORECASE),
    ),
    (
        "encoded_traversal",
        AttackCategory.TRAVERSAL,
        re.compile(r"\.\.%2f|\.\.%5c|%2e%2e%2f|%2e%2e%5c", re.IGNORECASE),
    ),
    # Server-Side Template Injection Patterns
    (
        "jinja2_template",
        AttackCategory.SSTI,
        re.compile(r"\{\{.*?\}\}|\{%\s*.*?\s*%\}", re.IGNORECASE),
    ),
    (
        "smarty_template",
        AttackCategory.SSTI,
        re.compile(r"\{.*?\}|\{if\s+.*?\}", re.IGNORECASE),
    ),
    (
        "freemarker_template",
        AttackCategory.SSTI,
        re.compile(r"\$\{.*?\}|<#.*?>", re.IGNORECASE),
    ),
    (
        "velocity_template",
        AttackCategory.SSTI,
        re.compile(r"\$!?\{.*?\}", re.IGNORECASE),
    ),
    (
        "twig_template",
        AttackCategory.SSTI,
        re.compile(r"\{\{.*?\}\}|\{%\s*.*?\s*%\}", re.IGNORECASE),
    ),
]
