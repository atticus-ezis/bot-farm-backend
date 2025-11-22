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
