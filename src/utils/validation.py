import re
from typing import Optional, Dict
from functools import lru_cache

_PATTERN_CACHE: Dict[str, re.Pattern] = {}

def _get_pattern(key: str) -> re.Pattern:
    if key not in _PATTERN_CACHE:
        patterns = {
            'control_chars': re.compile(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f]'),
            'session_id': re.compile(r'^[a-zA-Z0-9_\-]+$'),
            'phone_clean': re.compile(r'[\s\-\(\)]'),
            'phone_plus91': re.compile(r'^\+91\d{10}$'),
            'phone_91': re.compile(r'^91\d{10}$'),
            'phone_10': re.compile(r'^\d{10}$'),
            'upi_valid': re.compile(r'^[a-zA-Z0-9._\-]+@[a-zA-Z]+$'),
            'dangerous_chars': re.compile(r'[<>"\';\\]'),
        }
        _PATTERN_CACHE[key] = patterns[key]
    return _PATTERN_CACHE[key]


def sanitize_input(text: str) -> str:
    if not text:
        return ""
    text = text.strip()
    text = _get_pattern('control_chars').sub('', text)
    text = _get_pattern('dangerous_chars').sub('', text)
    return text[:10000]


def validate_session_id(session_id: str) -> bool:
    if not session_id or len(session_id) > 256:
        return False
    return bool(_get_pattern('session_id').match(session_id))


def validate_message(message: str) -> bool:
    return bool(message and 1 <= len(message) <= 10000)


def normalize_phone_number(phone: str) -> Optional[str]:
    if not phone:
        return None
    cleaned = _get_pattern('phone_clean').sub('', phone)
    if _get_pattern('phone_plus91').match(cleaned):
        return cleaned
    if _get_pattern('phone_91').match(cleaned):
        return f"+{cleaned}"
    if _get_pattern('phone_10').match(cleaned):
        return f"+91{cleaned}"
    return None


def normalize_upi_id(upi_id: str) -> Optional[str]:
    if not upi_id:
        return None
    normalized = upi_id.lower().strip()
    if _get_pattern('upi_valid').match(normalized):
        return normalized
    return None


@lru_cache(maxsize=1024)
def is_valid_indian_phone(phone: str) -> bool:
    normalized = normalize_phone_number(phone)
    if not normalized:
        return False
    digits = normalized.replace('+91', '')
    return len(digits) == 10 and digits[0] in '6789'


def sanitize_for_logging(text: str) -> str:
    if not text:
        return ""
    text = _get_pattern('control_chars').sub('', text)
    return text[:500]
