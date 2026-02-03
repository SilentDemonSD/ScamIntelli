import re
from typing import Optional


def sanitize_input(text: str) -> str:
    if not text:
        return ""
    text = text.strip()
    text = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f]', '', text)
    return text[:10000]


def validate_session_id(session_id: str) -> bool:
    if not session_id:
        return False
    if len(session_id) < 1 or len(session_id) > 256:
        return False
    pattern = r'^[a-zA-Z0-9_\-]+$'
    return bool(re.match(pattern, session_id))


def validate_message(message: str) -> bool:
    if not message:
        return False
    if len(message) < 1 or len(message) > 10000:
        return False
    return True


def normalize_phone_number(phone: str) -> Optional[str]:
    cleaned = re.sub(r'[\s\-\(\)]', '', phone)
    if re.match(r'^\+91\d{10}$', cleaned):
        return cleaned
    if re.match(r'^91\d{10}$', cleaned):
        return f"+{cleaned}"
    if re.match(r'^\d{10}$', cleaned):
        return f"+91{cleaned}"
    return None


def normalize_upi_id(upi_id: str) -> str:
    return upi_id.lower().strip()
