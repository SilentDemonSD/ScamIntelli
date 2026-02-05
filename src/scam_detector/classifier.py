import re
from typing import List, Tuple, FrozenSet
from src.models import ScamScore
from src.scam_detector.keywords import (
    get_all_scam_keywords,
    get_keyword_categories,
    get_high_severity_keywords,
    get_category_severity,
    URGENCY_KEYWORDS,
    THREAT_KEYWORDS,
    PAYMENT_KEYWORDS,
    CREDENTIAL_KEYWORDS,
    DIGITAL_ARREST_KEYWORDS
)
from src.config import get_settings

settings = get_settings()
_COMPILED_PATTERNS = {}


def _get_phone_pattern():
    if 'phone' not in _COMPILED_PATTERNS:
        _COMPILED_PATTERNS['phone'] = re.compile(r'(\+91[\s\-]?\d{10}|\d{10})')
    return _COMPILED_PATTERNS['phone']


async def calculate_keyword_score(message: str) -> Tuple[float, List[str]]:
    message_lower = message.lower()
    all_keywords = get_all_scam_keywords()
    matched_keywords = [kw for kw in all_keywords if kw in message_lower]
    
    if not matched_keywords:
        return 0.0, []
    
    high_severity = get_high_severity_keywords()
    high_matches = sum(1 for kw in matched_keywords if kw in high_severity)
    
    base_score = min(len(matched_keywords) * 0.15 + high_matches * 0.15, 0.6)
    
    categories = get_keyword_categories()
    severity_map = get_category_severity()
    matched_categories = set()
    category_severity_total = 0
    
    for category, keywords in categories.items():
        if any(kw in message_lower for kw in keywords):
            matched_categories.add(category)
            category_severity_total += severity_map.get(category, 3)
    
    category_bonus = min(len(matched_categories) * 0.1 + (category_severity_total / 50), 0.4)
    
    return min(base_score + category_bonus, 1.0), matched_keywords


async def calculate_intent_score(message: str) -> float:
    message_lower = message.lower()
    score = 0.0
    
    digital_arrest_count = sum(1 for k in DIGITAL_ARREST_KEYWORDS if k in message_lower)
    if digital_arrest_count > 0:
        score += min(digital_arrest_count * 0.4, 0.8)
    
    threat_count = sum(1 for k in THREAT_KEYWORDS if k in message_lower)
    if threat_count > 0:
        score += min(threat_count * 0.25, 0.5)
    
    urgency_count = sum(1 for k in URGENCY_KEYWORDS if k in message_lower)
    if urgency_count > 0:
        score += min(urgency_count * 0.15, 0.3)
    
    credential_count = sum(1 for k in CREDENTIAL_KEYWORDS if k in message_lower)
    if credential_count > 0:
        score += min(credential_count * 0.3, 0.6)
    
    payment_count = sum(1 for k in PAYMENT_KEYWORDS if k in message_lower)
    if payment_count > 0:
        score += min(payment_count * 0.2, 0.4)
    
    return min(score, 1.0)


async def calculate_pattern_score(message: str) -> float:
    message_lower = message.lower()
    score = 0.0
    
    if "http://" in message_lower or "https://" in message_lower:
        score += 0.2
        if any(sus in message_lower for sus in ['.xyz', '.tk', '.top', 'bit.ly', 'tinyurl', 'short']):
            score += 0.15
    
    upi_handles = ("@ybl", "@paytm", "@okaxis", "@oksbi", "@upi", "@ibl", "@axl", "@icici")
    if "@" in message_lower and any(handle in message_lower for handle in upi_handles):
        score += 0.3
    
    if _get_phone_pattern().search(message):
        score += 0.1
    
    action_phrases = ("click here", "click the link", "tap here", "open this", "scan qr", "download app")
    if any(phrase in message_lower for phrase in action_phrases):
        score += 0.2
    
    if any(phrase in message_lower for phrase in ["video call", "skype", "zoom call", "stay on call"]):
        score += 0.25
    
    return min(score, 1.0)


async def detect_scam(message: str) -> ScamScore:
    keyword_score, matched_keywords = await calculate_keyword_score(message)
    intent_score = await calculate_intent_score(message)
    pattern_score = await calculate_pattern_score(message)
    
    total_score = (keyword_score * 0.25) + (intent_score * 0.55) + (pattern_score * 0.2)
    
    is_scam = (
        total_score >= settings.scam_threshold or
        intent_score >= 0.5 or
        (keyword_score >= 0.4 and pattern_score >= 0.3)
    )
    
    return ScamScore(
        keyword_score=keyword_score,
        intent_score=intent_score,
        pattern_score=pattern_score,
        total_score=total_score,
        is_scam=is_scam
    )


async def get_matched_keywords(message: str) -> List[str]:
    _, matched = await calculate_keyword_score(message)
    return matched
