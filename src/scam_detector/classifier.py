from typing import List, Tuple
from src.models import ScamScore
from src.scam_detector.keywords import (
    get_all_scam_keywords,
    get_keyword_categories,
    URGENCY_KEYWORDS,
    THREAT_KEYWORDS,
    PAYMENT_KEYWORDS,
    CREDENTIAL_KEYWORDS
)
from src.config import get_settings

settings = get_settings()


async def calculate_keyword_score(message: str) -> Tuple[float, List[str]]:
    message_lower = message.lower()
    all_keywords = get_all_scam_keywords()
    matched_keywords = []
    
    for keyword in all_keywords:
        if keyword in message_lower:
            matched_keywords.append(keyword)
    
    if not matched_keywords:
        return 0.0, []
    
    base_score = min(len(matched_keywords) * 0.15, 0.5)
    
    categories = get_keyword_categories()
    category_bonus = 0.0
    matched_categories = set()
    
    for category, keywords in categories.items():
        for keyword in keywords:
            if keyword in message_lower:
                matched_categories.add(category)
                break
    
    category_bonus = len(matched_categories) * 0.1
    
    return min(base_score + category_bonus, 1.0), matched_keywords


async def calculate_intent_score(message: str) -> float:
    message_lower = message.lower()
    score = 0.0
    
    threat_count = sum(1 for k in THREAT_KEYWORDS if k in message_lower)
    if threat_count > 0:
        score += min(threat_count * 0.2, 0.4)
    
    urgency_count = sum(1 for k in URGENCY_KEYWORDS if k in message_lower)
    if urgency_count > 0:
        score += min(urgency_count * 0.15, 0.3)
    
    credential_count = sum(1 for k in CREDENTIAL_KEYWORDS if k in message_lower)
    if credential_count > 0:
        score += min(credential_count * 0.25, 0.5)
    
    payment_count = sum(1 for k in PAYMENT_KEYWORDS if k in message_lower)
    if payment_count > 0:
        score += min(payment_count * 0.15, 0.3)
    
    return min(score, 1.0)


async def calculate_pattern_score(message: str) -> float:
    message_lower = message.lower()
    score = 0.0
    
    if "http://" in message_lower or "https://" in message_lower:
        score += 0.2
    
    if "@" in message_lower and any(upi in message_lower for upi in ["@ybl", "@paytm", "@okaxis", "@oksbi", "@upi", "@ibl"]):
        score += 0.3
    
    import re
    phone_pattern = r'(\+91[\s\-]?\d{10}|\d{10})'
    if re.search(phone_pattern, message):
        score += 0.15
    
    if any(phrase in message_lower for phrase in ["click here", "click the link", "tap here", "open this"]):
        score += 0.2
    
    return min(score, 1.0)


async def detect_scam(message: str) -> ScamScore:
    keyword_score, matched_keywords = await calculate_keyword_score(message)
    intent_score = await calculate_intent_score(message)
    pattern_score = await calculate_pattern_score(message)
    
    total_score = (keyword_score * 0.3) + (intent_score * 0.4) + (pattern_score * 0.3)
    
    is_scam = total_score >= settings.scam_threshold
    
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
