import re
from typing import List, FrozenSet
from src.models import ExtractedIntelligence
from src.utils.validation import normalize_phone_number, normalize_upi_id

_PATTERNS = {}


def _get_pattern(name: str) -> re.Pattern:
    if name not in _PATTERNS:
        patterns = {
            'upi': re.compile(r'[a-zA-Z0-9._\-]+@[a-zA-Z]+', re.IGNORECASE),
            'phone': re.compile(r'(?:\+91[\s\-]?)?[6-9]\d{9}'),
            'link': re.compile(r'https?://[^\s<>"{}|\\^`\[\]]+', re.IGNORECASE),
            'card': re.compile(r'\b\d{4}[\s\-]?\d{4}[\s\-]?\d{4}[\s\-]?\d{4}\b'),
            'account': re.compile(r'\b\d{9,18}\b')
        }
        _PATTERNS[name] = patterns[name]
    return _PATTERNS[name]


COMMON_EMAIL_DOMAINS: FrozenSet[str] = frozenset({
    "gmail", "yahoo", "hotmail", "outlook", "email", "mail", "live", "icloud"
})

TRUSTED_DOMAINS: FrozenSet[str] = frozenset({
    "google.com", "facebook.com", "twitter.com", "linkedin.com",
    "microsoft.com", "apple.com", "amazon.com", "github.com"
})

BANK_CONTEXT_KEYWORDS: FrozenSet[str] = frozenset({
    "account", "a/c", "acc", "bank", "ifsc", "neft", "imps", "rtgs",
    "transfer", "balance", "credited", "debited", "transaction"
})


async def extract_upi_ids(message: str) -> List[str]:
    matches = _get_pattern('upi').findall(message)
    upi_ids = []
    
    for match in matches:
        parts = match.split("@")
        if len(parts) == 2 and parts[1].lower() not in COMMON_EMAIL_DOMAINS:
            normalized = normalize_upi_id(match)
            if normalized and normalized not in upi_ids:
                upi_ids.append(normalized)
    
    return upi_ids


async def extract_phone_numbers(message: str) -> List[str]:
    matches = _get_pattern('phone').findall(message)
    phone_numbers = []
    
    for match in matches:
        normalized = normalize_phone_number(match)
        if normalized and normalized not in phone_numbers:
            phone_numbers.append(normalized)
    
    return phone_numbers


async def extract_links(message: str) -> List[str]:
    matches = _get_pattern('link').findall(message)
    links = []
    
    for link in matches:
        link_lower = link.lower()
        if not any(domain in link_lower for domain in TRUSTED_DOMAINS):
            if link not in links:
                links.append(link)
    
    return links


async def extract_bank_references(message: str, phone_numbers: List[str] = None) -> List[str]:
    card_matches = _get_pattern('card').findall(message)
    account_matches = _get_pattern('account').findall(message)
    
    phone_digits = set()
    if phone_numbers:
        for phone in phone_numbers:
            digits = re.sub(r'\D', '', phone)
            phone_digits.add(digits)
            if digits.startswith('91') and len(digits) > 10:
                phone_digits.add(digits[2:])
    
    message_lower = message.lower()
    has_bank_context = any(kw in message_lower for kw in BANK_CONTEXT_KEYWORDS)
    
    references = []
    
    for match in card_matches:
        cleaned = re.sub(r'[\s\-]', '', match)
        if cleaned not in references and cleaned not in phone_digits:
            references.append(cleaned)
    
    if has_bank_context:
        for match in account_matches:
            if len(match) == 10 and match[0] in '6789':
                continue
            if match in phone_digits:
                continue
            if len(match) == 4:
                try:
                    if 1900 <= int(match) <= 2100:
                        continue
                except ValueError:
                    pass
            if len(match) >= 9 and match not in references:
                references.append(match)
    
    return references


async def extract_all_intelligence(message: str, existing: ExtractedIntelligence) -> ExtractedIntelligence:
    upi_ids = await extract_upi_ids(message)
    phone_numbers = await extract_phone_numbers(message)
    links = await extract_links(message)
    
    all_known_phones = list(set(existing.phone_numbers + phone_numbers))
    bank_refs = await extract_bank_references(message, all_known_phones)
    
    from src.scam_detector.classifier import get_matched_keywords
    keywords = await get_matched_keywords(message)
    
    return ExtractedIntelligence(
        upi_ids=list(set(existing.upi_ids + upi_ids)),
        phone_numbers=list(set(existing.phone_numbers + phone_numbers)),
        phishing_links=list(set(existing.phishing_links + links)),
        bank_accounts=list(set(existing.bank_accounts + bank_refs)),
        suspicious_keywords=list(set(existing.suspicious_keywords + keywords))
    )


async def has_sufficient_intelligence(intel: ExtractedIntelligence) -> bool:
    has_upi = len(intel.upi_ids) >= 1
    has_link = len(intel.phishing_links) >= 1
    has_phone = len(intel.phone_numbers) >= 1
    has_bank = len(intel.bank_accounts) >= 1
    
    return has_upi or has_link or has_bank or (has_phone and len(intel.suspicious_keywords) >= 3)
