import re
from typing import List
from src.models import ExtractedIntelligence
from src.utils.validation import normalize_phone_number, normalize_upi_id


UPI_PATTERN = re.compile(r'[a-zA-Z0-9._\-]+@[a-zA-Z]+', re.IGNORECASE)
PHONE_PATTERN = re.compile(r'(?:\+91[\s\-]?)?[6-9]\d{9}')
LINK_PATTERN = re.compile(r'https?://[^\s<>"{}|\\^`\[\]]+', re.IGNORECASE)
BANK_REF_PATTERN = re.compile(r'\b\d{4}[\s\-]?\d{4}[\s\-]?\d{4}[\s\-]?\d{4}\b')
ACCOUNT_PATTERN = re.compile(r'\b\d{9,18}\b')


async def extract_upi_ids(message: str) -> List[str]:
    matches = UPI_PATTERN.findall(message)
    upi_ids = []
    
    common_domains = {"gmail", "yahoo", "hotmail", "outlook", "email", "mail"}
    
    for match in matches:
        parts = match.split("@")
        if len(parts) == 2:
            domain = parts[1].lower()
            if domain not in common_domains:
                normalized = normalize_upi_id(match)
                if normalized not in upi_ids:
                    upi_ids.append(normalized)
    
    return upi_ids


async def extract_phone_numbers(message: str) -> List[str]:
    matches = PHONE_PATTERN.findall(message)
    phone_numbers = []
    
    for match in matches:
        normalized = normalize_phone_number(match)
        if normalized and normalized not in phone_numbers:
            phone_numbers.append(normalized)
    
    return phone_numbers


async def extract_links(message: str) -> List[str]:
    matches = LINK_PATTERN.findall(message)
    links = []
    
    trusted_domains = {"google.com", "facebook.com", "twitter.com", "linkedin.com"}
    
    for link in matches:
        is_trusted = False
        for domain in trusted_domains:
            if domain in link.lower():
                is_trusted = True
                break
        
        if not is_trusted and link not in links:
            links.append(link)
    
    return links


async def extract_bank_references(message: str) -> List[str]:
    card_matches = BANK_REF_PATTERN.findall(message)
    account_matches = ACCOUNT_PATTERN.findall(message)
    
    references = []
    
    for match in card_matches:
        cleaned = re.sub(r'[\s\-]', '', match)
        if cleaned not in references:
            references.append(cleaned)
    
    for match in account_matches:
        if len(match) >= 9 and match not in references:
            references.append(match)
    
    return references


async def extract_all_intelligence(message: str, existing: ExtractedIntelligence) -> ExtractedIntelligence:
    upi_ids = await extract_upi_ids(message)
    phone_numbers = await extract_phone_numbers(message)
    links = await extract_links(message)
    bank_refs = await extract_bank_references(message)
    
    from src.scam_detector.classifier import get_matched_keywords
    keywords = await get_matched_keywords(message)
    
    all_upi = list(set(existing.upi_ids + upi_ids))
    all_phones = list(set(existing.phone_numbers + phone_numbers))
    all_links = list(set(existing.phishing_links + links))
    all_bank = list(set(existing.bank_accounts + bank_refs))
    all_keywords = list(set(existing.suspicious_keywords + keywords))
    
    return ExtractedIntelligence(
        upi_ids=all_upi,
        phone_numbers=all_phones,
        phishing_links=all_links,
        bank_accounts=all_bank,
        suspicious_keywords=all_keywords
    )


async def has_sufficient_intelligence(intel: ExtractedIntelligence) -> bool:
    has_upi = len(intel.upi_ids) >= 1
    has_link = len(intel.phishing_links) >= 1
    has_phone = len(intel.phone_numbers) >= 1
    
    return has_upi or has_link or (has_phone and len(intel.suspicious_keywords) >= 3)
