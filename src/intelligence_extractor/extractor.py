"""
Module: intelligence_extractor.extractor

Purpose:
    Extracts all intelligence entities from scammer messages including phone numbers,
    UPI IDs, emails, bank accounts, phishing links, case IDs, policy numbers,
    order numbers, organization names, employee IDs, addresses, and scammer names.

Key Components:
    - extract_all_intelligence: Main pipeline that runs all extractors and merges results
    - Individual extract_* functions for each entity type
    - has_sufficient_intelligence: Checks if enough intel gathered for report
    - make_context_aware_probe: Generates targeted follow-up questions

Design Patterns:
    - Lazy-compiled regex patterns via _get_pattern() for performance
    - Each extractor is isolated with independent error handling for resilience

Author: ScamIntelli Team
Last Modified: 2026-02-20
Version: 2.0
"""

import logging
import re
from typing import Any, Dict, FrozenSet, List, Optional

from src.models import ExtractedIntelligence
from src.utils.validation import normalize_phone_number, normalize_upi_id

logger = logging.getLogger(__name__)

_PATTERNS: Dict[str, re.Pattern] = {}


def _get_pattern(name: str) -> re.Pattern:
    """Lazily compile and cache regex patterns by name for performance.

    Args:
        name: Pattern identifier key.

    Returns:
        Compiled regex pattern.

    Raises:
        KeyError: If name is not a recognized pattern.
    """
    if name not in _PATTERNS:
        patterns = {
            "upi": re.compile(r"[a-zA-Z0-9._\-]+@[a-zA-Z]+", re.IGNORECASE),
            "phone": re.compile(
                r"(?<!\d)(?:\+91[\s\-]?)?[6-9]\d{9}(?!\d)"
                r"|(?:\+91[\s\-]?[6-9]\d{3}[\s\-]?\d{3}[\s\-]?\d{3})(?!\d)"
            ),
            "link": re.compile(
                r'https?://[^\s<>"{}|\\^`\[\]]+', re.IGNORECASE
            ),
            "card": re.compile(
                r"\b\d{4}[\s\-]?\d{4}[\s\-]?\d{4}[\s\-]?\d{4}\b"
            ),
            "account": re.compile(r"\b\d{9,18}\b"),
            "email": re.compile(
                r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}",
                re.IGNORECASE,
            ),
            # New patterns for extended intel extraction
            "case_id": re.compile(
                r"\b(?:CASE|CID|REF|CMP|FIR|INV|INVEST|COMPLAINT|TKT|TICKET)"
                r"[\s#/\-]?[\dA-Z\-/]{3,20}\b",
                re.IGNORECASE,
            ),
            "policy_number": re.compile(
                r"\b(?:POL|POLICY|INS|LIC|CLM|CLAIM|INSURANCE)"
                r"[\s#/\-]?[\dA-Z\-/]{3,20}\b",
                re.IGNORECASE,
            ),
            "order_number": re.compile(
                r"\b(?:ORD|ORDER|TRK|TRACK|TXN|TRANS|SHP|SHIP|AWB|CONSIGNMENT)"
                r"[\s#/\-]?[\dA-Z\-/]{3,20}\b",
                re.IGNORECASE,
            ),
            "employee_id": re.compile(
                r"\b(?:EMP|EMPLOYEE|BADGE|OFFICER|ID|STAFF)"
                r"[\s#/:\-]?[A-Z0-9\-]{2,15}\b",
                re.IGNORECASE,
            ),
        }
        _PATTERNS[name] = patterns[name]
    return _PATTERNS[name]


COMMON_EMAIL_DOMAINS: FrozenSet[str] = frozenset(
    {"gmail", "yahoo", "hotmail", "outlook", "email", "mail", "live", "icloud"}
)

TRUSTED_DOMAINS: FrozenSet[str] = frozenset(
    {
        "google.com",
        "facebook.com",
        "twitter.com",
        "linkedin.com",
        "microsoft.com",
        "apple.com",
        "amazon.com",
        "github.com",
    }
)

BANK_CONTEXT_KEYWORDS: FrozenSet[str] = frozenset(
    {
        "account",
        "a/c",
        "acc",
        "bank",
        "ifsc",
        "neft",
        "imps",
        "rtgs",
        "transfer",
        "balance",
        "credited",
        "debited",
        "transaction",
    }
)


async def extract_upi_ids(message: str, known_emails: List[str] = None) -> List[str]:
    """Extract UPI IDs from message text, filtering out known emails and common domains."""
    email_set = {e.lower() for e in (known_emails or [])}
    matches = _get_pattern("upi").findall(message)
    upi_ids = []

    for match in matches:
        if match.lower() in email_set:
            continue
        parts = match.split("@")
        if len(parts) != 2:
            continue
        domain = parts[1].lower()
        if domain in COMMON_EMAIL_DOMAINS:
            continue
        if "." in domain:
            continue
        idx = message.find(match)
        if idx != -1:
            end_idx = idx + len(match)
            if end_idx < len(message) and message[end_idx] in ("-", "."):
                after_pos = end_idx + 1
                if after_pos < len(message) and message[after_pos].isalnum():
                    continue
        normalized = normalize_upi_id(match)
        if normalized and normalized not in upi_ids:
            upi_ids.append(normalized)

    return upi_ids


async def extract_emails(message: str) -> List[str]:
    """Extract unique email addresses from message text."""
    matches = _get_pattern("email").findall(message)
    emails = []
    for match in matches:
        email_lower = match.lower().strip()
        if email_lower not in emails:
            emails.append(email_lower)
    return emails


async def extract_phone_numbers(message: str) -> List[str]:
    """Extract Indian phone numbers (with/without +91) from message text."""
    matches = _get_pattern("phone").findall(message)
    phone_numbers = []

    for match in matches:
        original = match.strip()
        if original and original not in phone_numbers:
            phone_numbers.append(original)
        normalized = normalize_phone_number(match)
        if normalized and normalized not in phone_numbers:
            phone_numbers.append(normalized)

    return phone_numbers


async def extract_links(message: str) -> List[str]:
    """Extract suspicious URLs from message text, excluding trusted domains."""
    matches = _get_pattern("link").findall(message)
    links = []

    for link in matches:
        link = link.rstrip(".,;:!?)")
        link_lower = link.lower()
        if not any(domain in link_lower for domain in TRUSTED_DOMAINS):
            if link not in links:
                links.append(link)

    return links


async def extract_bank_references(
    message: str, phone_numbers: List[str] = None
) -> List[str]:
    """Extract card numbers and bank account references, filtering out phone numbers."""
    card_matches = _get_pattern("card").findall(message)
    account_matches = _get_pattern("account").findall(message)

    phone_digits = set()
    if phone_numbers:
        for phone in phone_numbers:
            digits = re.sub(r"\D", "", phone)
            phone_digits.add(digits)
            if digits.startswith("91") and len(digits) > 10:
                phone_digits.add(digits[2:])

    message_lower = message.lower()
    has_bank_context = any(kw in message_lower for kw in BANK_CONTEXT_KEYWORDS)

    references = []

    for match in card_matches:
        cleaned = re.sub(r"[\s\-]", "", match)
        if cleaned not in references and cleaned not in phone_digits:
            references.append(cleaned)

    for match in account_matches:
        if len(match) == 10 and match[0] in "6789":
            continue
        if match in phone_digits:
            continue
        if len(match) == 4:
            try:
                if 1900 <= int(match) <= 2100:
                    continue
            except ValueError:
                pass
        if len(match) >= 14 and match not in references:
            references.append(match)
        elif has_bank_context and len(match) >= 9 and match not in references:
            references.append(match)

    return references


# ---------------------------------------------------------------------------
# Organization / institution names for impersonation detection
# ---------------------------------------------------------------------------
KNOWN_ORGANIZATIONS: FrozenSet[str] = frozenset({
    # Banks
    "sbi", "hdfc", "icici", "axis bank", "pnb", "bob", "canara bank",
    "kotak", "yes bank", "idbi", "union bank", "indusind",
    "federal bank", "rbl bank", "bandhan bank",
    # Government / law enforcement
    "cbi", "ed", "enforcement directorate", "income tax", "customs",
    "police", "cyber police", "cyber cell", "crime branch",
    "rbi", "sebi", "trai", "uidai", "nsdl",
    "income tax department", "narcotics", "ncb",
    # Companies / platforms
    "amazon", "flipkart", "paytm", "phonepe", "google pay", "gpay",
    "whatsapp", "facebook", "meta", "microsoft", "apple", "olx",
    "meesho", "myntra", "swiggy", "zomato", "uber", "ola",
    # Telecom
    "airtel", "jio", "bsnl", "vi", "vodafone",
    # Insurance
    "lic", "max life", "bajaj allianz", "star health", "hdfc life",
})

# Common Indian and generic name patterns for scammer name extraction
_NAME_PREFIXES = frozenset({
    "officer", "inspector", "sub-inspector", "si", "ips",
    "mr", "mrs", "ms", "dr", "prof", "shri", "smt",
    "constable", "sergeant", "captain", "major",
    "advocate", "lawyer",
})


async def extract_case_ids(message: str) -> List[str]:
    """Extract case/reference/complaint IDs from scammer messages.

    Patterns matched:
    - Case IDs: CASE12345, CID-789, REF#ABC123
    - Complaint numbers: CMP2024-001, FIR/123/2024
    - Reference codes: REF123456, TRN-ABC-123
    - Investigation IDs: INV-2024-001, INVEST#123

    Args:
        message: Raw scammer message text.

    Returns:
        List of normalized case IDs found in message.
    """
    try:
        matches = _get_pattern("case_id").findall(message)
    except (re.error, KeyError) as exc:
        logger.error("Regex error in case ID extraction: %s", exc)
        return []

    result: List[str] = []
    for m in matches:
        cleaned = m.strip().upper()
        if len(cleaned) >= 4 and cleaned not in result:
            result.append(cleaned)
    return result


async def extract_policy_numbers(message: str) -> List[str]:
    """Extract insurance/policy numbers from scammer messages.

    Patterns matched:
    - Policy numbers: POL123456789, POLICY-2024-ABC
    - Insurance IDs: INS/12345/2024, LIC-123456
    - Claim numbers: CLM-2024-001, CLAIM#123456

    Args:
        message: Raw scammer message text.

    Returns:
        List of normalized policy numbers.
    """
    try:
        matches = _get_pattern("policy_number").findall(message)
    except (re.error, KeyError) as exc:
        logger.error("Regex error in policy number extraction: %s", exc)
        return []

    result: List[str] = []
    for m in matches:
        cleaned = m.strip().upper()
        if len(cleaned) >= 4 and cleaned not in result:
            result.append(cleaned)
    return result


async def extract_order_numbers(message: str) -> List[str]:
    """Extract order/transaction/tracking IDs from scammer messages.

    Patterns matched:
    - Order IDs: ORD123456, ORDER-2024-ABC
    - Tracking numbers: TRK123456789, AWB-123-456
    - Transaction IDs: TXN20240115123, TRANS#12345
    - Shipment IDs: SHP-2024-001, SHIP#123456

    Args:
        message: Raw scammer message text.

    Returns:
        List of normalized order/tracking numbers.
    """
    try:
        matches = _get_pattern("order_number").findall(message)
    except (re.error, KeyError) as exc:
        logger.error("Regex error in order number extraction: %s", exc)
        return []

    result: List[str] = []
    for m in matches:
        cleaned = m.strip().upper()
        if len(cleaned) >= 4 and cleaned not in result:
            result.append(cleaned)
    return result


async def extract_organization_names(message: str) -> List[str]:
    """Extract company/organization/department names mentioned by scammer.

    Uses a curated set of known organizations plus contextual department patterns.

    Patterns detected:
    - Bank names: SBI, HDFC, ICICI, Axis Bank
    - Government agencies: CBI, ED, Income Tax, Customs
    - Companies: Amazon, Flipkart, PayTM, PhonePe
    - Departments: Fraud Department, KYC Department, Security Team

    Args:
        message: Raw scammer message text.

    Returns:
        List of organization names found (title-cased).
    """
    msg_lower = message.lower()
    found: List[str] = []

    # Match against known organizations
    for org in KNOWN_ORGANIZATIONS:
        if org in msg_lower:
            org_title = org.upper() if len(org) <= 4 else org.title()
            if org_title not in found:
                found.append(org_title)

    # Detect department references via pattern
    dept_pattern = re.compile(
        r"(?:fraud|kyc|security|verification|compliance|legal|technical|customer[\s\-]?(?:care|service|support)|"
        r"it|grievance|recovery)\s+(?:department|team|cell|unit|division|branch|desk|section)",
        re.IGNORECASE,
    )
    for match in dept_pattern.findall(message):
        dept = match.strip().title()
        if dept not in found:
            found.append(dept)

    return found


async def extract_employee_ids(message: str) -> List[str]:
    """Extract employee/badge/officer IDs from scammer messages.

    Scammers often claim fake credentials like badge numbers or employee IDs
    to appear legitimate.

    Args:
        message: Raw scammer message text.

    Returns:
        List of employee/badge IDs.
    """
    try:
        matches = _get_pattern("employee_id").findall(message)
    except (re.error, KeyError) as exc:
        logger.error("Regex error in employee ID extraction: %s", exc)
        return []

    result: List[str] = []
    # Generic short IDs like "ID 5" are too noisy; require minimum 4 chars
    for m in matches:
        cleaned = m.strip().upper()
        if len(cleaned) >= 4 and cleaned not in result:
            result.append(cleaned)
    return result


async def extract_names_mentioned(message: str) -> List[str]:
    """Extract person names/aliases mentioned by scammer.

    Looks for patterns like 'Officer Sharma', 'Mr. Patel', 'Inspector Kumar'
    which scammers use to establish false credibility.

    Args:
        message: Raw scammer message text.

    Returns:
        List of names detected.
    """
    name_pattern = re.compile(
        r"\b(?:officer|inspector|sub[\-\s]?inspector|si|ips|mr\.?|mrs\.?|ms\.?|dr\.?|"
        r"prof\.?|shri|smt\.?|constable|sergeant|captain|major|advocate|lawyer)"
        r"\s+([A-Z][a-z]{2,}(?:\s+[A-Z][a-z]{2,})?)",
        re.IGNORECASE,
    )
    found: List[str] = []
    for match in name_pattern.finditer(message):
        name = match.group(1).strip().title()
        if name not in found and len(name) >= 3:
            found.append(name)
    return found


async def extract_addresses(message: str) -> List[str]:
    """Extract physical addresses, office locations, or PIN code references.

    Detects patterns with street/city/pin codes commonly used in Indian scams.

    Args:
        message: Raw scammer message text.

    Returns:
        List of address strings detected.
    """
    found: List[str] = []

    # Indian PIN code-based addresses (6-digit codes)
    pin_pattern = re.compile(
        r"[A-Za-z\s,.\-]{5,60}(?:\d{6})",
        re.IGNORECASE,
    )
    for match in pin_pattern.finditer(message):
        addr = match.group().strip()
        if len(addr) >= 10 and addr not in found:
            found.append(addr)

    # Sector / block / floor pattern common in Indian govt office addresses
    office_pattern = re.compile(
        r"(?:sector|block|floor|building|tower|phase|plot)\s*[\-#]?\s*\d+[A-Za-z]?"
        r"(?:[\s,]+[A-Za-z\s]{3,30})?",
        re.IGNORECASE,
    )
    for match in office_pattern.finditer(message):
        addr = match.group().strip()
        if len(addr) >= 8 and addr not in found:
            found.append(addr)

    return found


async def extract_all_intelligence(
    message: str, existing: ExtractedIntelligence
) -> ExtractedIntelligence:
    """Extract ALL intelligence entities from message, merging with existing intel.

    Now extracts: UPI IDs, phones, links, banks, emails, keywords, case IDs,
    policy numbers, order numbers, organizations, addresses, employee IDs, names.

    Each extraction wrapped in try/except for resilience — a single failure
    will not discard partial results from other extractors.

    Args:
        message: Raw scammer message text.
        existing: Previously extracted intel to merge with.

    Returns:
        Merged ExtractedIntelligence with all entities found.
    """
    emails: List[str] = []
    upi_ids: List[str] = []
    phone_numbers: List[str] = []
    links: List[str] = []
    bank_refs: List[str] = []
    keywords: List[str] = []
    case_ids: List[str] = []
    policy_numbers: List[str] = []
    order_numbers: List[str] = []
    org_names: List[str] = []
    addresses: List[str] = []
    emp_ids: List[str] = []
    names: List[str] = []

    try:
        emails = await extract_emails(message)
    except re.error as exc:
        logger.error("Regex error in email extraction: %s", exc)
    except (AttributeError, TypeError) as exc:
        logger.error("Type/attribute error in email extraction: %s", exc)
    except Exception:
        logger.exception("Unexpected error in email extraction; continuing with empty list")

    try:
        upi_ids = await extract_upi_ids(message, known_emails=emails)
    except re.error as exc:
        logger.error("Regex error in UPI extraction: %s", exc)
    except (AttributeError, TypeError) as exc:
        logger.error("Type/attribute error in UPI extraction: %s", exc)
    except ValueError as exc:
        logger.error("Value error in UPI normalization: %s", exc)
    except Exception:
        logger.exception("Unexpected error in UPI extraction; continuing with empty list")

    try:
        phone_numbers = await extract_phone_numbers(message)
    except re.error as exc:
        logger.error("Regex error in phone extraction: %s", exc)
    except (AttributeError, TypeError) as exc:
        logger.error("Type/attribute error in phone extraction: %s", exc)
    except ValueError as exc:
        logger.error("Value error in phone normalization: %s", exc)
    except Exception:
        logger.exception("Unexpected error in phone extraction; continuing with empty list")

    try:
        links = await extract_links(message)
    except re.error as exc:
        logger.error("Regex error in link extraction: %s", exc)
    except (AttributeError, TypeError) as exc:
        logger.error("Type/attribute error in link extraction: %s", exc)
    except Exception:
        logger.exception("Unexpected error in link extraction; continuing with empty list")

    try:
        all_known_phones = list(set(existing.phone_numbers + phone_numbers))
        bank_refs = await extract_bank_references(message, all_known_phones)
    except re.error as exc:
        logger.error("Regex error in bank reference extraction: %s", exc)
    except (AttributeError, TypeError) as exc:
        logger.error("Type/attribute error in bank reference extraction: %s", exc)
    except ValueError as exc:
        logger.error("Value error in bank reference extraction: %s", exc)
    except Exception:
        logger.exception("Unexpected error in bank reference extraction; continuing with empty list")

    try:
        from src.scam_detector.classifier import get_matched_keywords
        keywords = await get_matched_keywords(message)
    except ImportError as exc:
        logger.error("Failed to import keyword classifier: %s", exc)
    except (AttributeError, TypeError) as exc:
        logger.error("Type/attribute error in keyword extraction: %s", exc)
    except Exception:
        logger.exception("Unexpected error in keyword extraction; continuing with empty list")

    # --- New extended extractors ---
    try:
        case_ids = await extract_case_ids(message)
    except re.error as exc:
        logger.error("Regex error in case ID extraction: %s", exc)
    except (AttributeError, TypeError) as exc:
        logger.error("Type/attribute error in case ID extraction: %s", exc)
    except Exception:
        logger.exception("Unexpected error in case ID extraction; continuing with empty list")

    try:
        policy_numbers = await extract_policy_numbers(message)
    except re.error as exc:
        logger.error("Regex error in policy number extraction: %s", exc)
    except (AttributeError, TypeError) as exc:
        logger.error("Type/attribute error in policy number extraction: %s", exc)
    except Exception:
        logger.exception("Unexpected error in policy number extraction; continuing with empty list")

    try:
        order_numbers = await extract_order_numbers(message)
    except re.error as exc:
        logger.error("Regex error in order number extraction: %s", exc)
    except (AttributeError, TypeError) as exc:
        logger.error("Type/attribute error in order number extraction: %s", exc)
    except Exception:
        logger.exception("Unexpected error in order number extraction; continuing with empty list")

    try:
        org_names = await extract_organization_names(message)
    except re.error as exc:
        logger.error("Regex error in organization name extraction: %s", exc)
    except (AttributeError, TypeError) as exc:
        logger.error("Type/attribute error in organization name extraction: %s", exc)
    except Exception:
        logger.exception("Unexpected error in organization name extraction; continuing with empty list")

    try:
        addresses = await extract_addresses(message)
    except re.error as exc:
        logger.error("Regex error in address extraction: %s", exc)
    except (AttributeError, TypeError) as exc:
        logger.error("Type/attribute error in address extraction: %s", exc)
    except Exception:
        logger.exception("Unexpected error in address extraction; continuing with empty list")

    try:
        emp_ids = await extract_employee_ids(message)
    except re.error as exc:
        logger.error("Regex error in employee ID extraction: %s", exc)
    except (AttributeError, TypeError) as exc:
        logger.error("Type/attribute error in employee ID extraction: %s", exc)
    except Exception:
        logger.exception("Unexpected error in employee ID extraction; continuing with empty list")

    try:
        names = await extract_names_mentioned(message)
    except re.error as exc:
        logger.error("Regex error in name extraction: %s", exc)
    except (AttributeError, TypeError) as exc:
        logger.error("Type/attribute error in name extraction: %s", exc)
    except Exception:
        logger.exception("Unexpected error in name extraction; continuing with empty list")

    return ExtractedIntelligence(
        upi_ids=list(set(existing.upi_ids + upi_ids)),
        phone_numbers=list(set(existing.phone_numbers + phone_numbers)),
        phishing_links=list(set(existing.phishing_links + links)),
        bank_accounts=list(set(existing.bank_accounts + bank_refs)),
        email_addresses=list(set(existing.email_addresses + emails)),
        suspicious_keywords=list(set(existing.suspicious_keywords + keywords)),
        case_ids=list(set(existing.case_ids + case_ids)),
        policy_numbers=list(set(existing.policy_numbers + policy_numbers)),
        order_numbers=list(set(existing.order_numbers + order_numbers)),
        organization_names=list(set(existing.organization_names + org_names)),
        addresses=list(set(existing.addresses + addresses)),
        employee_ids=list(set(existing.employee_ids + emp_ids)),
        names_mentioned=list(set(existing.names_mentioned + names)),
    )


async def has_sufficient_intelligence(intel: ExtractedIntelligence) -> bool:
    """Return True when enough intel has been gathered to file a report."""
    has_upi = len(intel.upi_ids) >= 1
    has_link = len(intel.phishing_links) >= 1
    has_phone = len(intel.phone_numbers) >= 1
    has_bank = len(intel.bank_accounts) >= 1

    return (
        has_upi
        or has_link
        or has_bank
        or (has_phone and len(intel.suspicious_keywords) >= 3)
    )


def make_context_aware_probe(
    recent_messages: List[Dict[str, Any]],
    extracted_intel: ExtractedIntelligence,
    confidence: float = 0.0,
) -> Optional[str]:
    """Build a targeted follow-up question using conversation history and flagged entities.

    Uses the last 3 scammer messages plus already-extracted entities to
    formulate a question that elicits missing intelligence (e.g. UPI ID,
    phone number, or link) without revealing awareness of the scam.
    """
    # Gather last 3 scammer messages for context
    scammer_msgs = [
        m.get("content", "")
        for m in (recent_messages or [])[-6:]
        if m.get("role") in ("user", "scammer")
    ][-3:]

    # Identify which intel is still missing
    missing: List[str] = []
    if not extracted_intel.phone_numbers:
        missing.append("phone number")
    if not extracted_intel.upi_ids:
        missing.append("UPI ID")
    if not extracted_intel.email_addresses:
        missing.append("email address")
    if not extracted_intel.bank_accounts:
        missing.append("bank account")

    if not missing:
        return None

    # Pick the highest-priority missing item
    target = missing[0]

    # Build probe conditioned on recent context
    context_snippet = scammer_msgs[-1][:60] if scammer_msgs else ""

    if context_snippet:
        topic_map = {
            "phone number": f"Aapne abhi kaha '{context_snippet}...' \u2014 sir agar call drop ho jaye toh aapka direct number kya hai?",
            "UPI ID": f"Sir maine samjha ki '{context_snippet}...' \u2014 payment karne ke liye aapka UPI ID batao na?",
            "email address": f"Sir '{context_snippet}...' ke baare mein \u2014 kya aap email pe bhi details bhej sakte hain? Email ID batao na?",
            "bank account": f"Sir aapne kaha '{context_snippet}...' \u2014 verification ke liye account number chahiye, batao na?",
        }
    else:
        topic_map = {
            "phone number": "Sir agar call drop ho jaye toh aapka direct number kya hai?",
            "UPI ID": "Sir payment karne ke liye aapka UPI ID batao na?",
            "email address": "Sir kya aap email pe bhi details bhej sakte hain? Email ID batao na?",
            "bank account": "Sir verification ke liye account number chahiye, batao na?",
        }

    # Higher confidence → more assertive phrasing
    probe = topic_map.get(target)
    if probe and confidence >= 0.8:
        probe = probe.replace("batao na?", "batao, jaldi karna padega.")

    return probe
