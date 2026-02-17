import logging
import re
from typing import Any, Dict, FrozenSet, List, Optional

from src.models import ExtractedIntelligence
from src.utils.validation import normalize_phone_number, normalize_upi_id

logger = logging.getLogger(__name__)

_PATTERNS = {}


def _get_pattern(name: str) -> re.Pattern:
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

    if has_bank_context:
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
            if len(match) >= 9 and match not in references:
                references.append(match)

    return references


async def extract_all_intelligence(
    message: str, existing: ExtractedIntelligence
) -> ExtractedIntelligence:
    """Extract all intelligence entities from a message, merging with existing intel.

    Wraps each extraction step in try/except so a single failure doesn't
    discard partial results.
    """
    emails: List[str] = []
    upi_ids: List[str] = []
    phone_numbers: List[str] = []
    links: List[str] = []
    bank_refs: List[str] = []
    keywords: List[str] = []

    try:
        emails = await extract_emails(message)
    except Exception:
        logger.exception("Email extraction failed; continuing with empty list")

    try:
        upi_ids = await extract_upi_ids(message, known_emails=emails)
    except Exception:
        logger.exception("UPI extraction failed; continuing with empty list")

    try:
        phone_numbers = await extract_phone_numbers(message)
    except Exception:
        logger.exception("Phone extraction failed; continuing with empty list")

    try:
        links = await extract_links(message)
    except Exception:
        logger.exception("Link extraction failed; continuing with empty list")

    try:
        all_known_phones = list(set(existing.phone_numbers + phone_numbers))
        bank_refs = await extract_bank_references(message, all_known_phones)
    except Exception:
        logger.exception("Bank reference extraction failed; continuing with empty list")

    try:
        from src.scam_detector.classifier import get_matched_keywords
        keywords = await get_matched_keywords(message)
    except Exception:
        logger.exception("Keyword extraction failed; continuing with empty list")

    return ExtractedIntelligence(
        upi_ids=list(set(existing.upi_ids + upi_ids)),
        phone_numbers=list(set(existing.phone_numbers + phone_numbers)),
        phishing_links=list(set(existing.phishing_links + links)),
        bank_accounts=list(set(existing.bank_accounts + bank_refs)),
        email_addresses=list(set(existing.email_addresses + emails)),
        suspicious_keywords=list(set(existing.suspicious_keywords + keywords)),
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
