import pytest

from src.intelligence_extractor.extractor import (
    extract_all_intelligence,
    extract_bank_references,
    extract_links,
    extract_phone_numbers,
    extract_upi_ids,
    has_sufficient_intelligence,
    make_context_aware_probe,
)
from src.models import ExtractedIntelligence


@pytest.mark.asyncio
async def test_extract_upi_ids_valid():
    message = "Send money to fraudster@ybl or scammer@paytm"

    upi_ids = await extract_upi_ids(message)

    assert len(upi_ids) == 2
    assert "fraudster@ybl" in upi_ids
    assert "scammer@paytm" in upi_ids


@pytest.mark.asyncio
async def test_extract_upi_ids_filters_email():
    message = "Contact me at user@gmail.com or send to user@ybl"

    upi_ids = await extract_upi_ids(message)

    assert len(upi_ids) == 1
    assert "user@ybl" in upi_ids
    assert "user@gmail.com" not in upi_ids


@pytest.mark.asyncio
async def test_extract_phone_numbers_valid():
    message = "Call me at +919876543210 or 9123456789"

    phones = await extract_phone_numbers(message)

    assert len(phones) >= 1
    assert any("+91" in phone for phone in phones)


@pytest.mark.asyncio
async def test_extract_phone_numbers_invalid():
    message = "The code is 12345"

    phones = await extract_phone_numbers(message)

    assert len(phones) == 0


@pytest.mark.asyncio
async def test_extract_links_suspicious():
    message = "Click here https://fake-bank.com/verify to update"

    links = await extract_links(message)

    assert len(links) == 1
    assert "fake-bank.com" in links[0]


@pytest.mark.asyncio
async def test_extract_links_filters_trusted():
    message = "Visit https://google.com for more info"

    links = await extract_links(message)

    assert len(links) == 0


@pytest.mark.asyncio
async def test_extract_bank_references():
    message = "Your card ending 1234 5678 9012 3456 needs verification"

    refs = await extract_bank_references(message)

    assert len(refs) >= 1


@pytest.mark.asyncio
async def test_extract_all_intelligence():
    message = "Send money to scammer@ybl immediately. Call +919876543210. Visit http://fake.com"
    existing = ExtractedIntelligence()

    intel = await extract_all_intelligence(message, existing)

    assert len(intel.upi_ids) >= 1
    assert len(intel.phone_numbers) >= 1
    assert len(intel.phishing_links) >= 1


@pytest.mark.asyncio
async def test_has_sufficient_intelligence_true():
    intel = ExtractedIntelligence(
        upi_ids=["fraud@upi"], phishing_links=["http://fake.com"]
    )

    result = await has_sufficient_intelligence(intel)

    assert result is True


@pytest.mark.asyncio
async def test_has_sufficient_intelligence_false():
    intel = ExtractedIntelligence()

    result = await has_sufficient_intelligence(intel)

    assert result is False


# ── Smoke tests for context-aware probing and extraction resilience ──


def test_context_aware_probe_returns_question_when_intel_missing():
    """Probe should return a targeted question when phone number is missing."""
    messages = [
        {"role": "scammer", "content": "Your account will be blocked immediately"},
    ]
    intel = ExtractedIntelligence()  # nothing extracted yet

    probe = make_context_aware_probe(messages, intel, confidence=0.7)

    assert probe is not None
    assert "?" in probe or "batao" in probe


def test_context_aware_probe_returns_none_when_intel_complete():
    """Probe should return None when all intel types are already collected."""
    intel = ExtractedIntelligence(
        phone_numbers=["+919876543210"],
        upi_ids=["fraud@ybl"],
        email_addresses=["x@y.com"],
        bank_accounts=["123456789"],
    )
    probe = make_context_aware_probe([], intel, confidence=0.9)
    assert probe is None


def test_context_aware_probe_handles_empty_messages():
    """Probe should still return a clean question even when no messages exist."""
    intel = ExtractedIntelligence()  # all intel missing
    probe = make_context_aware_probe([], intel, confidence=0.6)
    assert probe is not None
    # Must not contain empty-quote artifacts like "'...'"
    assert "'...'" not in probe
    assert "''" not in probe


def test_context_aware_probe_assertive_at_high_confidence():
    """When confidence >= 0.8, templates with 'batao na?' should become assertive."""
    intel = ExtractedIntelligence(phone_numbers=["+919876543210"])  # phone present, UPI missing → target = "UPI ID"
    messages = [{"role": "scammer", "content": "Send money now"}]
    probe = make_context_aware_probe(messages, intel, confidence=0.85)
    assert probe is not None
    assert "jaldi karna padega" in probe
    assert "batao na?" not in probe


def test_context_aware_probe_not_assertive_at_low_confidence():
    """When confidence < 0.8, templates should keep the polite phrasing."""
    intel = ExtractedIntelligence(phone_numbers=["+919876543210"])  # UPI missing
    messages = [{"role": "scammer", "content": "Send money now"}]
    probe = make_context_aware_probe(messages, intel, confidence=0.5)
    assert probe is not None
    assert "batao na?" in probe


@pytest.mark.asyncio
async def test_extract_all_intelligence_no_unhandled_exception():
    """Extraction must never raise; partial failures return empty fields."""
    # Even with garbage input, extract_all_intelligence should not throw
    intel = await extract_all_intelligence("", ExtractedIntelligence())
    assert isinstance(intel, ExtractedIntelligence)


def test_context_aware_probe_prioritizes_phone_first():
    """When all intel is missing, phone number should be the first target."""
    intel = ExtractedIntelligence()
    messages = [{"role": "scammer", "content": "Hello sir how are you"}]
    probe = make_context_aware_probe(messages, intel, confidence=0.6)
    assert probe is not None
    # Phone is first in priority list → probe should ask about phone/number
    assert "number" in probe.lower()


def test_context_aware_probe_skips_to_next_when_phone_present():
    """When phone is present but UPI is missing, probe should target UPI."""
    intel = ExtractedIntelligence(phone_numbers=["+919876543210"])
    messages = [{"role": "scammer", "content": "Send payment now"}]
    probe = make_context_aware_probe(messages, intel, confidence=0.6)
    assert probe is not None
    assert "upi" in probe.lower()
