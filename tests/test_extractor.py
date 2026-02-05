import pytest

from src.intelligence_extractor.extractor import (
    extract_all_intelligence,
    extract_bank_references,
    extract_links,
    extract_phone_numbers,
    extract_upi_ids,
    has_sufficient_intelligence,
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
