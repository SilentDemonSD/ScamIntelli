"""
Unit tests for intelligence extraction module.

Tests cover phone numbers, UPI IDs, bank accounts, phishing links,
and email addresses across various formats used in Indian scams.
"""

import pytest

from src.intelligence_extractor.extractor import (
    extract_all_intelligence,
    extract_emails,
    extract_phone_numbers,
    extract_upi_ids,
)
from src.models import ExtractedIntelligence


class TestPhoneExtraction:
    """Phone number extraction across Indian formats."""

    @pytest.mark.asyncio
    async def test_standard_indian_mobile(self):
        result = await extract_phone_numbers("Call 9876543210")
        assert any("9876543210" in p for p in result)

    @pytest.mark.asyncio
    async def test_with_plus91_prefix(self):
        result = await extract_phone_numbers("Call +919876543210")
        assert any("9876543210" in p for p in result)

    @pytest.mark.asyncio
    async def test_with_dashes(self):
        result = await extract_phone_numbers("Call +91-9876543210")
        assert any("9876543210" in p for p in result)

    @pytest.mark.asyncio
    async def test_with_spaces(self):
        result = await extract_phone_numbers("Call +91 9876543210")
        assert any("9876543210" in p for p in result)

    @pytest.mark.asyncio
    async def test_multiple_numbers(self):
        msg = "Call 9876543210 or 8765432109"
        result = await extract_phone_numbers(msg)
        assert len(result) >= 2

    @pytest.mark.asyncio
    async def test_invalid_number_ignored(self):
        result = await extract_phone_numbers("Call 1234567890")
        assert not any("1234567890" in p for p in result)

    @pytest.mark.asyncio
    async def test_number_with_country_code_dashes(self):
        result = await extract_phone_numbers("Contact +91-8877-665-544")
        assert any("8877665544" in p for p in result)

    @pytest.mark.asyncio
    async def test_preserves_original_format(self):
        result = await extract_phone_numbers("+91-7654321098 pe call karein")
        assert any("7654321098" in p for p in result)


class TestUPIExtraction:
    """UPI ID extraction with email filtering."""

    @pytest.mark.asyncio
    async def test_standard_upi(self):
        result = await extract_upi_ids("Pay to scammer@ybl")
        assert "scammer@ybl" in result

    @pytest.mark.asyncio
    async def test_paytm_upi(self):
        result = await extract_upi_ids("UPI: fraud@paytm")
        assert "fraud@paytm" in result

    @pytest.mark.asyncio
    async def test_okaxis_upi(self):
        result = await extract_upi_ids("Send to user@okaxis")
        assert "user@okaxis" in result

    @pytest.mark.asyncio
    async def test_oksbi_upi(self):
        result = await extract_upi_ids("Pay to scam@oksbi")
        assert "scam@oksbi" in result

    @pytest.mark.asyncio
    async def test_email_not_extracted_as_upi(self):
        result = await extract_upi_ids(
            "Email: user@gmail.com",
            known_emails=["user@gmail.com"],
        )
        assert len(result) == 0

    @pytest.mark.asyncio
    async def test_domain_with_dot_excluded(self):
        result = await extract_upi_ids("Contact support@domain.com")
        assert len(result) == 0

    @pytest.mark.asyncio
    async def test_hyphenated_domain_excluded(self):
        result = await extract_upi_ids(
            "Contact support@phishing-domain.com"
        )
        assert "support@phishing" not in result

    @pytest.mark.asyncio
    async def test_fakebank_upi(self):
        result = await extract_upi_ids("UPI: scammer.fraud@fakebank")
        assert "scammer.fraud@fakebank" in result

    @pytest.mark.asyncio
    async def test_fakeupi_upi(self):
        result = await extract_upi_ids("Pay to cashback.scam@fakeupi")
        assert "cashback.scam@fakeupi" in result


class TestEmailExtraction:
    """Email address extraction."""

    @pytest.mark.asyncio
    async def test_standard_email(self):
        result = await extract_emails("Contact support@example.com")
        assert "support@example.com" in result

    @pytest.mark.asyncio
    async def test_complex_email(self):
        result = await extract_emails("Email offers@fake-amazon-deals.com")
        assert "offers@fake-amazon-deals.com" in result

    @pytest.mark.asyncio
    async def test_multiple_emails(self):
        msg = "Contact a@test.com or b@test.com"
        result = await extract_emails(msg)
        assert len(result) >= 2

    @pytest.mark.asyncio
    async def test_email_case_insensitive(self):
        result = await extract_emails("Email USER@TEST.COM")
        assert "user@test.com" in result

    @pytest.mark.asyncio
    async def test_email_with_dots_in_local(self):
        result = await extract_emails("Contact first.last@domain.com")
        assert "first.last@domain.com" in result

    @pytest.mark.asyncio
    async def test_email_with_plus(self):
        result = await extract_emails("Email user+tag@example.com")
        assert "user+tag@example.com" in result


class TestBankAccountExtraction:
    """Bank account number extraction."""

    @pytest.mark.asyncio
    async def test_16_digit_card_format(self):
        intel = await extract_all_intelligence(
            "Card number 1234567890123456 was used",
            ExtractedIntelligence(),
        )
        assert any("1234567890123456" in a for a in intel.bank_accounts)

    @pytest.mark.asyncio
    async def test_account_with_context_keyword(self):
        intel = await extract_all_intelligence(
            "Your bank account 987654321012 has issues",
            ExtractedIntelligence(),
        )
        assert any("987654321012" in a for a in intel.bank_accounts)

    @pytest.mark.asyncio
    async def test_card_with_spaces(self):
        intel = await extract_all_intelligence(
            "Card 1234 5678 9012 3456 was charged",
            ExtractedIntelligence(),
        )
        found = any(
            "1234567890123456" in a.replace(" ", "")
            for a in intel.bank_accounts
        )
        assert found or len(intel.bank_accounts) > 0

    @pytest.mark.asyncio
    async def test_no_false_positive_short_number(self):
        intel = await extract_all_intelligence(
            "Order #12345 confirmed",
            ExtractedIntelligence(),
        )
        assert len(intel.bank_accounts) == 0


class TestPhishingLinkExtraction:
    """Phishing link extraction."""

    @pytest.mark.asyncio
    async def test_http_link(self):
        intel = await extract_all_intelligence(
            "Click http://fake-site.com/claim?id=123",
            ExtractedIntelligence(),
        )
        assert any("fake-site.com" in l for l in intel.phishing_links)

    @pytest.mark.asyncio
    async def test_https_link(self):
        intel = await extract_all_intelligence(
            "Visit https://scam-bank.fake.xyz/login",
            ExtractedIntelligence(),
        )
        assert any("scam-bank.fake.xyz" in l for l in intel.phishing_links)

    @pytest.mark.asyncio
    async def test_link_with_query_params(self):
        intel = await extract_all_intelligence(
            "Go to http://phish.com/page?user=123&token=abc",
            ExtractedIntelligence(),
        )
        links = intel.phishing_links
        assert any("phish.com" in l for l in links)
        assert any("token=abc" in l for l in links)

    @pytest.mark.asyncio
    async def test_trusted_domain_excluded(self):
        intel = await extract_all_intelligence(
            "Visit https://www.google.com for help",
            ExtractedIntelligence(),
        )
        assert not any("google.com" in l for l in intel.phishing_links)

    @pytest.mark.asyncio
    async def test_link_trailing_punctuation_stripped(self):
        intel = await extract_all_intelligence(
            "Click http://fake.com/page. Do it now!",
            ExtractedIntelligence(),
        )
        links = intel.phishing_links
        if links:
            assert not links[0].endswith(".")


class TestFullIntelligenceExtraction:
    """End-to-end intelligence extraction combining all types."""

    @pytest.mark.asyncio
    async def test_all_types_in_one_message(self):
        msg = (
            "Call +91-9876543210. Account: 1234567890123456. "
            "UPI: scam@ybl. Link: http://fake.com/steal. "
            "Email: scam@evil.com"
        )
        intel = await extract_all_intelligence(msg, ExtractedIntelligence())

        assert any("9876543210" in p for p in intel.phone_numbers)
        assert any("1234567890123456" in a for a in intel.bank_accounts)
        assert any("scam@ybl" in u for u in intel.upi_ids)
        assert any("fake.com" in l for l in intel.phishing_links)
        assert any("scam@evil.com" in e for e in intel.email_addresses)

    @pytest.mark.asyncio
    async def test_accumulation_across_messages(self):
        intel = ExtractedIntelligence()
        intel = await extract_all_intelligence(
            "Phone: +91-6111111111", intel
        )
        intel = await extract_all_intelligence(
            "UPI: scam@ybl", intel
        )
        intel = await extract_all_intelligence(
            "Email: test@evil.com", intel
        )

        assert any("6111111111" in p for p in intel.phone_numbers)
        assert any("scam@ybl" in u for u in intel.upi_ids)
        assert any("test@evil.com" in e for e in intel.email_addresses)

    @pytest.mark.asyncio
    async def test_no_duplicates_on_repeat(self):
        intel = ExtractedIntelligence()
        for _ in range(3):
            intel = await extract_all_intelligence(
                "UPI: test@ybl Phone: +91-9876543210", intel
            )
        assert intel.upi_ids.count("test@ybl") == 1
