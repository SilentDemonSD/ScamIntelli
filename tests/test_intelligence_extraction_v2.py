"""
Comprehensive tests for enhanced intelligence extraction (v2).

Tests coverage for all entity types including new additions:
- Case IDs, Policy Numbers, Order Numbers
- Organization Names, Addresses
- Employee IDs, Names Mentioned
"""

import pytest

from src.intelligence_extractor.extractor import (
    extract_all_intelligence,
    extract_case_ids,
    extract_employee_ids,
    extract_names_mentioned,
    extract_order_numbers,
    extract_organization_names,
    extract_policy_numbers,
)
from src.models import ExtractedIntelligence


# ---------------------------------------------------------------------------
# Case ID extraction
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_extract_case_ids_standard():
    """Extract case IDs in common formats."""
    test_cases = [
        ("Your case ID is CASE12345", ["CASE12345"]),
        ("FIR number FIR/123/2024 has been registered", ["FIR/123/2024"]),
        ("Reference number REF-2024-ABC-789", ["REF-2024-ABC-789"]),
        ("Complaint CMP2024-001 under investigation", ["CMP2024-001", "COMPLAINT CMP2024-001"]),
    ]
    for message, expected in test_cases:
        result = await extract_case_ids(message)
        assert any(exp_id in result for exp_id in expected), (
            f"Failed to extract any of {expected} from '{message}', got {result}"
        )


@pytest.mark.asyncio
async def test_extract_case_ids_empty_message():
    """No case IDs from an unrelated message."""
    result = await extract_case_ids("Hello, how are you?")
    assert result == []


@pytest.mark.asyncio
async def test_extract_case_ids_multiple():
    """Multiple case IDs in one message."""
    msg = "Refer to CASE-111 and also FIR/456/2024 for your matter."
    result = await extract_case_ids(msg)
    assert len(result) >= 2


# ---------------------------------------------------------------------------
# Policy number extraction
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_extract_policy_numbers():
    """Extract insurance-style policy numbers."""
    msg = "Your policy POL12345678 is expiring. Also check LIC-2024-99999."
    result = await extract_policy_numbers(msg)
    assert len(result) >= 1


@pytest.mark.asyncio
async def test_extract_policy_numbers_empty():
    """No results for unrelated text."""
    result = await extract_policy_numbers("The weather is nice today.")
    assert result == []


# ---------------------------------------------------------------------------
# Order number extraction
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_extract_order_numbers():
    """Extract e-commerce order numbers."""
    msg = "Your order ORD-2024-12345 has been seized at customs."
    result = await extract_order_numbers(msg)
    assert len(result) >= 1


@pytest.mark.asyncio
async def test_extract_order_numbers_empty():
    result = await extract_order_numbers("Good morning sir")
    assert result == []


# ---------------------------------------------------------------------------
# Organization name extraction
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_extract_organization_names_banks():
    """Detect major Indian bank names."""
    test_cases = [
        ("I'm calling from SBI Bank fraud department", ["SBI"]),
        ("This is ICICI customer care", ["ICICI"]),
        ("HDFC Bank security division here", ["HDFC"]),
    ]
    for message, expected in test_cases:
        result = await extract_organization_names(message)
        assert len(result) >= 1, f"Failed to extract org from '{message}'"


@pytest.mark.asyncio
async def test_extract_organization_names_government():
    """Detect government agencies."""
    test_cases = [
        "CBI investigation team here",
        "Income Tax Department notice",
        "This is from the RBI",
    ]
    for message in test_cases:
        result = await extract_organization_names(message)
        assert len(result) >= 1, f"Failed to extract org from '{message}'"


@pytest.mark.asyncio
async def test_extract_organization_names_empty():
    result = await extract_organization_names("Hello bhai, kaise ho?")
    assert result == []


# ---------------------------------------------------------------------------
# Employee ID extraction
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_extract_employee_ids():
    """Extract employee/badge ID patterns."""
    msg = "My badge ID is CBI-12345 and officer ID is EMP/6789."
    result = await extract_employee_ids(msg)
    assert len(result) >= 1


@pytest.mark.asyncio
async def test_extract_employee_ids_empty():
    result = await extract_employee_ids("Aap kaun ho?")
    assert result == []


# ---------------------------------------------------------------------------
# Names mentioned extraction
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_extract_names_mentioned():
    """Extract person names from text."""
    msg = "This is Officer Sharma speaking. Inspector Verma is also on the case."
    result = await extract_names_mentioned(msg)
    assert len(result) >= 1


@pytest.mark.asyncio
async def test_extract_names_mr_ms():
    msg = "Mr. Rajesh Kumar and Mrs. Priya Singh are witnesses."
    result = await extract_names_mentioned(msg)
    assert len(result) >= 1


# ---------------------------------------------------------------------------
# Comprehensive extraction
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_comprehensive_extraction():
    """Full extract_all_intelligence with multiple entity types."""
    message = """
    This is Officer Sharma from CBI, badge ID CBI-12345.
    Your case number is CASE-2024-789.
    You must pay 5000 to UPI scammer@paytm.
    Call me back at +91-9876543210 or email cbi.fake@scam.com.
    """
    existing = ExtractedIntelligence()
    result = await extract_all_intelligence(message, existing)

    assert len(result.upi_ids) >= 1, "Failed to extract UPI ID"
    assert len(result.phone_numbers) >= 1, "Failed to extract phone"
    assert len(result.email_addresses) >= 1, "Failed to extract email"
    assert len(result.case_ids) >= 1, "Failed to extract case ID"
    assert len(result.employee_ids) >= 1, "Failed to extract employee ID"
    assert len(result.organization_names) >= 1, "Failed to extract organization"
    assert len(result.names_mentioned) >= 1, "Failed to extract name"


@pytest.mark.asyncio
async def test_extraction_accumulates():
    """Intel from multiple messages accumulates correctly."""
    intel = ExtractedIntelligence()
    intel = await extract_all_intelligence(
        "Call me at +91-9876543210", intel
    )
    intel = await extract_all_intelligence(
        "Pay to UPI id fraud@upi", intel
    )
    assert len(intel.phone_numbers) >= 1
    assert len(intel.upi_ids) >= 1


@pytest.mark.asyncio
async def test_extraction_no_duplicates():
    """Same phone number should not be duplicated across calls."""
    intel = ExtractedIntelligence()
    intel = await extract_all_intelligence(
        "Call +91-9876543210 now", intel
    )
    phone_count_1 = len(intel.phone_numbers)
    intel = await extract_all_intelligence(
        "I repeat: +91-9876543210", intel
    )
    assert len(intel.phone_numbers) == phone_count_1


@pytest.mark.asyncio
async def test_extraction_empty_message():
    """Empty message returns unchanged intel."""
    intel = ExtractedIntelligence()
    result = await extract_all_intelligence("", intel)
    assert result.phone_numbers == []
    assert result.upi_ids == []
    assert result.case_ids == []


@pytest.mark.asyncio
async def test_extraction_preserves_existing():
    """Existing intel is preserved across calls."""
    intel = ExtractedIntelligence(phone_numbers=["9999999999"])
    result = await extract_all_intelligence("Hello there", intel)
    assert "9999999999" in result.phone_numbers


@pytest.mark.asyncio
async def test_extract_digital_arrest_scenario():
    """Full digital arrest scenario with mixed entities."""
    msg = (
        "Yeh Inspector Rajan bol raha hun CBI se. "
        "Aapke naam pe FIR/2024/DIG-001 register hua hai. "
        "Fine 25000 pay karo UPI pe crook@ybl "
        "nahi toh arrest ho jaoge. "
        "Call back on +91-9801234567."
    )
    intel = ExtractedIntelligence()
    result = await extract_all_intelligence(msg, intel)
    assert len(result.phone_numbers) >= 1
    assert len(result.upi_ids) >= 1
    assert len(result.case_ids) >= 1
    assert len(result.organization_names) >= 1
    assert len(result.names_mentioned) >= 1


@pytest.mark.asyncio
async def test_kyc_scam_scenario():
    """KYC phishing scenario entities."""
    msg = (
        "Your SBI account will be blocked. "
        "Click http://sbi-kyc-update.fake.com to update KYC. "
        "Contact officer at 9123456789."
    )
    intel = ExtractedIntelligence()
    result = await extract_all_intelligence(msg, intel)
    assert len(result.phishing_links) >= 1
    assert len(result.phone_numbers) >= 1
    assert len(result.organization_names) >= 1
