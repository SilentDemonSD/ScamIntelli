import pytest

from src.scam_detector.classifier import (
    calculate_intent_score,
    calculate_keyword_score,
    calculate_pattern_score,
    detect_scam,
    get_matched_keywords,
)
from src.scam_detector.keywords import get_all_scam_keywords, get_keyword_categories


@pytest.mark.asyncio
async def test_detect_scam_positive():
    message = "Your account will be blocked immediately! Verify your UPI ID now at fraudster@ybl"

    result = await detect_scam(message)

    assert result.is_scam is True
    assert result.total_score >= 0.7


@pytest.mark.asyncio
async def test_detect_scam_negative():
    message = "Hello, how are you doing today?"

    result = await detect_scam(message)

    assert result.is_scam is False
    assert result.total_score < 0.7


@pytest.mark.asyncio
async def test_calculate_keyword_score_with_matches():
    message = "Your account is blocked. Update KYC immediately."

    score, keywords = await calculate_keyword_score(message)

    assert score > 0
    assert len(keywords) > 0
    assert any(kw in ["account blocked", "immediately", "kyc"] for kw in keywords)


@pytest.mark.asyncio
async def test_calculate_keyword_score_no_matches():
    message = "The weather is nice today."

    score, keywords = await calculate_keyword_score(message)

    assert score == 0.0
    assert len(keywords) == 0


@pytest.mark.asyncio
async def test_calculate_intent_score_high():
    message = "Legal action will be taken. Your account is suspended. Share OTP now."

    score = await calculate_intent_score(message)

    assert score > 0.5


@pytest.mark.asyncio
async def test_calculate_pattern_score_with_upi():
    message = "Send money to scammer@ybl immediately"

    score = await calculate_pattern_score(message)

    assert score >= 0.3


@pytest.mark.asyncio
async def test_calculate_pattern_score_with_link():
    message = "Click here https://fake-bank.com/verify"

    score = await calculate_pattern_score(message)

    assert score >= 0.2


@pytest.mark.asyncio
async def test_get_matched_keywords():
    message = "Urgent! Your bank account is blocked. Call customer care."

    keywords = await get_matched_keywords(message)

    assert len(keywords) > 0


def test_get_all_scam_keywords():
    keywords = get_all_scam_keywords()

    assert len(keywords) > 50
    assert "urgent" in keywords
    assert "account blocked" in keywords


def test_get_keyword_categories():
    categories = get_keyword_categories()

    assert "urgency" in categories
    assert "threat" in categories
    assert "payment" in categories
    assert "credential" in categories


@pytest.mark.asyncio
async def test_sbi_account_compromised_detected_as_scam():
    """Regression: 'Your SBI account is compromised. Call +91-...' must be scam."""
    from src.scam_detector.hybrid_engine import HybridScamDetectionEngine

    message = "Your SBI account is compromised. Call +91-9876543210."
    result = await HybridScamDetectionEngine.detect(message)

    assert result.is_scam is True
    assert result.confidence >= 0.7
    assert result.has_hard_indicators is True


@pytest.mark.asyncio
async def test_bank_name_with_threat_keyword_detected():
    """Bank name + threat keyword must produce keyword_score > 0."""
    score, matched = await calculate_keyword_score(
        "Your HDFC account has been hacked. Contact us immediately."
    )

    assert score > 0.1
    assert any(kw in matched for kw in ("hdfc", "hacked"))


@pytest.mark.asyncio
async def test_hard_indicators_bypass_early_return():
    """Messages with phone numbers should NOT be short-circuited by early gate."""
    from src.scam_detector.hybrid_engine import HybridScamDetectionEngine

    message = "Call +91-9876543210 for account verification."
    result = await HybridScamDetectionEngine.detect(message)

    assert len(result.detection_layers_used) > 1
    assert result.has_hard_indicators is True


@pytest.mark.asyncio
async def test_benign_sbi_mention_not_scam():
    """Casual mention of a bank should NOT trigger false positive."""
    from src.scam_detector.hybrid_engine import HybridScamDetectionEngine

    message = "I have an SBI account for savings."
    result = await HybridScamDetectionEngine.detect(message)

    assert result.is_scam is False
