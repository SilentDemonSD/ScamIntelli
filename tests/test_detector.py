import pytest
from src.scam_detector.classifier import (
    detect_scam,
    calculate_keyword_score,
    calculate_intent_score,
    calculate_pattern_score,
    get_matched_keywords
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
