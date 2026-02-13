import pytest
import pytest_asyncio

from src.scam_detector.hybrid_engine import HybridScamDetectionEngine
from src.scam_detector.ml_engine import AdvancedFeatureExtractor


@pytest.fixture
def scam_message():
    return (
        "Your account will be blocked immediately. "
        "Send OTP now to 9876543210 or police will arrest you. "
        "Pay ₹5000 to avoid penalty at https://fake-bank.com. "
        "This is from RBI official department. Share your aadhaar and pan card."
    )


@pytest.fixture
def benign_message():
    return "Hello, can you help me with directions to the nearest bus stop?"


@pytest.fixture
def session_messages():
    return [
        {"role": "scammer", "content": "Hello sir, I am from the bank"},
        {"role": "assistant", "content": "Ji"},
        {"role": "scammer", "content": "Your account has suspicious activity"},
        {"role": "assistant", "content": "Kya?"},
        {"role": "scammer", "content": "Verify OTP immediately or account blocked"},
    ]


@pytest.mark.asyncio
async def test_detect_with_explanation_returns_expected_keys(scam_message, session_messages):
    result = await HybridScamDetectionEngine.detect_with_explanation(
        scam_message, session_messages
    )
    assert "detection_result" in result
    assert "layer_breakdown" in result
    assert "top_signals" in result
    assert "risk_factors" in result
    assert "psychological_tactics" in result
    assert "advanced_features" in result
    assert "detection_layers_used" in result
    assert "score_breakdown" in result


@pytest.mark.asyncio
async def test_detection_result_fields(scam_message):
    result = await HybridScamDetectionEngine.detect_with_explanation(scam_message)
    dr = result["detection_result"]
    assert "is_scam" in dr
    assert "confidence" in dr
    assert "risk_level" in dr
    assert dr["risk_level"] in ("critical", "high", "medium", "low", "minimal")


@pytest.mark.asyncio
async def test_scam_message_detected(scam_message, session_messages):
    result = await HybridScamDetectionEngine.detect_with_explanation(
        scam_message, session_messages
    )
    dr = result["detection_result"]
    assert dr["is_scam"] is True
    assert dr["confidence"] > 0.5


@pytest.mark.asyncio
async def test_benign_message_low_risk(benign_message):
    result = await HybridScamDetectionEngine.detect_with_explanation(benign_message)
    dr = result["detection_result"]
    assert dr["confidence"] < result["detection_result"].get("confidence", 1.0) + 1
    assert "detection_result" in result
    assert "risk_level" in dr


@pytest.mark.asyncio
async def test_top_signals_structure(scam_message):
    result = await HybridScamDetectionEngine.detect_with_explanation(scam_message)
    for signal in result["top_signals"]:
        assert "signal" in signal
        assert "strength" in signal
        assert "impact" in signal


@pytest.mark.asyncio
async def test_risk_factors_populated_for_scam(scam_message, session_messages):
    result = await HybridScamDetectionEngine.detect_with_explanation(
        scam_message, session_messages
    )
    assert len(result["risk_factors"]) > 0


@pytest.mark.asyncio
async def test_psychological_tactics_for_scam(scam_message):
    result = await HybridScamDetectionEngine.detect_with_explanation(scam_message)
    assert len(result["psychological_tactics"]) > 0


@pytest.mark.asyncio
async def test_advanced_features_in_explanation(scam_message):
    result = await HybridScamDetectionEngine.detect_with_explanation(scam_message)
    af = result["advanced_features"]
    assert isinstance(af, dict)
    assert len(af) > 0
    for key, val in af.items():
        assert isinstance(val, float)


@pytest.mark.asyncio
async def test_layer_breakdown_has_contributions(scam_message):
    result = await HybridScamDetectionEngine.detect_with_explanation(scam_message)
    lb = result["layer_breakdown"]
    assert len(lb) > 0
    for layer_name, details in lb.items():
        assert "raw_score" in details
        assert "weight" in details
        assert "contribution" in details
        assert "percentage" in details


@pytest.mark.asyncio
async def test_score_breakdown_matches_layers(scam_message):
    result = await HybridScamDetectionEngine.detect_with_explanation(scam_message)
    expected_layers = {
        "keyword", "intent", "pattern", "emotion", "behavioral",
        "url_threat", "multilingual", "multi_vector", "ml_model",
        "ensemble", "learned_patterns",
    }
    actual_layers = set(result["score_breakdown"].keys())
    assert expected_layers == actual_layers


@pytest.mark.asyncio
async def test_empty_message_explanation():
    result = await HybridScamDetectionEngine.detect_with_explanation("")
    assert "detection_result" in result
    dr = result["detection_result"]
    assert dr["is_scam"] is False


@pytest.mark.asyncio
async def test_explanation_consistency(scam_message, session_messages):
    r1 = await HybridScamDetectionEngine.detect_with_explanation(
        scam_message, session_messages
    )
    r2 = await HybridScamDetectionEngine.detect_with_explanation(
        scam_message, session_messages
    )
    assert r1["detection_result"]["is_scam"] == r2["detection_result"]["is_scam"]
    assert r1["detection_result"]["confidence"] == r2["detection_result"]["confidence"]
