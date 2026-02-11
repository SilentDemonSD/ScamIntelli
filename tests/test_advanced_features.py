import pytest

from src.scam_detector.ml_engine import (
    ADVANCED_FEATURE_NAMES,
    AdvancedFeatureExtractor,
)


@pytest.fixture
def scam_message():
    return (
        "Sir your account will be blocked immediately! "
        "Send OTP now or police will arrest you. "
        "Pay ₹5000 to avoid penalty. Call 9876543210. "
        "This is from RBI official department."
    )


@pytest.fixture
def benign_message():
    return "Hello, I wanted to ask about the weather today."


@pytest.fixture
def session_messages():
    return [
        {"role": "scammer", "content": "Hello sir, this is bank calling"},
        {"role": "assistant", "content": "Ji kahiye"},
        {"role": "scammer", "content": "Your account has been compromised"},
        {"role": "assistant", "content": "Kya hua?"},
        {"role": "scammer", "content": "Send OTP immediately or account will be blocked"},
        {"role": "assistant", "content": "OTP kya hai?"},
    ]


def test_extract_returns_all_features(scam_message):
    features = AdvancedFeatureExtractor.extract_advanced_features(scam_message)
    assert isinstance(features, dict)
    for name in ADVANCED_FEATURE_NAMES:
        assert name in features, f"Missing feature: {name}"


def test_feature_count():
    assert len(ADVANCED_FEATURE_NAMES) == 40


def test_all_features_are_floats(scam_message):
    features = AdvancedFeatureExtractor.extract_advanced_features(scam_message)
    for name, value in features.items():
        assert isinstance(value, float), f"{name} is {type(value)}, expected float"


def test_features_bounded_zero_to_one(scam_message, session_messages):
    features = AdvancedFeatureExtractor.extract_advanced_features(
        scam_message, session_messages
    )
    for name, value in features.items():
        assert 0.0 <= value <= 1.0, f"{name}={value} out of [0, 1] range"


def test_scam_message_higher_scores(scam_message, benign_message):
    scam_features = AdvancedFeatureExtractor.extract_advanced_features(scam_message)
    benign_features = AdvancedFeatureExtractor.extract_advanced_features(benign_message)

    assert scam_features["psych_fear_appeal_score"] > benign_features["psych_fear_appeal_score"]
    assert scam_features["psych_authority_claim_score"] >= benign_features["psych_authority_claim_score"]


def test_temporal_features_with_session(scam_message, session_messages):
    features_no_session = AdvancedFeatureExtractor.extract_advanced_features(scam_message)
    features_with_session = AdvancedFeatureExtractor.extract_advanced_features(
        scam_message, session_messages
    )
    assert features_with_session["temporal_msg_rate"] > features_no_session["temporal_msg_rate"]


def test_linguistic_features(scam_message):
    features = AdvancedFeatureExtractor.extract_advanced_features(scam_message)
    assert features["linguistic_vocabulary_richness"] > 0
    assert features["linguistic_readability_score"] > 0


def test_info_extraction_features(scam_message):
    features = AdvancedFeatureExtractor.extract_advanced_features(scam_message)
    assert features["info_unique_phone_count"] > 0
    assert features["info_amount_mention_count"] > 0
    assert features["info_credential_request_density"] > 0


def test_psychological_features_scam(scam_message):
    features = AdvancedFeatureExtractor.extract_advanced_features(scam_message)
    assert features["psych_fear_appeal_score"] > 0
    assert features["psych_anchoring_score"] > 0


def test_behavioral_features_with_session(session_messages):
    msg = "Send your OTP now and transfer money immediately"
    features = AdvancedFeatureExtractor.extract_advanced_features(msg, session_messages)
    assert features["behav_info_request_density"] > 0
    assert features["behav_rapport_vs_demand_ratio"] > 0


def test_empty_message():
    features = AdvancedFeatureExtractor.extract_advanced_features("")
    assert isinstance(features, dict)
    assert len(features) == len(ADVANCED_FEATURE_NAMES)


def test_hindi_code_switching():
    msg = "Aap jaldi se OTP bhejo warna aapka account block ho jayega"
    features = AdvancedFeatureExtractor.extract_advanced_features(msg)
    assert features["linguistic_code_switch_count"] > 0


def test_personal_data_detection():
    msg = "Please share your aadhaar number and pan card details for verification"
    features = AdvancedFeatureExtractor.extract_advanced_features(msg)
    assert features["info_personal_data_requests"] > 0


def test_financial_entity_density():
    msg = "Transfer the amount to bank account via NEFT or RTGS payment"
    features = AdvancedFeatureExtractor.extract_advanced_features(msg)
    assert features["info_financial_entity_density"] > 0
