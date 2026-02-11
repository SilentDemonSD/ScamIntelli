import pytest

from src.intelligence_extractor.behavioral_fingerprint import (
    BehavioralFingerprinter,
    get_fingerprinter,
    MIN_MESSAGES_FOR_FINGERPRINT,
    SIMILARITY_THRESHOLD,
)


@pytest.fixture
def fingerprinter():
    return BehavioralFingerprinter()


@pytest.fixture
def scammer_session_1():
    return [
        {"role": "scammer", "content": "Hello sir, I am calling from SBI bank headquarters"},
        {"role": "assistant", "content": "Ji kahiye"},
        {"role": "scammer", "content": "Your account has been compromised and we need to verify immediately"},
        {"role": "assistant", "content": "Kya hua?"},
        {"role": "scammer", "content": "Send your OTP right now or your account will be blocked! This is urgent!"},
        {"role": "assistant", "content": "Theek hai"},
        {"role": "scammer", "content": "Sir time is running out, police will arrest you if you don't comply"},
    ]


@pytest.fixture
def scammer_session_2_similar():
    return [
        {"role": "scammer", "content": "Good day madam, I am calling from SBI bank office"},
        {"role": "assistant", "content": "Hello"},
        {"role": "scammer", "content": "Your bank account has been compromised and verification is needed urgently"},
        {"role": "assistant", "content": "What happened?"},
        {"role": "scammer", "content": "Share your OTP immediately or your account will be suspended! Very urgent!"},
        {"role": "assistant", "content": "Okay"},
        {"role": "scammer", "content": "Madam no time left, police case will be filed if you don't comply now"},
    ]


@pytest.fixture
def scammer_session_3_different():
    return [
        {"role": "scammer", "content": "Congratulations! You have won a lottery of ₹50 lakhs!"},
        {"role": "assistant", "content": "Really?"},
        {"role": "scammer", "content": "Yes, just pay a processing fee of ₹5000 to claim your prize"},
        {"role": "assistant", "content": "How?"},
        {"role": "scammer", "content": "Send money to UPI ID lottery@paytm and you will get ₹50 lakhs instantly"},
    ]


def test_create_fingerprint(fingerprinter, scammer_session_1):
    fp = fingerprinter.create_fingerprint("session-1", scammer_session_1)
    assert fp is not None
    assert fp.session_id == "session-1"
    assert fp.fingerprint_id
    assert fp.signature_hash
    assert fp.message_count >= MIN_MESSAGES_FOR_FINGERPRINT


def test_fingerprint_requires_minimum_messages(fingerprinter):
    short_session = [
        {"role": "scammer", "content": "Hello"},
        {"role": "assistant", "content": "Hi"},
    ]
    fp = fingerprinter.create_fingerprint("session-short", short_session)
    assert fp is None


def test_timing_pattern(fingerprinter, scammer_session_1):
    fp = fingerprinter.create_fingerprint("session-1", scammer_session_1)
    assert fp.timing.avg_message_length > 0
    assert fp.timing.avg_word_count > 0
    assert fp.timing.punctuation_density >= 0
    assert fp.timing.capitalization_ratio >= 0


def test_language_pattern(fingerprinter, scammer_session_1):
    fp = fingerprinter.create_fingerprint("session-1", scammer_session_1)
    assert fp.language.vocabulary_richness > 0
    assert fp.language.avg_sentence_length > 0
    assert isinstance(fp.language.top_bigrams, list)
    assert fp.language.formality_score is not None


def test_escalation_pattern(fingerprinter, scammer_session_1):
    fp = fingerprinter.create_fingerprint("session-1", scammer_session_1)
    assert fp.escalation.pressure_pattern in (
        "aggressive_escalation", "gradual_escalation",
        "sustained_pressure", "urgency_buildup", "low_pressure",
    )
    assert fp.escalation.threat_density >= 0
    assert fp.escalation.escalation_speed >= 0


def test_store_and_retrieve_fingerprint(fingerprinter, scammer_session_1):
    fp = fingerprinter.create_fingerprint("session-1", scammer_session_1)
    fingerprinter.store_fingerprint(fp)
    assert fingerprinter.get_stored_count() == 1

    retrieved = fingerprinter.get_fingerprint_by_session("session-1")
    assert retrieved is not None
    assert retrieved.fingerprint_id == fp.fingerprint_id


def test_match_similar_fingerprints(
    fingerprinter, scammer_session_1, scammer_session_2_similar
):
    fp1 = fingerprinter.create_fingerprint("session-1", scammer_session_1)
    fingerprinter.store_fingerprint(fp1)

    fp2 = fingerprinter.create_fingerprint("session-2", scammer_session_2_similar)
    matches = fingerprinter.match_fingerprint(fp2)

    assert len(matches) >= 1
    best_match = matches[0]
    assert best_match.matched_session_id == "session-1"
    assert best_match.similarity_score >= SIMILARITY_THRESHOLD


def test_no_match_different_fingerprints(
    fingerprinter, scammer_session_1, scammer_session_3_different
):
    fp1 = fingerprinter.create_fingerprint("session-1", scammer_session_1)
    fingerprinter.store_fingerprint(fp1)

    fp3 = fingerprinter.create_fingerprint("session-3", scammer_session_3_different)
    matches = fingerprinter.match_fingerprint(fp3)

    if matches:
        assert all(m.similarity_score < 0.95 for m in matches)


def test_self_not_matched(fingerprinter, scammer_session_1):
    fp = fingerprinter.create_fingerprint("session-1", scammer_session_1)
    fingerprinter.store_fingerprint(fp)

    matches = fingerprinter.match_fingerprint(fp)
    for m in matches:
        assert m.matched_session_id != "session-1"


def test_entity_patterns(fingerprinter):
    session = [
        {"role": "scammer", "content": "Send money to scammer@upi or call 9876543210"},
        {"role": "assistant", "content": "Ok"},
        {"role": "scammer", "content": "Visit https://phishing.com and enter OTP 1234"},
        {"role": "assistant", "content": "Wait"},
        {"role": "scammer", "content": "Transfer ₹5000 now to 9876543210"},
    ]
    fp = fingerprinter.create_fingerprint("session-entities", session)
    assert fp is not None
    assert fp.entity_patterns["phones"] > 0
    assert fp.entity_patterns["urls"] > 0


def test_reset(fingerprinter, scammer_session_1):
    fp = fingerprinter.create_fingerprint("session-1", scammer_session_1)
    fingerprinter.store_fingerprint(fp)
    assert fingerprinter.get_stored_count() == 1
    fingerprinter.reset()
    assert fingerprinter.get_stored_count() == 0


def test_global_fingerprinter_singleton():
    f1 = get_fingerprinter()
    f2 = get_fingerprinter()
    assert f1 is f2


def test_multiple_fingerprints_stored(fingerprinter, scammer_session_1, scammer_session_3_different):
    fp1 = fingerprinter.create_fingerprint("session-1", scammer_session_1)
    fp3 = fingerprinter.create_fingerprint("session-3", scammer_session_3_different)
    fingerprinter.store_fingerprint(fp1)
    fingerprinter.store_fingerprint(fp3)
    assert fingerprinter.get_stored_count() == 2
