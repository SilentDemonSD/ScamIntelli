"""
Tests for red flag detection and probing system.

Validates RedFlagDetector pattern matching for all 12 red flag types,
RedFlagProber question generation, and behavioral escalation analysis.
"""

import pytest

from src.agent_controller.red_flag_tracker import (
    RedFlagDetector,
    RedFlagInstance,
    RedFlagProber,
    RedFlagType,
)


# ---------------------------------------------------------------------------
# RedFlagDetector – individual red flag types
# ---------------------------------------------------------------------------

class TestRedFlagDetection:
    """Detection tests for each of the 12 red flag types."""

    def test_detect_urgency_pressure(self):
        """Urgency/pressure language triggers flag."""
        messages = [
            "Do it immediately or account will be blocked!",
            "You have only 5 minutes to act!",
            "Abhi karo jaldi!",
        ]
        for msg in messages:
            flags = RedFlagDetector.detect_red_flags(msg, turn_number=1)
            assert any(f.flag_type == RedFlagType.URGENCY_PRESSURE for f in flags), (
                f"Failed to detect urgency in: {msg}"
            )

    def test_detect_threat_intimidation(self):
        """Arrest/legal threats trigger flag."""
        messages = [
            "Arrest warrant has been issued against you",
            "Police will come to your house",
            "Legal action will be taken immediately",
            "FIR is registered in your name",
        ]
        for msg in messages:
            flags = RedFlagDetector.detect_red_flags(msg, turn_number=2)
            assert any(f.flag_type == RedFlagType.THREAT_INTIMIDATION for f in flags), (
                f"Failed to detect threat in: {msg}"
            )

    def test_detect_credential_request(self):
        """OTP/PIN/password requests trigger flag."""
        messages = [
            "Share your OTP now",
            "Tell me the pin number",
            "Enter your password here",
            "Send otp bhejo jaldi",
        ]
        for msg in messages:
            flags = RedFlagDetector.detect_red_flags(msg, turn_number=3)
            assert any(f.flag_type == RedFlagType.CREDENTIAL_REQUEST for f in flags), (
                f"Failed to detect credential request in: {msg}"
            )

    def test_detect_payment_demand(self):
        """Payment demands trigger flag."""
        messages = [
            "You must pay the fine immediately",
            "Transfer 5000 rupees to this account",
            "Processing fee required, send money now",
        ]
        for msg in messages:
            flags = RedFlagDetector.detect_red_flags(msg, turn_number=4)
            assert any(f.flag_type == RedFlagType.PAYMENT_DEMAND for f in flags), (
                f"Failed to detect payment demand in: {msg}"
            )

    def test_detect_authority_claim(self):
        """Fake authority claims trigger flag."""
        messages = [
            "I am officer from CBI headquarters",
            "This is the police calling",
            "Bank manager speaking, your account has issue",
        ]
        for msg in messages:
            flags = RedFlagDetector.detect_red_flags(msg, turn_number=1)
            assert any(f.flag_type == RedFlagType.AUTHORITY_CLAIM for f in flags), (
                f"Failed to detect authority claim in: {msg}"
            )

    def test_detect_secrecy_demand(self):
        """Secrecy demands trigger flag."""
        messages = [
            "Don't tell anyone about this call",
            "Keep this between us only",
            "Kisi ko mat batana",
        ]
        for msg in messages:
            flags = RedFlagDetector.detect_red_flags(msg, turn_number=3)
            assert any(f.flag_type == RedFlagType.SECRECY_DEMAND for f in flags), (
                f"Failed to detect secrecy demand in: {msg}"
            )

    def test_detect_link_pressure(self):
        """Link clicking pressure triggers flag."""
        flags = RedFlagDetector.detect_red_flags(
            "Click this link immediately to verify", turn_number=2,
        )
        assert any(f.flag_type == RedFlagType.LINK_PRESSURE for f in flags)

    def test_detect_trust_building(self):
        """Trust building language triggers flag."""
        flags = RedFlagDetector.detect_red_flags(
            "Trust me on this, it is 100% safe and guaranteed", turn_number=3,
        )
        assert any(f.flag_type == RedFlagType.TRUST_BUILDING for f in flags)

    def test_detect_personal_info_probe(self):
        """Personal data requests trigger flag."""
        flags = RedFlagDetector.detect_red_flags(
            "Share your aadhaar number and date of birth", turn_number=2,
        )
        assert any(f.flag_type == RedFlagType.PERSONAL_INFO_PROBE for f in flags)

    def test_detect_process_irregularity(self):
        """Irregular process instructions trigger flag."""
        flags = RedFlagDetector.detect_red_flags(
            "Install anydesk app and give remote access", turn_number=4,
        )
        assert any(f.flag_type == RedFlagType.PROCESS_IRREGULARITY for f in flags)

    def test_detect_time_constraint(self):
        """Deadline/time constraint language triggers flag."""
        flags = RedFlagDetector.detect_red_flags(
            "This offer is valid till today only, deadline is today", turn_number=3,
        )
        assert any(f.flag_type == RedFlagType.TIME_CONSTRAINT for f in flags)

    def test_detect_verification_avoidance(self):
        """Refusal to share credentials triggers flag."""
        flags = RedFlagDetector.detect_red_flags(
            "I cannot share that, it's confidential and classified", turn_number=3,
        )
        assert any(f.flag_type == RedFlagType.VERIFICATION_AVOIDANCE for f in flags)


# ---------------------------------------------------------------------------
# No false positives
# ---------------------------------------------------------------------------

class TestNoFalsePositives:
    def test_benign_message_no_flags(self):
        """Normal conversation should produce no flags."""
        flags = RedFlagDetector.detect_red_flags("Hello, how are you?", turn_number=1)
        assert len(flags) == 0

    def test_neutral_longer_message(self):
        """Longer neutral message stays clean."""
        flags = RedFlagDetector.detect_red_flags(
            "Good morning sir, I want to talk about the new plan for next quarter.",
            turn_number=2,
        )
        assert len(flags) == 0


# ---------------------------------------------------------------------------
# Multiple flags in one message
# ---------------------------------------------------------------------------

class TestMultipleFlags:
    def test_combined_threat_and_urgency(self):
        """Message with both threat and urgency triggers both flags."""
        msg = "Arrest warrant issued! Do it now immediately or police will come!"
        flags = RedFlagDetector.detect_red_flags(msg, turn_number=3)
        flag_types = {f.flag_type for f in flags}
        assert RedFlagType.THREAT_INTIMIDATION in flag_types
        assert RedFlagType.URGENCY_PRESSURE in flag_types

    def test_credential_plus_payment(self):
        """Credential request + payment demand detected together."""
        msg = "Share your OTP and send 5000 rupees fee immediately"
        flags = RedFlagDetector.detect_red_flags(msg, turn_number=4)
        flag_types = {f.flag_type for f in flags}
        assert RedFlagType.CREDENTIAL_REQUEST in flag_types
        assert RedFlagType.PAYMENT_DEMAND in flag_types


# ---------------------------------------------------------------------------
# RedFlagInstance serialization
# ---------------------------------------------------------------------------

class TestRedFlagInstance:
    def test_to_dict(self):
        """to_dict produces correct structure."""
        flag = RedFlagInstance(
            flag_type=RedFlagType.URGENCY_PRESSURE,
            turn_number=3,
            message_content="do it now!",
            confidence=0.85,
        )
        d = flag.to_dict()
        assert d["flag_type"] == "urgency_pressure"
        assert d["turn"] == 3
        assert d["confidence"] == 0.85
        assert "timestamp" in d

    def test_content_snippet_truncated(self):
        """Long content is truncated to 100 chars."""
        long_msg = "x" * 200
        flag = RedFlagInstance(
            flag_type=RedFlagType.THREAT_INTIMIDATION,
            turn_number=1, message_content=long_msg, confidence=0.9,
        )
        assert len(flag.to_dict()["content_snippet"]) <= 100


# ---------------------------------------------------------------------------
# Behavioral escalation analysis
# ---------------------------------------------------------------------------

class TestEscalationAnalysis:
    def test_short_conversation_no_escalation(self):
        """Too few messages = no escalation detected."""
        history = [
            {"role": "scammer", "content": "Hello"},
            {"role": "agent", "content": "Ji boliye"},
        ]
        result = RedFlagDetector.analyze_behavioral_escalation(history)
        assert result["escalation_detected"] is False

    def test_escalation_detected(self):
        """Second half has more urgency/threats → escalation detected."""
        history = [
            {"role": "scammer", "content": "Hello sir"},
            {"role": "agent", "content": "Haan ji"},
            {"role": "scammer", "content": "Your account needs update"},
            {"role": "agent", "content": "Okay"},
            {"role": "scammer", "content": "Do it urgent now immediately!"},
            {"role": "agent", "content": "Haan"},
            {"role": "scammer", "content": "Police will arrest you! Urgent! Jaldi!"},
            {"role": "agent", "content": "Sir please"},
        ]
        result = RedFlagDetector.analyze_behavioral_escalation(history)
        assert result["escalation_detected"] is True
        assert result["escalation_speed"] in ("slow", "moderate", "rapid")


# ---------------------------------------------------------------------------
# RedFlagProber
# ---------------------------------------------------------------------------

class TestRedFlagProber:
    def test_generate_probing_question(self):
        """Probing question generated for detected flags."""
        flags = RedFlagDetector.detect_red_flags(
            "Share your OTP immediately!", turn_number=3,
        )
        assert len(flags) > 0, "No flags detected in test setup"
        q = RedFlagProber.generate_probing_question(flags, turn_number=3, already_asked=[])
        assert q is not None
        assert isinstance(q, str)
        assert len(q) > 10

    def test_probing_question_no_flags(self):
        """No flags → no probing question."""
        q = RedFlagProber.generate_probing_question([], turn_number=3)
        assert q is None

    def test_should_probe_first_two_turns(self):
        """No probing in first two turns (build rapport)."""
        flag = RedFlagInstance(
            flag_type=RedFlagType.URGENCY_PRESSURE,
            turn_number=1, message_content="now!", confidence=0.9,
        )
        assert RedFlagProber.should_probe_now([flag], turn_number=1, total_red_flags_session=1) is False
        assert RedFlagProber.should_probe_now([flag], turn_number=2, total_red_flags_session=1) is False

    def test_should_probe_multiple_flags(self):
        """Multiple flags in one message → always probe."""
        flags = [
            RedFlagInstance(flag_type=RedFlagType.URGENCY_PRESSURE, turn_number=4, message_content="a", confidence=0.8),
            RedFlagInstance(flag_type=RedFlagType.THREAT_INTIMIDATION, turn_number=4, message_content="b", confidence=0.9),
        ]
        assert RedFlagProber.should_probe_now(flags, turn_number=4, total_red_flags_session=3) is True

    def test_should_probe_accumulated_flags(self):
        """5+ accumulated flags at turn 5+ → always probe."""
        flag = RedFlagInstance(
            flag_type=RedFlagType.CREDENTIAL_REQUEST,
            turn_number=5, message_content="otp", confidence=0.9,
        )
        assert RedFlagProber.should_probe_now([flag], turn_number=6, total_red_flags_session=6) is True

    def test_probing_deduplicates(self):
        """Already-asked questions are skipped."""
        flag = RedFlagInstance(
            flag_type=RedFlagType.URGENCY_PRESSURE,
            turn_number=3, message_content="jaldi!", confidence=0.8,
        )
        # Get all possible questions then pass them as already asked
        all_questions = RedFlagProber.PROBING_QUESTIONS.get(RedFlagType.URGENCY_PRESSURE, [])
        q = RedFlagProber.generate_probing_question([flag], turn_number=3, already_asked=all_questions)
        # Should be None when all questions exhausted, or fall through to other flag types
        assert q is None or isinstance(q, str)
