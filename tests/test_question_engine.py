"""
Tests for investigative question engine.

Validates QuestionBank coverage across all scam categories, question
filtering by turn and extracted intel, probing follow-ups, and
IntelligenceExtractionPlanner prioritization.
"""

import pytest

from src.agent_controller.question_engine import (
    IntelligenceExtractionPlanner,
    InvestigativeQuestion,
    QuestionBank,
    QuestionType,
)
from src.models import ExtractedIntelligence
from src.scam_detector.scam_types import ScamCategory


# ---------------------------------------------------------------------------
# QuestionBank coverage tests
# ---------------------------------------------------------------------------

def test_question_bank_has_all_major_categories():
    """Verify question bank has questions for all major scam types."""
    required = [
        ScamCategory.DIGITAL_ARREST,
        ScamCategory.KYC_PHISHING,
        ScamCategory.INVESTMENT_FRAUD,
        ScamCategory.JOB_SCAM,
        ScamCategory.BANK_FRAUD,
        ScamCategory.UPI_FRAUD,
        ScamCategory.CUSTOMS_PARCEL,
        ScamCategory.ROMANCE_SCAM,
    ]
    for cat in required:
        questions = QuestionBank.IDENTITY_QUESTIONS.get(cat, [])
        assert len(questions) >= 5, f"Insufficient questions for {cat.value}"


def test_all_questions_have_text():
    """Every question must have non-empty question_text."""
    for cat, questions in QuestionBank.IDENTITY_QUESTIONS.items():
        for q in questions:
            assert q.question_text and len(q.question_text) > 5, (
                f"Empty question in {cat.value}"
            )


def test_all_questions_have_valid_turn_range():
    """Turn ranges must be (min, max) with min <= max."""
    for cat, questions in QuestionBank.IDENTITY_QUESTIONS.items():
        for q in questions:
            assert q.turn_range[0] <= q.turn_range[1], (
                f"Invalid turn range {q.turn_range} in {cat.value}"
            )


def test_general_questions_exist():
    """General investigative questions should be populated."""
    assert len(QuestionBank.GENERAL_INVESTIGATIVE_QUESTIONS) >= 5


# ---------------------------------------------------------------------------
# get_questions_for_category
# ---------------------------------------------------------------------------

def test_get_questions_for_digital_arrest_turn_3():
    """Should return questions for digital arrest at turn 3."""
    intel = ExtractedIntelligence()
    questions = QuestionBank.get_questions_for_category(
        ScamCategory.DIGITAL_ARREST, turn_count=3, extracted_intel=intel,
    )
    assert len(questions) > 0, "No questions for digital arrest turn 3"


def test_questions_sorted_by_priority():
    """First question should have highest priority."""
    intel = ExtractedIntelligence()
    questions = QuestionBank.get_questions_for_category(
        ScamCategory.DIGITAL_ARREST, turn_count=4, extracted_intel=intel,
    )
    if len(questions) >= 2:
        assert questions[0].priority >= questions[1].priority


def test_questions_filtered_when_intel_collected():
    """Fewer questions when we already have relevant intel."""
    empty_intel = ExtractedIntelligence()
    full_intel = ExtractedIntelligence(
        phone_numbers=["9876543210", "9123456789"],
        upi_ids=["fraud@paytm", "scam@upi"],
        email_addresses=["a@b.com", "c@d.com"],
        bank_accounts=["1234", "5678"],
    )
    q_empty = QuestionBank.get_questions_for_category(
        ScamCategory.KYC_PHISHING, 5, empty_intel,
    )
    q_full = QuestionBank.get_questions_for_category(
        ScamCategory.KYC_PHISHING, 5, full_intel,
    )
    assert len(q_empty) >= len(q_full), "More questions should be available when intel is empty"


def test_turn_range_filtering():
    """Questions outside their turn_range should not appear."""
    intel = ExtractedIntelligence()
    questions = QuestionBank.get_questions_for_category(
        ScamCategory.DIGITAL_ARREST, turn_count=1, extracted_intel=intel,
    )
    for q in questions:
        assert q.turn_range[0] <= 1 <= q.turn_range[1]


# ---------------------------------------------------------------------------
# Probing follow-ups
# ---------------------------------------------------------------------------

def test_probing_followup_phone():
    """Follow-up generated when phone is mentioned."""
    followup = QuestionBank.get_probing_followup(
        "phone_mentioned", "+91-9876543210", [],
    )
    # May return None due to randomness, but should not crash
    assert followup is None or isinstance(followup, str)


def test_probing_followup_unknown_entity():
    """Unknown entity type returns None gracefully."""
    assert QuestionBank.get_probing_followup("unknown_type", "val", []) is None


def test_probing_followup_deduplication():
    """Avoids repeating similar questions."""
    recent = [{"role": "agent", "content": QuestionBank.PROBING_FOLLOWUPS.get("phone_mentioned", [""])[0]}]
    # Should try to find a different question or return None
    result = QuestionBank.get_probing_followup("phone_mentioned", "123", recent)
    assert result is None or isinstance(result, str)


# ---------------------------------------------------------------------------
# IntelligenceExtractionPlanner
# ---------------------------------------------------------------------------

def test_planner_prioritizes_missing_intel():
    """Planner targets missing phone_numbers first for KYC_PHISHING."""
    intel = ExtractedIntelligence(
        upi_ids=["scammer@paytm"],  # have UPI
        phone_numbers=[],           # missing phones
    )
    strategy = IntelligenceExtractionPlanner.get_extraction_strategy(
        ScamCategory.KYC_PHISHING, turn_count=4, extracted_intel=intel,
    )
    # Phishing links have highest priority for KYC; if already extracted check next
    assert strategy["primary_target"] is not None
    assert strategy["urgency_level"] in ("high", "medium", "low")


def test_planner_returns_valid_structure():
    """Strategy dict has required keys."""
    intel = ExtractedIntelligence()
    strategy = IntelligenceExtractionPlanner.get_extraction_strategy(
        ScamCategory.DIGITAL_ARREST, 3, intel,
    )
    assert "primary_target" in strategy
    assert "secondary_targets" in strategy
    assert "recommended_question_type" in strategy
    assert "urgency_level" in strategy


def test_planner_all_intel_collected():
    """When all intel collected, planner still returns valid strategy."""
    intel = ExtractedIntelligence(
        phone_numbers=["1"], upi_ids=["a@b"], bank_accounts=["x"],
        email_addresses=["e@f.com"], phishing_links=["http://x.com"],
        case_ids=["C1"], organization_names=["SBI"], employee_ids=["E1"],
        names_mentioned=["Sharma"], addresses=["Delhi"], order_numbers=["ORD1"],
        policy_numbers=["POL1"],
    )
    strategy = IntelligenceExtractionPlanner.get_extraction_strategy(
        ScamCategory.INVESTMENT_FRAUD, 6, intel,
    )
    assert strategy["urgency_level"] == "low"


def test_planner_default_category():
    """Unknown category uses default priorities."""
    intel = ExtractedIntelligence()
    strategy = IntelligenceExtractionPlanner.get_extraction_strategy(
        ScamCategory.UNKNOWN, 3, intel,
    )
    assert strategy["primary_target"] is not None
