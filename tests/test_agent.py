import pytest

from src.agent_controller.agent_state import (
    check_end_conditions,
    create_agent_context,
    generate_agent_notes,
    update_agent_state,
)
from src.models import ExtractedIntelligence, PersonaStyle, SessionState


@pytest.fixture
def sample_session():
    return SessionState(
        session_id="test-session-001",
        persona_style=PersonaStyle.CONFUSED,
        extracted_intel=ExtractedIntelligence(),
        turn_count=0,
        confidence_level=0.5,
        scam_detected=False,
        engagement_active=True,
        messages=[],
    )


@pytest.mark.asyncio
async def test_create_agent_context(sample_session):
    context = await create_agent_context(sample_session, "test message", 0.8)

    assert context.session.session_id == "test-session-001"
    assert context.current_message == "test message"
    assert context.scam_score == 0.8


@pytest.mark.asyncio
async def test_check_end_conditions_not_met(sample_session):
    result = await check_end_conditions(sample_session)

    assert result is False


@pytest.mark.asyncio
async def test_check_end_conditions_met():
    session = SessionState(
        session_id="test-session-002",
        persona_style=PersonaStyle.CONFUSED,
        extracted_intel=ExtractedIntelligence(upi_ids=["fraud@upi"]),
        turn_count=12,
        confidence_level=0.5,
        scam_detected=True,
        engagement_active=True,
        messages=[],
    )

    result = await check_end_conditions(session)

    assert result is True


@pytest.mark.asyncio
async def test_update_agent_state(sample_session):
    updated = await update_agent_state(sample_session, "Hello", "scammer")

    assert len(updated.messages) == 1
    assert updated.messages[0]["role"] == "scammer"
    assert updated.messages[0]["content"] == "Hello"
    assert updated.turn_count == 1


@pytest.mark.asyncio
async def test_generate_agent_notes():
    session = SessionState(
        session_id="test-session-003",
        persona_style=PersonaStyle.ANXIOUS,
        extracted_intel=ExtractedIntelligence(
            upi_ids=["fraud@upi"], suspicious_keywords=["urgent", "blocked"]
        ),
        turn_count=5,
        confidence_level=0.8,
        scam_detected=True,
        engagement_active=False,
        messages=[],
    )

    notes = await generate_agent_notes(session)

    assert "fraud@upi" in notes
    # Check for enhanced agent notes features
    assert "Scam Type:" in notes or "Urgency" in notes or "Fear" in notes
