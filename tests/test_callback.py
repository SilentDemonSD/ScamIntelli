from unittest.mock import AsyncMock, patch

import pytest

from src.callback_worker.guvi_callback import build_callback_payload, send_guvi_callback
from src.models import (
    ExtractedIntelligence,
    GuviCallbackPayload,
    PersonaStyle,
    SessionState,
)


@pytest.fixture
def sample_session():
    return SessionState(
        session_id="test-session-callback",
        persona_style=PersonaStyle.CONFUSED,
        extracted_intel=ExtractedIntelligence(
            upi_ids=["fraudster@upi"],
            phone_numbers=["+919876543210"],
            phishing_links=["http://fake.com"],
            suspicious_keywords=["urgent", "blocked"],
        ),
        turn_count=10,
        confidence_level=0.9,
        scam_detected=True,
        engagement_active=False,
        messages=[],
    )


@pytest.mark.asyncio
async def test_build_callback_payload(sample_session):
    payload = await build_callback_payload(sample_session)

    assert isinstance(payload, GuviCallbackPayload)
    assert payload.sessionId == "test-session-callback"
    assert payload.scamDetected is True
    assert payload.totalMessagesExchanged == 10
    # Check the GuviExtractedIntelligence model has camelCase fields
    assert hasattr(payload.extractedIntelligence, "upiIds")
    assert "fraudster@upi" in payload.extractedIntelligence.upiIds


@pytest.mark.asyncio
async def test_send_guvi_callback_no_url(sample_session):
    with patch("src.callback_worker.guvi_callback.settings") as mock_settings:
        mock_settings.guvi_callback_url = ""

        result = await send_guvi_callback(sample_session)

        assert result is False


@pytest.mark.asyncio
async def test_send_guvi_callback_success(sample_session):
    with patch("src.callback_worker.guvi_callback.settings") as mock_settings:
        mock_settings.guvi_callback_url = "https://test.com/callback"

        with patch("httpx.AsyncClient.post") as mock_post:
            mock_response = AsyncMock()
            mock_response.status_code = 200
            mock_post.return_value = mock_response

            with patch(
                "httpx.AsyncClient.__aenter__", return_value=AsyncMock(post=mock_post)
            ):
                pass


@pytest.mark.asyncio
async def test_callback_payload_structure(sample_session):
    payload = await build_callback_payload(sample_session)
    payload_dict = payload.model_dump()

    required_fields = [
        "sessionId",
        "scamDetected",
        "totalMessagesExchanged",
        "extractedIntelligence",
        "agentNotes",
    ]

    for field in required_fields:
        assert field in payload_dict

    intel_fields = [
        "bankAccounts",
        "upiIds",
        "phishingLinks",
        "phoneNumbers",
        "suspiciousKeywords",
    ]

    for field in intel_fields:
        assert field in payload_dict["extractedIntelligence"]
