import asyncio
from typing import Any, Dict, Optional

import httpx

from src.agent_controller.agent_state import generate_agent_notes
from src.config import get_settings
from src.models import GuviCallbackPayload, GuviExtractedIntelligence, SessionState
from src.utils.logging import get_logger

settings = get_settings()
logger = get_logger(__name__)

_HTTP_CLIENT: Optional[httpx.AsyncClient] = None
_RETRY_DELAYS = (0.5, 1.0, 2.0)


async def get_http_client() -> httpx.AsyncClient:
    global _HTTP_CLIENT
    if _HTTP_CLIENT is None or _HTTP_CLIENT.is_closed:
        _HTTP_CLIENT = httpx.AsyncClient(
            timeout=httpx.Timeout(30.0, connect=10.0, read=20.0, write=10.0),
            limits=httpx.Limits(max_connections=50, max_keepalive_connections=10),
            http2=True,
        )
    return _HTTP_CLIENT


async def build_callback_payload(session: SessionState) -> GuviCallbackPayload:
    notes = await generate_agent_notes(session)

    guvi_intel = GuviExtractedIntelligence(
        bankAccounts=session.extracted_intel.bank_accounts,
        upiIds=session.extracted_intel.upi_ids,
        phishingLinks=session.extracted_intel.phishing_links,
        phoneNumbers=session.extracted_intel.phone_numbers,
        suspiciousKeywords=session.extracted_intel.suspicious_keywords,
    )

    return GuviCallbackPayload(
        sessionId=session.session_id,
        scamDetected=session.scam_detected,
        totalMessagesExchanged=session.turn_count,
        extractedIntelligence=guvi_intel,
        agentNotes=notes,
    )


async def _send_with_retry(
    client: httpx.AsyncClient,
    url: str,
    payload: Dict[str, Any],
    headers: Dict[str, str],
) -> Optional[httpx.Response]:
    last_error = None
    for i, delay in enumerate(_RETRY_DELAYS):
        try:
            response = await client.post(url, json=payload, headers=headers)
            if response.status_code in (200, 201, 202):
                return response
            if response.status_code < 500:
                return response
        except (httpx.TimeoutException, httpx.ConnectError) as e:
            last_error = e
        if i < len(_RETRY_DELAYS) - 1:
            await asyncio.sleep(delay)
    if last_error:
        raise last_error
    return None


async def send_guvi_callback(session: SessionState) -> bool:
    if not settings.guvi_callback_url:
        logger.warning(
            f"GUVI callback URL not configured for session {session.session_id}"
        )
        return False

    try:
        payload = await build_callback_payload(session)
        client = await get_http_client()

        headers = {
            "Content-Type": "application/json",
            "X-Session-Id": session.session_id,
            "Accept": "application/json",
        }

        response = await _send_with_retry(
            client, settings.guvi_callback_url, payload.model_dump(), headers
        )

        if response and response.status_code in (200, 201, 202):
            logger.info(f"GUVI callback successful for session {session.session_id}")
            return True

        status = response.status_code if response else "no response"
        logger.error(f"GUVI callback failed with status {status}")
        return False

    except httpx.TimeoutException:
        logger.error(f"GUVI callback timeout for session {session.session_id}")
        return False
    except httpx.RequestError as e:
        logger.error(f"GUVI callback request error: {str(e)}")
        return False
    except Exception as e:
        logger.error(f"GUVI callback unexpected error: {str(e)}")
        return False


async def schedule_callback(session: SessionState) -> Optional[str]:
    success = await send_guvi_callback(session)
    return f"Callback sent for session {session.session_id}" if success else None


async def cleanup_client() -> None:
    global _HTTP_CLIENT
    if _HTTP_CLIENT and not _HTTP_CLIENT.is_closed:
        await _HTTP_CLIENT.aclose()
        _HTTP_CLIENT = None
