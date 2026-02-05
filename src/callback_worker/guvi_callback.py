import httpx
from typing import Optional
from src.models import SessionState, GuviCallbackPayload, GuviExtractedIntelligence
from src.config import get_settings
from src.utils.logging import get_logger
from src.agent_controller.agent_state import generate_agent_notes

settings = get_settings()
logger = get_logger(__name__)


async def build_callback_payload(session: SessionState) -> GuviCallbackPayload:
    notes = await generate_agent_notes(session)
    
    # Convert internal snake_case fields to GUVI's expected camelCase format
    guvi_intel = GuviExtractedIntelligence(
        bankAccounts=session.extracted_intel.bank_accounts,
        upiIds=session.extracted_intel.upi_ids,
        phishingLinks=session.extracted_intel.phishing_links,
        phoneNumbers=session.extracted_intel.phone_numbers,
        suspiciousKeywords=session.extracted_intel.suspicious_keywords
    )
    
    return GuviCallbackPayload(
        sessionId=session.session_id,
        scamDetected=session.scam_detected,
        totalMessagesExchanged=session.turn_count,
        extractedIntelligence=guvi_intel,
        agentNotes=notes
    )


async def send_guvi_callback(session: SessionState) -> bool:
    if not settings.guvi_callback_url:
        logger.warning(f"GUVI callback URL not configured for session {session.session_id}")
        return False
    
    try:
        payload = await build_callback_payload(session)
        
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.post(
                settings.guvi_callback_url,
                json=payload.model_dump(),
                headers={
                    "Content-Type": "application/json",
                    "X-Session-Id": session.session_id
                }
            )
            
            if response.status_code in (200, 201, 202):
                logger.info(f"GUVI callback successful for session {session.session_id}")
                return True
            else:
                logger.error(f"GUVI callback failed with status {response.status_code}")
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
    
    if success:
        return f"Callback sent for session {session.session_id}"
    else:
        return None
