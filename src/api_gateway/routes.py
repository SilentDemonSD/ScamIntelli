from fastapi import APIRouter, HTTPException, Header, Depends
from typing import Optional
from datetime import datetime, timezone
from src.models import (
    MessageRequest,
    AgentReply,
    SessionResponse,
    EndSessionResponse,
    HealthResponse,
    HoneypotRequest,
    HoneypotSimpleResponse
)
from src.session_manager.session_store import (
    get_or_create_session,
    delete_session,
    session_exists
)
from src.agent_controller.strategy import process_message, should_trigger_callback, get_engagement_summary
from src.callback_worker.guvi_callback import send_guvi_callback
from src.utils.validation import validate_session_id, validate_message, sanitize_input
from src.config import get_settings

settings = get_settings()
router = APIRouter(prefix="/api/v1", tags=["honeypot"])


async def verify_api_key(x_api_key: Optional[str] = Header(None)) -> str:
    if not x_api_key:
        raise HTTPException(status_code=401, detail="API key required")
    if x_api_key != settings.api_key:
        raise HTTPException(status_code=403, detail="Invalid API key")
    return x_api_key


@router.post("/message", response_model=AgentReply)
async def handle_message(
    request: MessageRequest,
    api_key: str = Depends(verify_api_key)
):
    if not validate_session_id(request.session_id):
        raise HTTPException(status_code=400, detail="Invalid session ID format")
    
    if not validate_message(request.message):
        raise HTTPException(status_code=400, detail="Invalid message format")
    
    message = sanitize_input(request.message)
    
    session = await get_or_create_session(request.session_id)
    
    session, reply = await process_message(session, message)
    
    if not session.engagement_active and await should_trigger_callback(session):
        await send_guvi_callback(session)
    
    return reply


@router.post("/honeypot", response_model=HoneypotSimpleResponse)
async def honeypot_endpoint(
    request: HoneypotRequest,
    x_api_key: Optional[str] = Header(None, alias="x-api-key")
):
    """
    GUVI Hackathon format honeypot endpoint.
    
    Accepts message object with sender, text, timestamp (epoch ms).
    Returns simple response: {"status": "success", "reply": "..."}
    Sends callback to GUVI when conversation is complete.
    """
    # Verify API key
    if not x_api_key:
        raise HTTPException(status_code=401, detail="API key required")
    if x_api_key != settings.api_key:
        raise HTTPException(status_code=403, detail="Invalid API key")
    
    # Extract message text from the hackathon format
    if isinstance(request.message, dict):
        message_text = request.message.get("text", "")
    else:
        message_text = request.message.text
    
    if not message_text:
        raise HTTPException(status_code=400, detail="Message text required")
    
    # Get or create session
    session = await get_or_create_session(request.sessionId)
    
    # Process message through our existing pipeline
    session, reply = await process_message(session, message_text)
    
    # Determine if conversation should be complete (after 10 turns or engagement ended)
    conversation_complete = not session.engagement_active or session.turn_count >= 10
    
    # Send callback if conversation is complete and scam was detected
    if conversation_complete and session.scam_detected:
        await send_guvi_callback(session)
    
    # Return simple format as GUVI expects
    return HoneypotSimpleResponse(
        status="success",
        reply=reply.reply
    )


@router.get("/session/{session_id}", response_model=SessionResponse)
async def get_session(
    session_id: str,
    api_key: str = Depends(verify_api_key)
):
    if not validate_session_id(session_id):
        raise HTTPException(status_code=400, detail="Invalid session ID format")
    
    if not await session_exists(session_id):
        raise HTTPException(status_code=404, detail="Session not found")
    
    session = await get_or_create_session(session_id)
    
    return SessionResponse(
        session_id=session.session_id,
        scam_detected=session.scam_detected,
        engagement_active=session.engagement_active,
        turn_count=session.turn_count,
        extracted_intelligence=session.extracted_intel
    )


@router.delete("/session/{session_id}", response_model=EndSessionResponse)
async def end_session(
    session_id: str,
    api_key: str = Depends(verify_api_key)
):
    if not validate_session_id(session_id):
        raise HTTPException(status_code=400, detail="Invalid session ID format")
    
    if not await session_exists(session_id):
        raise HTTPException(status_code=404, detail="Session not found")
    
    session = await get_or_create_session(session_id)
    
    callback_sent = False
    if session.scam_detected:
        callback_sent = await send_guvi_callback(session)
    
    await delete_session(session_id)
    
    return EndSessionResponse(
        status="success",
        session_id=session_id,
        callback_sent=callback_sent,
        total_messages=session.turn_count,
        extracted_intelligence=session.extracted_intel
    )


@router.get("/health", response_model=HealthResponse)
async def health_check():
    return HealthResponse(
        status="healthy",
        timestamp=datetime.now(timezone.utc)
    )


@router.get("/summary/{session_id}")
async def get_summary(
    session_id: str,
    api_key: str = Depends(verify_api_key)
):
    if not validate_session_id(session_id):
        raise HTTPException(status_code=400, detail="Invalid session ID format")
    
    if not await session_exists(session_id):
        raise HTTPException(status_code=404, detail="Session not found")
    
    session = await get_or_create_session(session_id)
    
    return await get_engagement_summary(session)
