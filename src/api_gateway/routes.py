from fastapi import APIRouter, HTTPException, Header, Depends, Request
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
    update_session
)
from src.agent_controller.strategy import process_message, should_trigger_callback, get_engagement_summary
from src.callback_worker.guvi_callback import send_guvi_callback
from src.utils.validation import validate_session_id, validate_message, sanitize_input
from src.security.tamper_proof import (
    validate_incoming_request,
    create_tamper_proof_response,
    TamperProofMiddleware
)
from src.config import get_settings

settings = get_settings()
router = APIRouter(prefix="/api/v1", tags=["honeypot"])
_middleware = TamperProofMiddleware()


async def verify_api_key(x_api_key: Optional[str] = Header(None)) -> str:
    if not x_api_key:
        raise HTTPException(status_code=401, detail="API key required")
    if x_api_key != settings.api_key:
        raise HTTPException(status_code=403, detail="Invalid API key")
    return x_api_key


def _extract_client_info(request: Request) -> tuple:
    ip = request.client.host if request.client else "unknown"
    user_agent = request.headers.get("user-agent", "unknown")
    return ip, user_agent, dict(request.headers)


@router.post("/message", response_model=AgentReply)
async def handle_message(
    request_body: MessageRequest,
    request: Request,
    api_key: str = Depends(verify_api_key)
):
    if not validate_session_id(request_body.session_id):
        raise HTTPException(status_code=400, detail="Invalid session ID format")
    if not validate_message(request_body.message):
        raise HTTPException(status_code=400, detail="Invalid message format")
    
    message = sanitize_input(request_body.message)
    ip, user_agent, headers = _extract_client_info(request)
    validate_incoming_request(ip, user_agent, request_body.session_id, message, headers)
    
    session = await get_or_create_session(request_body.session_id)
    session, reply = await process_message(session, message)
    await update_session(session)
    
    if not session.engagement_active and await should_trigger_callback(session):
        await send_guvi_callback(session)
    
    return reply


@router.post("/honeypot", response_model=HoneypotSimpleResponse)
async def honeypot_endpoint(
    request_body: HoneypotRequest,
    request: Request,
    x_api_key: Optional[str] = Header(None, alias="x-api-key")
):
    if not x_api_key or x_api_key != settings.api_key:
        raise HTTPException(status_code=401 if not x_api_key else 403, detail="API key required" if not x_api_key else "Invalid API key")
    
    message_text = request_body.message.get("text", "") if isinstance(request_body.message, dict) else request_body.message.text
    if not message_text:
        raise HTTPException(status_code=400, detail="Message text required")
    
    ip, user_agent, headers = _extract_client_info(request)
    validate_incoming_request(ip, user_agent, request_body.sessionId, message_text, headers)
    
    session = await get_or_create_session(request_body.sessionId)
    session, reply = await process_message(session, message_text)
    await update_session(session)
    
    conversation_complete = not session.engagement_active or session.turn_count >= 10
    if conversation_complete and session.scam_detected:
        await send_guvi_callback(session)
    
    persona_type = getattr(session, 'persona_type', None)
    persona_str = persona_type.value if persona_type else "default"
    
    response_data, _ = create_tamper_proof_response({"status": "success", "reply": reply.reply}, persona_str)
    
    return HoneypotSimpleResponse(
        status=response_data.get("status", "success"),
        reply=response_data.get("reply", reply.reply)
    )


@router.get("/session/{session_id}", response_model=SessionResponse)
async def get_session(session_id: str, api_key: str = Depends(verify_api_key)):
    if not validate_session_id(session_id):
        raise HTTPException(status_code=400, detail="Invalid session ID format")
    
    session = await get_or_create_session(session_id)
    
    return SessionResponse(
        session_id=session.session_id,
        scam_detected=session.scam_detected,
        engagement_active=session.engagement_active,
        turn_count=session.turn_count,
        extracted_intelligence=session.extracted_intel
    )


@router.delete("/session/{session_id}", response_model=EndSessionResponse)
async def end_session(session_id: str, api_key: str = Depends(verify_api_key)):
    if not validate_session_id(session_id):
        raise HTTPException(status_code=400, detail="Invalid session ID format")
    
    session = await get_or_create_session(session_id)
    callback_sent = await send_guvi_callback(session) if session.scam_detected else False
    
    from src.session_manager.session_store import get_or_create_session_store
    store = await get_or_create_session_store()
    await store.delete(session_id)
    
    return EndSessionResponse(
        status="success",
        session_id=session_id,
        callback_sent=callback_sent,
        total_messages=session.turn_count,
        extracted_intelligence=session.extracted_intel
    )


@router.get("/health", response_model=HealthResponse)
async def health_check():
    return HealthResponse(status="healthy", timestamp=datetime.now(timezone.utc))


@router.get("/summary/{session_id}")
async def get_summary(session_id: str, api_key: str = Depends(verify_api_key)):
    if not validate_session_id(session_id):
        raise HTTPException(status_code=400, detail="Invalid session ID format")
    session = await get_or_create_session(session_id)
    return await get_engagement_summary(session)
