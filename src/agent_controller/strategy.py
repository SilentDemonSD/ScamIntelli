from typing import Tuple
from src.models import SessionState, AgentReply
from src.agent_controller.agent_state import (
    create_agent_context,
    update_agent_state,
    generate_agent_notes
)
from src.scam_detector.classifier import detect_scam
from src.intelligence_extractor.extractor import extract_all_intelligence, has_sufficient_intelligence
from src.persona_engine.persona_generator import (
    generate_persona_response,
    get_exit_response,
    select_persona_style
)
from src.session_manager.session_store import update_session
from src.utils.logging import log_session


async def process_message(session: SessionState, message: str) -> Tuple[SessionState, AgentReply]:
    await log_session(session.session_id, message, "incoming", session.scam_detected)
    
    scam_result = await detect_scam(message)
    
    if scam_result.is_scam and not session.scam_detected:
        session.scam_detected = True
        session.persona_style = await select_persona_style(session.turn_count, scam_result.total_score)
    
    session.extracted_intel = await extract_all_intelligence(message, session.extracted_intel)
    
    session = await update_agent_state(session, message, "scammer")
    
    context = await create_agent_context(session, message, scam_result.total_score)
    
    if context.should_end:
        session.engagement_active = False
        reply_text = await get_exit_response()
    elif context.should_engage:
        reply_text = await generate_persona_response(session, message)
    else:
        reply_text = "Thank you for your message."
    
    session = await update_agent_state(session, reply_text, "agent")
    
    await update_session(session)
    
    await log_session(session.session_id, reply_text, "outgoing", session.scam_detected)
    
    return session, AgentReply(
        status="success",
        reply=reply_text,
        session_id=session.session_id,
        scam_detected=session.scam_detected,
        engagement_active=session.engagement_active
    )


async def should_trigger_callback(session: SessionState) -> bool:
    if not session.scam_detected:
        return False
    
    if session.engagement_active:
        return False
    
    has_intel = await has_sufficient_intelligence(session.extracted_intel)
    
    return has_intel or session.turn_count >= 5


async def get_engagement_summary(session: SessionState) -> dict:
    notes = await generate_agent_notes(session)
    
    return {
        "session_id": session.session_id,
        "scam_detected": session.scam_detected,
        "total_turns": session.turn_count,
        "persona_used": session.persona_style.value,
        "intelligence_collected": {
            "upi_ids": len(session.extracted_intel.upi_ids),
            "phone_numbers": len(session.extracted_intel.phone_numbers),
            "phishing_links": len(session.extracted_intel.phishing_links),
            "suspicious_keywords": len(session.extracted_intel.suspicious_keywords)
        },
        "notes": notes
    }
