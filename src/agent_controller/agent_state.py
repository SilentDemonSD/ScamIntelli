from dataclasses import dataclass
from datetime import datetime
from src.models import SessionState


@dataclass
class AgentContext:
    session: SessionState
    current_message: str
    scam_score: float
    should_engage: bool
    should_end: bool
    notes: str = ""


async def create_agent_context(
    session: SessionState,
    message: str,
    scam_score: float
) -> AgentContext:
    should_engage = session.scam_detected and session.engagement_active
    should_end = await check_end_conditions(session)
    
    notes = await generate_agent_notes(session)
    
    return AgentContext(
        session=session,
        current_message=message,
        scam_score=scam_score,
        should_engage=should_engage,
        should_end=should_end,
        notes=notes
    )


async def check_end_conditions(session: SessionState) -> bool:
    from src.config import get_settings
    settings = get_settings()
    
    conditions_met = 0
    
    intel = session.extracted_intel
    if len(intel.upi_ids) >= 1 or len(intel.phishing_links) >= 1:
        conditions_met += 1
    
    if session.turn_count >= settings.max_engagement_turns:
        conditions_met += 1
    
    if session.turn_count >= 10:
        conditions_met += 1
    
    recent_messages = session.messages[-3:] if len(session.messages) >= 3 else session.messages
    if len(recent_messages) >= 3:
        payment_keywords = {"upi", "pay", "send", "transfer", "money"}
        payment_requests = 0
        for msg in recent_messages:
            content = msg.get("content", "").lower()
            if any(kw in content for kw in payment_keywords):
                payment_requests += 1
        if payment_requests >= 2:
            conditions_met += 1
    
    return conditions_met >= 2


async def generate_agent_notes(session: SessionState) -> str:
    notes_parts = []
    
    intel = session.extracted_intel
    
    if intel.upi_ids:
        notes_parts.append(f"Extracted UPI IDs: {', '.join(intel.upi_ids)}")
    
    if intel.phishing_links:
        notes_parts.append(f"Detected phishing links: {len(intel.phishing_links)}")
    
    if intel.phone_numbers:
        notes_parts.append(f"Captured phone numbers: {', '.join(intel.phone_numbers)}")
    
    threat_keywords = [kw for kw in intel.suspicious_keywords if kw in ["urgent", "blocked", "suspend", "legal"]]
    if threat_keywords:
        notes_parts.append(f"Threat tactics used: {', '.join(threat_keywords)}")
    
    if not notes_parts:
        notes_parts.append(f"Engaged for {session.turn_count} turns")
    
    return ". ".join(notes_parts)


async def update_agent_state(
    session: SessionState,
    message: str,
    role: str
) -> SessionState:
    session.messages.append({
        "role": role,
        "content": message,
        "timestamp": datetime.utcnow().isoformat()
    })
    
    if role == "scammer":
        session.turn_count += 1
    
    session.last_updated = datetime.utcnow()
    
    return session
