from dataclasses import dataclass
from datetime import datetime, timezone
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
    """Generate comprehensive agent notes summarizing the scam engagement."""
    notes_parts = []
    intel = session.extracted_intel
    
    # Determine scam category based on keywords
    scam_type = _detect_scam_category(intel.suspicious_keywords)
    if scam_type:
        notes_parts.append(f"Scam Type: {scam_type}")
    
    # Engagement summary
    notes_parts.append(f"Engagement: {session.turn_count} message exchanges")
    
    # Intelligence extracted
    intel_items = []
    if intel.upi_ids:
        intel_items.append(f"UPI IDs: {', '.join(intel.upi_ids)}")
    if intel.bank_accounts:
        intel_items.append(f"Bank Accounts: {', '.join(intel.bank_accounts)}")
    if intel.phone_numbers:
        intel_items.append(f"Phone Numbers: {', '.join(intel.phone_numbers)}")
    if intel.phishing_links:
        intel_items.append(f"Phishing URLs: {len(intel.phishing_links)} detected")
    
    if intel_items:
        notes_parts.append(f"Intelligence Extracted: {'; '.join(intel_items)}")
    
    # Threat tactics analysis
    tactics = _analyze_threat_tactics(intel.suspicious_keywords)
    if tactics:
        notes_parts.append(f"Tactics Used: {tactics}")
    
    # Risk assessment
    risk_level = _assess_risk_level(intel, session.turn_count)
    notes_parts.append(f"Risk Level: {risk_level}")
    
    # Behavioral summary
    behavior = _analyze_scammer_behavior(session.messages)
    if behavior:
        notes_parts.append(f"Behavior: {behavior}")
    
    return ". ".join(notes_parts)


def _detect_scam_category(keywords: list) -> str:
    """Detect the type of scam based on keywords."""
    keywords_lower = [kw.lower() for kw in keywords]
    
    if any(kw in keywords_lower for kw in ['lottery', 'prize', 'won', 'winner', 'jackpot']):
        return "Lottery/Prize Scam"
    elif any(kw in keywords_lower for kw in ['kyc', 'verify', 'blocked', 'suspended', 'account will be blocked']):
        return "KYC/Phishing Scam"
    elif any(kw in keywords_lower for kw in ['invest', 'returns', 'profit', 'trading', 'crypto']):
        return "Investment Fraud"
    elif any(kw in keywords_lower for kw in ['job', 'work from home', 'part time', 'salary']):
        return "Job Scam"
    elif any(kw in keywords_lower for kw in ['police', 'arrest', 'legal', 'customs', 'parcel']):
        return "Impersonation/Authority Scam"
    elif any(kw in keywords_lower for kw in ['otp', 'pin', 'password', 'cvv']):
        return "Credential Theft Attempt"
    elif any(kw in keywords_lower for kw in ['transfer', 'send money', 'pay', 'advance']):
        return "Payment Fraud"
    return "Suspected Scam"


def _analyze_threat_tactics(keywords: list) -> str:
    """Analyze threat tactics used by scammer."""
    tactics = []
    keywords_lower = [kw.lower() for kw in keywords]
    
    # Urgency tactics
    urgency_words = ['urgent', 'immediately', 'right now', 'today', 'expires', 'last chance']
    if any(kw in keywords_lower for kw in urgency_words):
        tactics.append("Urgency pressure")
    
    # Fear tactics
    fear_words = ['blocked', 'suspended', 'legal action', 'arrest', 'police', 'fine']
    if any(kw in keywords_lower for kw in fear_words):
        tactics.append("Fear/Intimidation")
    
    # Authority impersonation
    authority_words = ['bank', 'rbi', 'government', 'officer', 'official', 'customs']
    if any(kw in keywords_lower for kw in authority_words):
        tactics.append("Authority impersonation")
    
    # Greed exploitation
    greed_words = ['prize', 'won', 'lottery', 'cashback', 'reward', 'bonus']
    if any(kw in keywords_lower for kw in greed_words):
        tactics.append("Greed exploitation")
    
    # Personal info request
    info_words = ['otp', 'pin', 'password', 'cvv', 'account number']
    if any(kw in keywords_lower for kw in info_words):
        tactics.append("Personal info extraction")
    
    return ", ".join(tactics) if tactics else "Standard social engineering"


def _assess_risk_level(intel, turn_count: int) -> str:
    """Assess the risk level of the scam attempt."""
    risk_score = 0
    
    # Intelligence factors
    if intel.upi_ids:
        risk_score += 3
    if intel.bank_accounts:
        risk_score += 3
    if intel.phishing_links:
        risk_score += 4
    if intel.phone_numbers:
        risk_score += 1
    
    # Keyword factors
    high_risk_keywords = ['otp', 'pin', 'password', 'cvv', 'transfer', 'send money']
    if any(kw.lower() in high_risk_keywords for kw in intel.suspicious_keywords):
        risk_score += 3
    
    # Engagement persistence
    if turn_count >= 5:
        risk_score += 2
    
    if risk_score >= 8:
        return "HIGH - Active financial threat"
    elif risk_score >= 4:
        return "MEDIUM - Confirmed scam attempt"
    else:
        return "LOW - Potential scam"


def _analyze_scammer_behavior(messages: list) -> str:
    """Analyze scammer behavior patterns from message history."""
    if not messages:
        return ""
    
    behaviors = []
    scammer_messages = [m for m in messages if m.get('role') == 'user']
    
    if len(scammer_messages) >= 3:
        # Check for escalation
        recent = scammer_messages[-3:]
        payment_mentions = sum(1 for m in recent if any(
            kw in m.get('content', '').lower() 
            for kw in ['pay', 'send', 'transfer', 'upi', 'money']
        ))
        if payment_mentions >= 2:
            behaviors.append("Escalating payment demands")
    
    # Check for repetition
    if len(scammer_messages) >= 2:
        contents = [m.get('content', '').lower() for m in scammer_messages]
        if len(set(contents)) < len(contents) * 0.7:
            behaviors.append("Repetitive messaging")
    
    # Check for persistence
    if len(scammer_messages) >= 5:
        behaviors.append("Persistent engagement")
    
    return ", ".join(behaviors) if behaviors else "Standard scam patterns"


async def update_agent_state(
    session: SessionState,
    message: str,
    role: str
) -> SessionState:
    session.messages.append({
        "role": role,
        "content": message,
        "timestamp": datetime.now(timezone.utc).isoformat()
    })
    
    if role == "scammer":
        session.turn_count += 1
    
    session.last_updated = datetime.now(timezone.utc)
    
    return session
