from dataclasses import dataclass
from datetime import datetime, timezone
from typing import List, Tuple
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
        payment_requests = sum(
            1 for msg in recent_messages
            if any(kw in msg.get("content", "").lower() for kw in payment_keywords)
        )
        if payment_requests >= 2:
            conditions_met += 1
    
    return conditions_met >= 2


async def generate_agent_notes(session: SessionState) -> str:
    notes_parts = []
    intel = session.extracted_intel
    
    scam_type = _detect_scam_category(intel.suspicious_keywords)
    if scam_type:
        notes_parts.append(f"Scam Type: {scam_type}")
    
    notes_parts.append(f"Engagement: {session.turn_count} exchanges")
    
    intel_items = []
    if intel.upi_ids:
        intel_items.append(f"UPI: {', '.join(intel.upi_ids[:3])}")
    if intel.bank_accounts:
        intel_items.append(f"Accounts: {', '.join(intel.bank_accounts[:3])}")
    if intel.phone_numbers:
        intel_items.append(f"Phones: {', '.join(intel.phone_numbers[:3])}")
    if intel.phishing_links:
        intel_items.append(f"Links: {len(intel.phishing_links)}")
    
    if intel_items:
        notes_parts.append(f"Intel: {'; '.join(intel_items)}")
    
    tactics = _analyze_threat_tactics(intel.suspicious_keywords)
    if tactics:
        notes_parts.append(f"Tactics: {tactics}")
    
    risk_level = _assess_risk_level(intel, session.turn_count)
    notes_parts.append(f"Risk: {risk_level}")
    
    behavior = _analyze_scammer_behavior(session.messages)
    if behavior:
        notes_parts.append(f"Behavior: {behavior}")
    
    return ". ".join(notes_parts)


SCAM_CATEGORY_MAP = {
    ("digital arrest", "cbi", "cyber police", "enforcement", "ed notice", "narcotics"): "Digital Arrest Scam",
    ("lottery", "prize", "won", "winner", "jackpot", "lucky draw"): "Lottery/Prize Scam",
    ("kyc", "verify", "blocked", "suspended", "account will be blocked", "reactivate"): "KYC/Phishing Scam",
    ("invest", "returns", "profit", "trading", "crypto", "guaranteed"): "Investment Fraud",
    ("job", "work from home", "part time", "salary", "typing job", "data entry"): "Job Scam",
    ("police", "arrest", "legal", "customs", "parcel", "seized"): "Authority Impersonation",
    ("otp", "pin", "password", "cvv", "card number"): "Credential Theft",
    ("transfer", "send money", "pay", "advance", "fee"): "Payment Fraud",
    ("qr", "scan to receive", "olx"): "QR Code Scam",
    ("refund", "excess payment", "wrong transfer"): "Refund Scam",
    ("loan", "instant loan", "processing fee"): "Loan Fraud",
    ("video call", "recorded", "private"): "Sextortion"
}


def _detect_scam_category(keywords: list) -> str:
    keywords_lower = {kw.lower() for kw in keywords}
    
    for category_keywords, category_name in SCAM_CATEGORY_MAP.items():
        if any(kw in keywords_lower or any(kw in k for k in keywords_lower) for kw in category_keywords):
            return category_name
    
    return "Suspected Scam"


THREAT_TACTICS = {
    "Urgency": ("urgent", "immediately", "right now", "today", "expires", "last chance", "within 24"),
    "Fear": ("blocked", "suspended", "legal action", "arrest", "police", "fine", "jail", "fir"),
    "Authority": ("bank", "rbi", "government", "officer", "official", "customs", "cbi", "ed"),
    "Greed": ("prize", "won", "lottery", "cashback", "reward", "bonus", "returns", "profit"),
    "Info Extraction": ("otp", "pin", "password", "cvv", "account number", "card")
}


def _analyze_threat_tactics(keywords: list) -> str:
    keywords_lower = {kw.lower() for kw in keywords}
    tactics = []
    
    for tactic_name, tactic_words in THREAT_TACTICS.items():
        if any(tw in keywords_lower or any(tw in kw for kw in keywords_lower) for tw in tactic_words):
            tactics.append(tactic_name)
    
    return ", ".join(tactics) if tactics else "Social engineering"


def _assess_risk_level(intel, turn_count: int) -> str:
    risk_score = 0
    
    if intel.upi_ids:
        risk_score += 3
    if intel.bank_accounts:
        risk_score += 3
    if intel.phishing_links:
        risk_score += 4
    if intel.phone_numbers:
        risk_score += 1
    
    high_risk_keywords = {"otp", "pin", "password", "cvv", "transfer", "send money", "digital arrest"}
    if any(kw.lower() in high_risk_keywords for kw in intel.suspicious_keywords):
        risk_score += 3
    
    if turn_count >= 5:
        risk_score += 2
    
    if risk_score >= 8:
        return "HIGH"
    elif risk_score >= 4:
        return "MEDIUM"
    return "LOW"


def _analyze_scammer_behavior(messages: list) -> str:
    if not messages:
        return ""
    
    behaviors = []
    scammer_messages = [m for m in messages if m.get('role') in ('user', 'scammer')]
    
    if len(scammer_messages) >= 3:
        recent = scammer_messages[-3:]
        payment_mentions = sum(
            1 for m in recent
            if any(kw in m.get('content', '').lower() for kw in ('pay', 'send', 'transfer', 'upi', 'money'))
        )
        if payment_mentions >= 2:
            behaviors.append("Payment escalation")
    
    if len(scammer_messages) >= 2:
        contents = [m.get('content', '').lower() for m in scammer_messages]
        unique_ratio = len(set(contents)) / len(contents) if contents else 1
        if unique_ratio < 0.7:
            behaviors.append("Repetitive")
    
    if len(scammer_messages) >= 5:
        behaviors.append("Persistent")
    
    return ", ".join(behaviors) if behaviors else "Standard patterns"


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
    
    if role in ("scammer", "user"):
        session.turn_count += 1
    
    session.last_updated = datetime.now(timezone.utc)
    return session
