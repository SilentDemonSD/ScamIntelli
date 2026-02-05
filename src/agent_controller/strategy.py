from typing import Tuple, Optional
from src.models import SessionState, AgentReply, PersonaStyle, ExtractedIntelligence
from src.scam_detector.classifier import detect_scam
from src.scam_detector.scam_types import ScamCategory, detect_scam_category, get_scam_profile
from src.intelligence_extractor.extractor import extract_all_intelligence, has_sufficient_intelligence
from src.persona_engine.personas import (
    PersonaType, select_persona_for_scam, generate_persona_response,
    get_exit_response, adapt_response_to_context, get_persona_profile
)
from src.security.tamper_proof import ResponseObfuscator
from src.session_manager.session_store import update_session
from src.config import get_settings

settings = get_settings()


class EngagementStrategy:
    
    STRATEGY_CONFIGS = {
        ScamCategory.DIGITAL_ARREST: {
            "max_turns": 12,
            "intel_priority": ["phone_numbers", "bank_accounts", "upi_ids"],
            "delay_factor": 1.5,
            "compliance_level": 0.8,
            "fear_response": True
        },
        ScamCategory.KYC_PHISHING: {
            "max_turns": 8,
            "intel_priority": ["phishing_links", "upi_ids", "phone_numbers"],
            "delay_factor": 1.0,
            "compliance_level": 0.6,
            "fear_response": False
        },
        ScamCategory.INVESTMENT_FRAUD: {
            "max_turns": 10,
            "intel_priority": ["upi_ids", "bank_accounts", "phishing_links"],
            "delay_factor": 0.8,
            "compliance_level": 0.7,
            "fear_response": False
        },
        ScamCategory.JOB_SCAM: {
            "max_turns": 8,
            "intel_priority": ["upi_ids", "phone_numbers", "phishing_links"],
            "delay_factor": 0.9,
            "compliance_level": 0.7,
            "fear_response": False
        },
        ScamCategory.CUSTOMS_PARCEL: {
            "max_turns": 10,
            "intel_priority": ["bank_accounts", "upi_ids", "phone_numbers"],
            "delay_factor": 1.2,
            "compliance_level": 0.6,
            "fear_response": True
        },
        ScamCategory.ROMANCE_SCAM: {
            "max_turns": 15,
            "intel_priority": ["bank_accounts", "phishing_links", "phone_numbers"],
            "delay_factor": 1.3,
            "compliance_level": 0.9,
            "fear_response": False
        },
        ScamCategory.SEXTORTION: {
            "max_turns": 5,
            "intel_priority": ["bank_accounts", "upi_ids"],
            "delay_factor": 0.5,
            "compliance_level": 0.3,
            "fear_response": True
        },
        ScamCategory.QR_CODE_SCAM: {
            "max_turns": 6,
            "intel_priority": ["upi_ids", "phone_numbers"],
            "delay_factor": 0.7,
            "compliance_level": 0.5,
            "fear_response": False
        }
    }
    
    DEFAULT_CONFIG = {
        "max_turns": 10,
        "intel_priority": ["upi_ids", "phone_numbers", "phishing_links"],
        "delay_factor": 1.0,
        "compliance_level": 0.5,
        "fear_response": False
    }
    
    @classmethod
    def get_config(cls, category: ScamCategory) -> dict:
        return cls.STRATEGY_CONFIGS.get(category, cls.DEFAULT_CONFIG)
    
    @classmethod
    def should_continue_engagement(
        cls,
        session: SessionState,
        scam_category: ScamCategory,
        intel: ExtractedIntelligence
    ) -> Tuple[bool, str]:
        config = cls.get_config(scam_category)
        
        if session.turn_count >= config["max_turns"]:
            return False, "max_turns_reached"
        
        intel_score = 0
        if intel.upi_ids:
            intel_score += 3
        if intel.bank_accounts:
            intel_score += 3
        if intel.phishing_links:
            intel_score += 4
        if intel.phone_numbers:
            intel_score += 1
        
        if intel_score >= 7 and session.turn_count >= 3:
            return False, "sufficient_intel"
        
        recent_msgs = session.messages[-4:] if len(session.messages) >= 4 else session.messages
        payment_pressure = sum(
            1 for m in recent_msgs
            if m.get('role') in ('user', 'scammer') and
            any(kw in m.get('content', '').lower() for kw in ['pay', 'send', 'transfer', 'now', 'immediately'])
        )
        if payment_pressure >= 3:
            return False, "payment_pressure"
        
        return True, "continue"


async def process_message(session: SessionState, message: str) -> Tuple[SessionState, AgentReply]:
    scam_result = await detect_scam(message)
    
    scam_category = ScamCategory.UNKNOWN
    if scam_result.is_scam or session.scam_detected:
        all_keywords = session.extracted_intel.suspicious_keywords.copy()
        scam_category, confidence = detect_scam_category(message, all_keywords)
    
    newly_detected = scam_result.is_scam and not session.scam_detected
    
    if newly_detected:
        session.scam_detected = True
        session.scam_category = scam_category
        persona_type = select_persona_for_scam(scam_category, session.turn_count)
        session.persona_type = persona_type
        session.persona_style = _map_persona_to_style(persona_type)
    
    session.extracted_intel = await extract_all_intelligence(message, session.extracted_intel)
    
    session = await _update_state(session, message, "scammer")
    
    should_continue, end_reason = EngagementStrategy.should_continue_engagement(
        session, getattr(session, 'scam_category', ScamCategory.UNKNOWN), session.extracted_intel
    )
    
    if not should_continue:
        session.engagement_active = False
        persona_type = getattr(session, 'persona_type', PersonaType.TECH_NAIVE)
        reply_text = get_exit_response(persona_type)
    elif session.scam_detected and session.engagement_active:
        persona_type = getattr(session, 'persona_type', PersonaType.TECH_NAIVE)
        scam_cat = getattr(session, 'scam_category', ScamCategory.UNKNOWN)
        
        reply_text = await generate_persona_response(
            persona_type, scam_cat, message, session.messages, session.turn_count
        )
        
        reply_text = await adapt_response_to_context(reply_text, message, scam_cat)
        
        profile = get_persona_profile(persona_type)
        reply_text = ResponseObfuscator.humanize_response(
            reply_text, profile.language_style, add_fillers=(session.turn_count > 1)
        )
    elif session.scam_detected:
        persona_type = getattr(session, 'persona_type', PersonaType.TECH_NAIVE)
        reply_text = get_exit_response(persona_type)
    else:
        reply_text = "Thank you for your message."
    
    session = await _update_state(session, reply_text, "agent")
    await update_session(session)
    
    return session, AgentReply(
        status="success",
        reply=reply_text,
        session_id=session.session_id,
        scam_detected=session.scam_detected,
        engagement_active=session.engagement_active
    )


def _map_persona_to_style(persona_type: PersonaType) -> PersonaStyle:
    anxious_personas = {
        PersonaType.ELDERLY_ANXIOUS, PersonaType.SCARED_VICTIM,
        PersonaType.WORRIED_PARENT, PersonaType.LONELY_SENIOR
    }
    cooperative_personas = {
        PersonaType.TRUSTING_HOUSEWIFE, PersonaType.FIRST_TIME_SELLER,
        PersonaType.GREEDY_INVESTOR, PersonaType.DESPERATE_JOBSEEKER
    }
    
    if persona_type in anxious_personas:
        return PersonaStyle.ANXIOUS
    elif persona_type in cooperative_personas:
        return PersonaStyle.COOPERATIVE
    return PersonaStyle.CONFUSED


async def _update_state(session: SessionState, message: str, role: str) -> SessionState:
    from datetime import datetime, timezone
    
    session.messages.append({
        "role": role,
        "content": message,
        "timestamp": datetime.now(timezone.utc).isoformat()
    })
    
    if role == "scammer":
        session.turn_count += 1
    
    session.last_updated = datetime.now(timezone.utc)
    return session


async def should_trigger_callback(session: SessionState) -> bool:
    if not session.scam_detected:
        return False
    
    if session.engagement_active:
        return False
    
    has_intel = await has_sufficient_intelligence(session.extracted_intel)
    return has_intel or session.turn_count >= 5


async def get_engagement_summary(session: SessionState) -> dict:
    from src.agent_controller.agent_state import generate_agent_notes
    
    notes = await generate_agent_notes(session)
    scam_category = getattr(session, 'scam_category', ScamCategory.UNKNOWN)
    persona_type = getattr(session, 'persona_type', PersonaType.TECH_NAIVE)
    
    return {
        "session_id": session.session_id,
        "scam_detected": session.scam_detected,
        "scam_category": scam_category.value if scam_category else "unknown",
        "total_turns": session.turn_count,
        "persona_used": persona_type.value if persona_type else session.persona_style.value,
        "intelligence_collected": {
            "upi_ids": len(session.extracted_intel.upi_ids),
            "phone_numbers": len(session.extracted_intel.phone_numbers),
            "bank_accounts": len(session.extracted_intel.bank_accounts),
            "phishing_links": len(session.extracted_intel.phishing_links),
            "suspicious_keywords": len(session.extracted_intel.suspicious_keywords)
        },
        "notes": notes
    }
