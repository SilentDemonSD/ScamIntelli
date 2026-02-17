import asyncio
import random
from datetime import datetime, timezone
from typing import Any, Dict, List, Tuple

from src.config import get_settings
from src.intelligence_extractor.extractor import (
    extract_all_intelligence,
    has_sufficient_intelligence,
    make_context_aware_probe,
)
from src.models import AgentReply, ExtractedIntelligence, PersonaStyle, SessionState
from src.persona_engine.age_adaptive import AgeAdaptivePersonaEngine
from src.persona_engine.emotional_intelligence import (
    EmotionalIntelligenceEngine,
)
from src.persona_engine.personas import (
    LanguageStyle,
    PersonaType,
    _ensure_persona_type,
    _ensure_scam_category,
    adapt_response_to_context,
    detect_scammer_language,
    generate_persona_response,
    get_exit_response,
    get_persona_profile,
    select_persona_for_scam,
)
from src.persona_engine.typing_simulator import HumanTypingSimulator
from src.scam_detector.classifier import detect_scam
from src.scam_detector.hybrid_engine import HybridScamDetectionEngine
from src.scam_detector.meta_detector import MetaScamDetector
from src.scam_detector.ml_engine import PatternLearner
from src.scam_detector.multilingual_detector import MultiLingualDetector
from src.scam_detector.scam_types import ScamCategory, detect_scam_category
from src.scam_detector.url_document_detector import MultiModalScamDetector
from src.security.jailbreak_guard import AntiJailbreakLayer
from src.security.tamper_proof import ResponseObfuscator
from src.session_manager.session_store import update_session
from src.utils.logging import log_session

settings = get_settings()


class ConversationContextTracker:
    """Analyzes recent messages to track scammer tactics and agent state."""

    @staticmethod
    def analyze_conversation_flow(messages: List[dict]) -> Dict[str, Any]:
        """Derive urgency, threats, info requests and emotional state from recent messages."""
        context = {
            "scammer_urgency": 0,
            "agent_compliance_shown": 0,
            "info_requested_count": 0,
            "threats_made": 0,
            "emotional_state": "neutral",
            "pending_actions": [],
            "scammer_language_trend": LanguageStyle.HINGLISH_HEAVY_ENGLISH,
            "last_scammer_topics": [],
        }

        if not messages:
            return context

        urgency_keywords = {
            "immediately",
            "urgent",
            "now",
            "quickly",
            "fast",
            "abhi",
            "jaldi",
            "turant",
        }
        threat_keywords = {
            "arrest",
            "police",
            "jail",
            "court",
            "case",
            "block",
            "freeze",
            "legal",
            "FIR",
        }
        info_keywords = {
            "otp",
            "pin",
            "password",
            "cvv",
            "account",
            "upi",
            "aadhaar",
            "pan",
        }
        compliance_keywords = {
            "okay",
            "theek",
            "haan",
            "yes",
            "alright",
            "kar raha",
            "sending",
        }

        for msg in messages[-8:]:
            content = msg.get("content", "").lower()
            role = msg.get("role", "")

            if role in ("user", "scammer"):
                context["scammer_urgency"] += len(
                    [kw for kw in urgency_keywords if kw in content]
                )
                context["threats_made"] += len(
                    [kw for kw in threat_keywords if kw in content]
                )
                context["info_requested_count"] += len(
                    [kw for kw in info_keywords if kw in content]
                )

                if any(kw in content for kw in ("otp", "pin", "password")):
                    context["last_scammer_topics"].append("credentials")
                if any(kw in content for kw in ("pay", "transfer", "send", "upi")):
                    context["last_scammer_topics"].append("payment")
                if any(kw in content for kw in ("arrest", "police", "legal")):
                    context["last_scammer_topics"].append("threat")

            elif role == "agent":
                context["agent_compliance_shown"] += len(
                    [kw for kw in compliance_keywords if kw in content]
                )

                if any(
                    phrase in content
                    for phrase in ("dhundh raha", "check kar", "looking", "finding")
                ):
                    context["pending_actions"].append("searching")
                if any(phrase in content for phrase in ("bank ja", "atm", "withdraw")):
                    context["pending_actions"].append("going_to_bank")

        if context["threats_made"] > 2:
            context["emotional_state"] = "fearful"
        elif context["scammer_urgency"] > 3:
            context["emotional_state"] = "anxious"
        elif context["agent_compliance_shown"] > 2:
            context["emotional_state"] = "compliant"

        if scammer_msgs := [
            m.get("content", "")
            for m in messages[-4:]
            if m.get("role") in ("user", "scammer")
        ]:
            context["scammer_language_trend"] = detect_scammer_language(
                " ".join(scammer_msgs)
            )

        return context

    @staticmethod
    def get_contextual_response_hint(context: Dict[str, Any], turn_count: int) -> str:
        """Produce a short hint string guiding the agent's next response tone."""
        hints = []

        if context["emotional_state"] == "fearful":
            hints.append("Show genuine fear, ask for reassurance")
        elif context["emotional_state"] == "anxious":
            hints.append("Show nervousness, mention family concerns")

        if "credentials" in context["last_scammer_topics"]:
            hints.append("Stall on OTP/credentials - pretend to search")
        if "payment" in context["last_scammer_topics"]:
            hints.append("Ask about amount, mention low balance")
        if "threat" in context["last_scammer_topics"]:
            hints.append("Plead innocence, show fear of consequences")

        if "searching" in context["pending_actions"]:
            hints.append("Continue pretending to search/find something")
        if "going_to_bank" in context["pending_actions"]:
            hints.append("Mention you need to go to bank/ATM")

        if turn_count > 5 and context["agent_compliance_shown"] < 2:
            hints.append("Show slightly more willingness to cooperate")

        return "; ".join(hints) if hints else "Respond naturally as the persona"


class EngagementStrategy:
    STRATEGY_CONFIGS = {
        ScamCategory.DIGITAL_ARREST: {
            "max_turns": 12,
            "intel_priority": ["phone_numbers", "bank_accounts", "upi_ids"],
            "delay_factor": 1.5,
            "compliance_level": 0.8,
            "fear_response": True,
        },
        ScamCategory.KYC_PHISHING: {
            "max_turns": 8,
            "intel_priority": ["phishing_links", "upi_ids", "phone_numbers"],
            "delay_factor": 1.0,
            "compliance_level": 0.6,
            "fear_response": False,
        },
        ScamCategory.INVESTMENT_FRAUD: {
            "max_turns": 10,
            "intel_priority": ["upi_ids", "bank_accounts", "phishing_links"],
            "delay_factor": 0.8,
            "compliance_level": 0.7,
            "fear_response": False,
        },
        ScamCategory.JOB_SCAM: {
            "max_turns": 8,
            "intel_priority": ["upi_ids", "phone_numbers", "phishing_links"],
            "delay_factor": 0.9,
            "compliance_level": 0.7,
            "fear_response": False,
        },
        ScamCategory.CUSTOMS_PARCEL: {
            "max_turns": 10,
            "intel_priority": ["bank_accounts", "upi_ids", "phone_numbers"],
            "delay_factor": 1.2,
            "compliance_level": 0.6,
            "fear_response": True,
        },
        ScamCategory.ROMANCE_SCAM: {
            "max_turns": 15,
            "intel_priority": ["bank_accounts", "phishing_links", "phone_numbers"],
            "delay_factor": 1.3,
            "compliance_level": 0.9,
            "fear_response": False,
        },
        ScamCategory.SEXTORTION: {
            "max_turns": 5,
            "intel_priority": ["bank_accounts", "upi_ids"],
            "delay_factor": 0.5,
            "compliance_level": 0.3,
            "fear_response": True,
        },
        ScamCategory.QR_CODE_SCAM: {
            "max_turns": 6,
            "intel_priority": ["upi_ids", "phone_numbers"],
            "delay_factor": 0.7,
            "compliance_level": 0.5,
            "fear_response": False,
        },
    }

    DEFAULT_CONFIG = {
        "max_turns": 10,
        "intel_priority": ["upi_ids", "phone_numbers", "phishing_links"],
        "delay_factor": 1.0,
        "compliance_level": 0.5,
        "fear_response": False,
    }

    @classmethod
    def get_config(cls, category: ScamCategory) -> dict:
        return cls.STRATEGY_CONFIGS.get(category, cls.DEFAULT_CONFIG)

    @classmethod
    def should_continue_engagement(
        cls, session: SessionState, scam_category, intel: ExtractedIntelligence
    ) -> Tuple[bool, str]:
        scam_category = _ensure_scam_category(scam_category)
        config = cls.get_config(scam_category)

        if session.turn_count >= config["max_turns"]:
            return False, "max_turns_reached"

        intel_score = (
            (3 if intel.upi_ids else 0)
            + (3 if intel.bank_accounts else 0)
            + (4 if intel.phishing_links else 0)
            + (1 if intel.phone_numbers else 0)
        )

        if intel_score >= 7 and session.turn_count >= 8:
            return False, "sufficient_intel"

        return True, "continue"


async def process_message(
    session: SessionState, message: str
) -> Tuple[SessionState, AgentReply]:
    """Process an incoming scammer message, detect scams, extract intel, and reply.

    Wrapped in a top-level safety net so that any uncaught exception still
    returns a valid AgentReply rather than crashing the session.
    """
    try:
        return await _process_message_inner(session, message)
    except Exception:
        import logging
        logging.getLogger(__name__).exception(
            "Unhandled error in process_message for session %s", session.session_id
        )
        # Return a safe fallback so the session isn't lost
        fallback = "Ek minute sir, phone mein kuch dikkat aa rahi hai... abhi try karta hun."
        session.messages.append({"role": "agent", "content": fallback,
                                  "timestamp": datetime.now(timezone.utc).isoformat()})
        try:
            await update_session(session)
        except Exception:
            pass
        return session, AgentReply(
            status="success",
            reply=fallback,
            session_id=session.session_id,
            scam_detected=session.scam_detected,
            engagement_active=session.engagement_active,
            confidence_score=0.0,
        )


async def _process_message_inner(
    session: SessionState, message: str
) -> Tuple[SessionState, AgentReply]:
    """Core message processing logic, called by process_message with error safety."""
    jailbreak_result = AntiJailbreakLayer.sanitize_input(message)
    if jailbreak_result.is_jailbreak:
        session.extracted_intel = await extract_all_intelligence(
            message, session.extracted_intel
        )
        session = await _update_state(session, message, "scammer")
        safe_reply = ResponseObfuscator.humanize_response(
            jailbreak_result.safe_response, "confused_human", add_fillers=True
        )
        session = await _update_state(session, safe_reply, "agent")
        await update_session(session)
        await log_session(session.session_id, message, "scammer", session.scam_detected, 0.0, session.scam_category)
        return session, AgentReply(
            status="success",
            reply=safe_reply,
            session_id=session.session_id,
            scam_detected=session.scam_detected,
            engagement_active=session.engagement_active,
            confidence_score=0.0,
        )

    meta_result = MetaScamDetector.analyze(
        message, session.session_id, session.messages
    )

    if meta_result.is_probe and meta_result.probe_type and not session.scam_detected:
        session.extracted_intel = await extract_all_intelligence(
            message, session.extracted_intel
        )
        counter_response = MetaScamDetector.get_counter_response(meta_result.probe_type)
        session = await _update_state(session, message, "scammer")
        counter_response = ResponseObfuscator.humanize_response(
            counter_response, "confused_human", add_fillers=True
        )
        session = await _update_state(session, counter_response, "agent")
        await update_session(session)
        await log_session(session.session_id, message, "scammer", session.scam_detected, 0.0, session.scam_category)
        return session, AgentReply(
            status="success",
            reply=counter_response,
            session_id=session.session_id,
            scam_detected=session.scam_detected,
            engagement_active=session.engagement_active,
            confidence_score=0.0,
        )

    async def _run_emotional_analysis():
        return EmotionalIntelligenceEngine.analyze(
            message, session.session_id, session.messages
        )

    emotional_analysis, multilingual_result, url_threat_result, scam_result = (
        await asyncio.gather(
            _run_emotional_analysis(),
            MultiLingualDetector.analyze(message, session.session_id),
            MultiModalScamDetector.analyze_message(message),
            detect_scam(message),
        )
    )

    if url_threat_result.intel_extracted.get("phishing_urls"):
        existing_links = set(session.extracted_intel.phishing_links)
        existing_links.update(url_threat_result.intel_extracted["phishing_urls"])
        session.extracted_intel.phishing_links = list(existing_links)

    hybrid_result = await HybridScamDetectionEngine.detect(
        message=message,
        session_messages=session.messages,
        emotional_score=emotional_analysis.emotion_intensity,
        multilingual_keywords=multilingual_result.scam_keywords_multilingual,
        url_threat_score=url_threat_result.overall_threat_score,
    )

    is_scam = (
        scam_result.is_scam
        or hybrid_result.is_scam
        or url_threat_result.phishing_urls_found > 0
    )

    if multilingual_result.scam_keywords_multilingual:
        existing_kw = set(session.extracted_intel.suspicious_keywords)
        existing_kw.update(multilingual_result.scam_keywords_multilingual)
        session.extracted_intel.suspicious_keywords = list(existing_kw)

    scam_category = ScamCategory.UNKNOWN
    if is_scam or session.scam_detected:
        all_keywords = session.extracted_intel.suspicious_keywords.copy()
        scam_category, _ = detect_scam_category(message, all_keywords)

    if is_scam and not session.scam_detected:
        session.scam_detected = True
        session.scam_category = (
            scam_category.value
            if hasattr(scam_category, "value")
            else str(scam_category)
        )
        persona_type = select_persona_for_scam(scam_category, session.turn_count)

        age_adaptation = AgeAdaptivePersonaEngine.adapt_persona(
            persona_type,
            session.scam_category,
            session.turn_count,
        )
        persona_type = age_adaptation.adapted_persona

        session.persona_type = (
            persona_type.value if hasattr(persona_type, "value") else str(persona_type)
        )
        session.persona_style = _map_persona_to_style(persona_type)

    session.extracted_intel = await extract_all_intelligence(
        message, session.extracted_intel
    )

    if multilingual_result.translated_text:
        translated_intel = await extract_all_intelligence(
            multilingual_result.translated_text, session.extracted_intel
        )
        session.extracted_intel = translated_intel

    session = await _update_state(session, message, "scammer")

    should_continue, _ = EngagementStrategy.should_continue_engagement(
        session, session.scam_category or ScamCategory.UNKNOWN, session.extracted_intel
    )

    if not should_continue:
        session.engagement_active = False
        persona_type = _ensure_persona_type(session.persona_type)
        reply_text = get_exit_response(persona_type)
        if session.scam_detected:
            PatternLearner.learn_from_conversation(
                session.messages,
                session.scam_category or "unknown",
                was_scam=True,
            )
    elif session.scam_detected and session.engagement_active:
        persona_type = _ensure_persona_type(session.persona_type)
        scam_cat = _ensure_scam_category(session.scam_category)

        conv_context = ConversationContextTracker.analyze_conversation_flow(
            session.messages
        )
        context_hint = ConversationContextTracker.get_contextual_response_hint(
            conv_context, session.turn_count
        )

        emotion_hint = EmotionalIntelligenceEngine.get_emotion_hint(emotional_analysis)
        context_hint = f"{context_hint}; {emotion_hint}" if context_hint else emotion_hint

        age_adaptation = AgeAdaptivePersonaEngine.adapt_persona(
            persona_type,
            scam_cat.value if hasattr(scam_cat, "value") else str(scam_cat),
            session.turn_count,
        )
        age_prompt = AgeAdaptivePersonaEngine.get_age_prompt_modifier(
            age_adaptation.selected_age_group
        )
        context_hint = f"{context_hint}\n{age_prompt}"
        context_hint = f"{context_hint}\nINTEL EXTRACTION: {age_adaptation.intel_extraction_hint}"

        jailbreak_protection = AntiJailbreakLayer.get_system_prompt_protection()
        context_hint = f"{jailbreak_protection}\n{context_hint}"

        if url_threat_result.phishing_urls_found > 0:
            context_hint += "\nURL DETECTED: Scammer sent suspicious URL. DO NOT click. Pretend link doesn't work, ask for details verbally instead."

        # Surface top red-flag signals so the agent can probe accordingly
        red_flag_summary = hybrid_result.get_red_flag_summary()
        if red_flag_summary["red_flags"]:
            flag_names = ", ".join(f["signal"] for f in red_flag_summary["red_flags"][:3])
            context_hint += f"\nACTIVE RED FLAGS: {flag_names}. Probe around these topics to elicit more intel."

        # Tell the AI which intel is still missing so it can weave in probing naturally
        missing_intel = _describe_missing_intel(session.extracted_intel)
        if missing_intel:
            context_hint += f"\nMISSING INTEL (try to extract naturally): {missing_intel}"

        reply_text = await generate_persona_response(
            persona_type,
            scam_cat,
            message,
            session.messages,
            session.turn_count,
            context_hint=context_hint,
        )

        reply_text = await adapt_response_to_context(
            reply_text, message, scam_cat, session.messages,
            turn_count=session.turn_count,
        )

        reply_text = _deduplicate_response(reply_text, session.messages)

        if url_threat_result.phishing_urls_found > 0 and session.turn_count <= 3:
            reply_text = MultiModalScamDetector.get_url_avoidance_response()

        reply_text = AgeAdaptivePersonaEngine.apply_age_artifacts(
            reply_text, age_adaptation.selected_age_group, session.turn_count
        )

        reply_text = HumanTypingSimulator.apply_typing_artifacts(
            reply_text, age_adaptation.selected_age_group
        )

        profile = get_persona_profile(persona_type)
        reply_text = ResponseObfuscator.humanize_response(
            reply_text, profile.language_style, add_fillers=(session.turn_count > 1)
        )
    elif session.scam_detected:
        persona_type = _ensure_persona_type(session.persona_type)
        reply_text = get_exit_response(persona_type)
    else:
        reply_text = _generate_dynamic_non_scam_response(message, session)

    _conf = hybrid_result.confidence if hybrid_result else 0.0

    if session.scam_detected and session.engagement_active:
        # Use context-aware probe when confidence is high enough
        probe = make_context_aware_probe(
            session.messages,
            session.extracted_intel,
            confidence=_conf,
        )
        if probe and _conf >= 0.5:
            reply_text = f"{reply_text} {probe}"
        else:
            intel_question = _get_intel_extraction_question(
                session.turn_count, session.extracted_intel
            )
            if intel_question:
                reply_text = f"{reply_text} {intel_question}"

    session = await _update_state(session, reply_text, "agent")

    session.confidence_level = _conf

    # Persist detection breakdown so /visualization has data immediately
    if hybrid_result is not None:
        session.detection_details = {
            "is_scam": hybrid_result.is_scam,
            "confidence": hybrid_result.confidence,
            "breakdown": hybrid_result.breakdown,
            "has_hard_indicators": hybrid_result.has_hard_indicators,
            "detection_layers_used": hybrid_result.detection_layers_used,
            "session_id": session.session_id,
            "scam_category": session.scam_category,
            "persona_type": session.persona_type,
            "turn_count": session.turn_count,
        }

    await update_session(session)

    await log_session(
        session.session_id, message, "scammer",
        session.scam_detected, _conf, session.scam_category,
    )

    return session, AgentReply(
        status="success",
        reply=reply_text,
        session_id=session.session_id,
        scam_detected=session.scam_detected,
        engagement_active=session.engagement_active,
        confidence_score=round(_conf, 4),
    )


def _map_persona_to_style(persona_type) -> PersonaStyle:
    persona_type = _ensure_persona_type(persona_type)
    anxious_personas = {
        PersonaType.ELDERLY_ANXIOUS,
        PersonaType.SCARED_VICTIM,
        PersonaType.WORRIED_PARENT,
        PersonaType.LONELY_SENIOR,
    }
    cooperative_personas = {
        PersonaType.TRUSTING_HOUSEWIFE,
        PersonaType.FIRST_TIME_SELLER,
        PersonaType.GREEDY_INVESTOR,
        PersonaType.DESPERATE_JOBSEEKER,
    }

    if persona_type in anxious_personas:
        return PersonaStyle.ANXIOUS
    elif persona_type in cooperative_personas:
        return PersonaStyle.COOPERATIVE
    return PersonaStyle.CONFUSED


def _deduplicate_response(reply: str, messages: list) -> str:
    recent_agent_msgs = [
        m.get("content", "").strip().lower()
        for m in messages[-10:]
        if m.get("role") == "agent"
    ]

    if not recent_agent_msgs:
        return reply

    reply_lower = reply.strip().lower()

    for prev in recent_agent_msgs:
        if not prev or not reply_lower:
            continue
        if reply_lower == prev:
            return _get_varied_response(reply, messages)
        if len(reply_lower) > 10 and len(prev) > 10:
            reply_words = set(reply_lower.split())
            prev_words = set(prev.split())
            if reply_words and prev_words:
                overlap = len(reply_words & prev_words) / max(len(reply_words), 1)
                if overlap > 0.8:
                    return _get_varied_response(reply, messages)

    return reply


def _get_varied_response(original: str, messages: list) -> str:
    varied_stalls = [
        "Ek minute sir, phone mein kuch dikkat aa rahi hai.",
        "Haan ji, main dekh raha hun, thoda time lagega.",
        "Sir aapka number note kar raha hun, ek second.",
        "Abhi check kar raha hun, hold karo please.",
        "Bhai net slow hai, page load nahi ho raha.",
        "Arre haan haan, ruko na, kar raha hun.",
        "Phone garam ho gaya hai sir, thoda ruk jao.",
        "Battery low hai, charger pe laga raha hun pehle.",
        "Ek minute, padosi bula raha hai, aata hun.",
        "Sir pehle wala message clear nahi aaya tha, ab samjha.",
        "Haan sir bas 2 minute, bahu khana de rahi hai.",
        "Sorry sir, phone neeche gir gaya tha, ab batao.",
    ]

    recent_used = {
        m.get("content", "").strip().lower()
        for m in messages[-10:]
        if m.get("role") == "agent"
    }
    available = [r for r in varied_stalls if r.lower() not in recent_used]
    return random.choice(available) if available else random.choice(varied_stalls)


_PHONE_QUESTIONS = [
    "btw sir aapka phone number batao, agar call drop ho jaye toh?",
    "sir aapka contact number de do, callback karunga verification ke liye.",
    "ek baat batao, aapka phone number kya hai? Main note kar leta hun.",
]

_UPI_QUESTIONS = [
    "sir aapka UPI ID bhi batao, mujhe verify karna padega.",
    "aapka UPI ID kya hai? Main payment details check karunga.",
    "UPI se karna padega kya? UPI ID batao toh.",
]

_EMAIL_QUESTIONS = [
    "sir aapka email ID kya hai? Main complaints cell ko bhi inform karunga.",
    "email address de do sir, documentation ke liye chahiye.",
    "official email bhi bhej do sir, record ke liye.",
]


def _get_intel_extraction_question(
    turn_count: int, intel,
) -> str:
    """Return an intel-eliciting question based on turn count and missing data.

    Now covers all turns (not just 3-7) by cycling through missing intel
    types so the agent keeps probing throughout the conversation.
    """
    if turn_count == 3 and not intel.phone_numbers:
        return random.choice(_PHONE_QUESTIONS)
    if turn_count == 4 and not intel.upi_ids:
        return random.choice(_UPI_QUESTIONS)
    if turn_count == 5 and not intel.email_addresses:
        return random.choice(_EMAIL_QUESTIONS)
    if turn_count == 6 and not intel.phone_numbers:
        return random.choice(_PHONE_QUESTIONS)
    if turn_count == 7:
        missing = []
        if not intel.phone_numbers:
            missing.append("phone number")
        if not intel.upi_ids:
            missing.append("UPI ID")
        if missing:
            items = " aur ".join(missing)
            return f"sir ek last thing, aapka {items} bhi de do."

    # For turns 8+, keep cycling through missing intel types
    if turn_count >= 8:
        candidates = []
        if not intel.phone_numbers:
            candidates.append(random.choice(_PHONE_QUESTIONS))
        if not intel.upi_ids:
            candidates.append(random.choice(_UPI_QUESTIONS))
        if not intel.email_addresses:
            candidates.append(random.choice(_EMAIL_QUESTIONS))
        if candidates:
            # Rotate by turn to avoid repeating the same question back-to-back
            return candidates[turn_count % len(candidates)]

    return ""


def _describe_missing_intel(intel: ExtractedIntelligence) -> str:
    """Build a human-readable summary of which intel types are still needed."""
    missing = []
    if not intel.phone_numbers:
        missing.append("phone number")
    if not intel.upi_ids:
        missing.append("UPI ID")
    if not intel.email_addresses:
        missing.append("email address")
    if not intel.bank_accounts:
        missing.append("bank account number")
    if not intel.phishing_links:
        missing.append("any URLs/links they share")
    return ", ".join(missing) if missing else ""


def _generate_dynamic_non_scam_response(message: str, session: SessionState) -> str:
    msg_lower = message.lower()
    turn = session.turn_count

    greetings = {"hi", "hello", "hey", "namaste", "namaskar", "assalamualaikum", "good morning", "good evening"}
    if any(g in msg_lower for g in greetings):
        responses = [
            "Namaste ji! Kaun bol rahe hain?",
            "Hello ji, haan boliye.",
            "Haan ji, kaun hai?",
            "Ji haan, boliye kaun?",
            "Namaskar, aap kaun bol rahe hain?",
            "Hello, haan ji batao.",
        ]
        return random.choice(responses)

    identity_kw = {"kaun", "who", "kahan se", "where from", "which company", "konsi company"}
    if any(kw in msg_lower for kw in identity_kw):
        responses = [
            "Ji aap kaun bol rahe hain? Mujhe nahi pata aap kaun hain.",
            "Sorry, aapka number save nahi hai mere paas. Kaun hai?",
            "Pehle bataiye aap kaun hain. Main kisi ko bhi apni details nahi deta.",
            "Aap kaun hain ji? Kahan se bol rahe ho?",
        ]
        return random.choice(responses)

    if turn <= 1:
        first_turn = [
            "Ji haan, boliye kya baat hai?",
            "Haan ji, kuch kaam tha kya?",
            "Hello ji, batao kya hua?",
            "Ji, kaun bol rahe hain? Kuch kaam hai?",
            "Haan ji suno.",
        ]
        return random.choice(first_turn)

    if turn <= 3:
        early_turn = [
            "Accha ji, thoda detail mein batao. Samajh nahi aaya.",
            "Haan ji main sun raha hun. Aage boliye.",
            "Theek hai, aur batao kya karna hai?",
            "Okay ji, continue karo. Main sun raha hun.",
            "Haan haan, aur kya hua? Batao.",
        ]
        return random.choice(early_turn)

    later_turn = [
        "Accha ji, main soch kar batata hun.",
        "Hmm, samajh gaya. Ek minute sochne do.",
        "Theek hai ji, lekin mujhe thoda time chahiye.",
        "Okay, main dekh raha hun. Aap thoda ruko.",
        "Haan ji, mujhe kisi se pooch lene do pehle.",
        "Accha accha, ek minute. Meri wife bula rahi hai.",
    ]
    recent_used = {
        m.get("content", "").strip().lower()
        for m in session.messages[-6:]
        if m.get("role") == "agent"
    }
    available = [r for r in later_turn if r.lower() not in recent_used]
    return random.choice(available) if available else random.choice(later_turn)


async def _update_state(session: SessionState, message: str, role: str) -> SessionState:

    session.messages.append(
        {
            "role": role,
            "content": message,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
    )

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
    scam_category = _ensure_scam_category(getattr(session, "scam_category", None))
    persona_type = _ensure_persona_type(getattr(session, "persona_type", None))

    age_adaptation = AgeAdaptivePersonaEngine.adapt_persona(
        persona_type,
        scam_category.value if scam_category else "unknown",
        session.turn_count,
    )

    return {
        "session_id": session.session_id,
        "scam_detected": session.scam_detected,
        "scam_category": scam_category.value if scam_category else "unknown",
        "total_turns": session.turn_count,
        "persona_used": persona_type.value
        if persona_type
        else session.persona_style.value,
        "age_group": age_adaptation.selected_age_group.value,
        "intelligence_collected": {
            "upi_ids": len(session.extracted_intel.upi_ids),
            "phone_numbers": len(session.extracted_intel.phone_numbers),
            "bank_accounts": len(session.extracted_intel.bank_accounts),
            "phishing_links": len(session.extracted_intel.phishing_links),
            "suspicious_keywords": len(session.extracted_intel.suspicious_keywords),
        },
        "notes": notes,
    }
