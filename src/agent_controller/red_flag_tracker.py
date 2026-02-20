"""
Module: agent_controller.red_flag_tracker

Purpose:
    Red flag detection, tracking, and probing system for scam conversations.
    Maintains a running tally of scam indicators and generates targeted questions
    to probe suspicious behaviors and expose contradictions.

Key Components:
    - RedFlagDetector: Analyses messages for red flag patterns (12 flag types)
    - RedFlagProber: Generates challenging questions based on detected flags
    - RedFlagInstance: Data class for a single red flag occurrence

Design Patterns:
    - Strategy pattern for per-flag-type probing questions
    - Observer pattern: flags are accumulated and analysed across the session

Author: ScamIntelli Team
Last Modified: 2026-02-20
Version: 2.0
"""

import logging
import re
import random
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


class RedFlagType(str, Enum):
    """Categories of red flags in scam conversations."""
    URGENCY_PRESSURE = "urgency_pressure"
    THREAT_INTIMIDATION = "threat_intimidation"
    CREDENTIAL_REQUEST = "credential_request"
    PAYMENT_DEMAND = "payment_demand"
    AUTHORITY_CLAIM = "authority_claim"
    VERIFICATION_AVOIDANCE = "verification_avoidance"
    PROCESS_IRREGULARITY = "process_irregularity"
    SECRECY_DEMAND = "secrecy_demand"
    PERSONAL_INFO_PROBE = "personal_info_probe"
    LINK_PRESSURE = "link_pressure"
    TRUST_BUILDING = "trust_building"
    TIME_CONSTRAINT = "time_constraint"


@dataclass
class RedFlagInstance:
    """Single occurrence of a red flag.

    Attributes:
        flag_type: Type of the red flag.
        turn_number: Conversation turn when detected.
        message_content: The specific phrase that triggered the flag.
        confidence: Detection confidence 0.0–1.0.
        timestamp: When the flag was detected.
    """
    flag_type: RedFlagType
    turn_number: int
    message_content: str
    confidence: float
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for logging/storage."""
        return {
            "flag_type": self.flag_type.value,
            "turn": self.turn_number,
            "content_snippet": self.message_content[:100],
            "confidence": round(self.confidence, 3),
            "timestamp": self.timestamp.isoformat(),
        }


class RedFlagDetector:
    """Detects red flags in scammer messages using keyword analysis and patterns.

    Goes beyond basic keyword matching to identify behavioral patterns
    that indicate scam tactics.  Covers all 12 red flag types.
    """

    RED_FLAG_PATTERNS: Dict[RedFlagType, Dict[str, Any]] = {
        RedFlagType.URGENCY_PRESSURE: {
            "keywords": [
                "urgent", "immediately", "right now", "abhi", "turant", "jaldi",
                "fast", "quickly", "hurry", "don't delay", "time is running",
                "avi", "ek minute mein", "2 minutes", "5 minutes", "now only",
                "last chance", "aakhri mauka",
            ],
            "phrases": [
                "do it now or",
                "you have only",
                "last chance",
                "time running out",
                "before it's too late",
                "aakhri mauka",
                "abhi karo warna",
            ],
            "confidence_base": 0.80,
        },
        RedFlagType.THREAT_INTIMIDATION: {
            "keywords": [
                "arrest", "police", "jail", "court", "legal action", "fir",
                "warrant", "case", "investigation", "cybercrime", "ed notice",
                "income tax raid", "customs seizure", "blocked", "suspended",
                "frozen account", "criminal case", "chargesheet", "giraftaar",
                "thana", "jail bhejenge", "andar kar denge",
            ],
            "phrases": [
                "arrest warrant issued",
                "police will come",
                "legal notice sent",
                "account will be blocked",
                "you'll go to jail",
                "gir dange andar",
                "action le lenge",
                "fir darj ho jayegi",
            ],
            "confidence_base": 0.90,
        },
        RedFlagType.CREDENTIAL_REQUEST: {
            "keywords": [
                "otp", "pin", "password", "cvv", "card number", "atm pin",
                "mpin", "passcode", "security code", "verification code",
                "net banking password", "login details",
            ],
            "phrases": [
                "share your otp",
                "send otp",
                "tell me the otp",
                "otp batao",
                "otp bhejo",
                "provide your pin",
                "enter your password",
                "screen share",
                "anydesk install",
                "teamviewer",
            ],
            "confidence_base": 0.95,
        },
        RedFlagType.PAYMENT_DEMAND: {
            "keywords": [
                "pay", "send money", "transfer", "fee", "charges", "deposit",
                "processing fee", "registration fee", "advance payment",
                "fine", "penalty", "bhejo", "paisa", "rupees", "rs",
            ],
            "phrases": [
                "send money to",
                "transfer amount",
                "pay the fee",
                "pay immediately",
                "processing fee required",
                "advance payment",
                "deposit first",
                "paise bhejo",
                "paisa transfer karo",
            ],
            "confidence_base": 0.85,
        },
        RedFlagType.AUTHORITY_CLAIM: {
            "keywords": [
                "officer", "inspector", "police", "cbi", "enforcement directorate", "customs",
                "bank manager", "rbi", "government", "ips", "ias",
                "department", "official", "ministry", "magistrate",
                "income tax", "cyber cell",
            ],
            "phrases": [
                "i am officer",
                "calling from police",
                "this is cbi",
                "bank se bol raha",
                "government order",
                "rbi directive",
                "senior officer",
                "headquarters se",
            ],
            "confidence_base": 0.80,
        },
        RedFlagType.VERIFICATION_AVOIDANCE: {
            "keywords": [
                "cannot", "not possible", "confidential", "classified",
                "protocol", "cannot share", "not allowed", "restricted",
            ],
            "phrases": [
                "i cannot share",
                "that's confidential",
                "not allowed to disclose",
                "classified information",
                "security protocol",
                "nahi bata sakte",
                "rules ke against",
            ],
            "confidence_base": 0.75,
        },
        RedFlagType.PROCESS_IRREGULARITY: {
            "keywords": [
                "qr code", "scan to receive", "scan karke",
                "remote access", "anydesk", "teamviewer",
                "screen share", "download app", "install",
            ],
            "phrases": [
                "scan this qr to receive money",
                "install this app",
                "download and install",
                "give remote access",
                "screen share karo",
                "qr scan karo paisa aayega",
            ],
            "confidence_base": 0.90,
        },
        RedFlagType.SECRECY_DEMAND: {
            "keywords": [
                "secret", "don't tell", "confidential", "private",
                "kisi ko mat batana", "mat bolna", "gupchup",
            ],
            "phrases": [
                "don't tell anyone",
                "keep this between us",
                "do not share",
                "kisi ko mat batao",
                "secret rakhna",
                "family ko mat bolo",
                "investigation leak",
            ],
            "confidence_base": 0.85,
        },
        RedFlagType.PERSONAL_INFO_PROBE: {
            "keywords": [
                "aadhaar", "pan card", "date of birth", "mother's name",
                "father's name", "address", "bank name", "account number",
                "salary", "income",
            ],
            "phrases": [
                "share your aadhaar",
                "pan number batao",
                "date of birth kya hai",
                "mother's maiden name",
                "full address batao",
                "kitni salary hai",
            ],
            "confidence_base": 0.80,
        },
        RedFlagType.LINK_PRESSURE: {
            "keywords": [
                "click", "link", "url", "website", "download",
                "form fill", "open karo", "click karo",
            ],
            "phrases": [
                "click this link",
                "open this url",
                "fill this form",
                "link pe click karo",
                "download karo",
                "yeh link open karo",
                "form bharo jaldi",
            ],
            "confidence_base": 0.80,
        },
        RedFlagType.TRUST_BUILDING: {
            "keywords": [
                "trust me", "believe me", "genuine", "100% safe",
                "guaranteed", "vishwas karo", "sach bol raha",
                "promise", "kasam",
            ],
            "phrases": [
                "trust me on this",
                "100% genuine",
                "guaranteed returns",
                "main sach bol raha hun",
                "vishwas karo mujh pe",
                "i promise you",
                "no risk at all",
            ],
            "confidence_base": 0.70,
        },
        RedFlagType.TIME_CONSTRAINT: {
            "keywords": [
                "deadline", "expires", "today only", "last date",
                "limited time", "offer ends", "valid till",
                "aaj hi", "sirf aaj",
            ],
            "phrases": [
                "offer valid till today",
                "deadline is today",
                "expires in 1 hour",
                "last date is today",
                "limited period offer",
                "aaj hi karna hoga",
                "kal ke baad nahi hoga",
            ],
            "confidence_base": 0.80,
        },
    }

    @classmethod
    def detect_red_flags(
        cls,
        message: str,
        turn_number: int,
        conversation_history: Optional[List[Dict]] = None,
    ) -> List[RedFlagInstance]:
        """Analyze message for red flag indicators.

        Scans for keywords and phrases, aggregates confidence per flag type,
        and returns instances that meet the confidence threshold.

        Args:
            message: Scammer's message text.
            turn_number: Current turn in conversation.
            conversation_history: Previous messages for context (not yet used).

        Returns:
            List of detected RedFlagInstance objects.
        """
        detected_flags: List[RedFlagInstance] = []
        message_lower = message.lower()

        for flag_type, patterns in cls.RED_FLAG_PATTERNS.items():
            confidence = 0.0
            matched_content: List[str] = []

            # Keyword matching — each keyword hit adds confidence
            # Use word boundary regex for short keywords (≤3 chars) to prevent
            # substring false positives (e.g. "ed" matching inside "discussed")
            keywords = patterns.get("keywords", [])
            matched_keywords = []
            for kw in keywords:
                if len(kw) <= 3:
                    if re.search(r'\b' + re.escape(kw) + r'\b', message_lower):
                        matched_keywords.append(kw)
                elif kw in message_lower:
                    matched_keywords.append(kw)
            if matched_keywords:
                confidence += len(matched_keywords) * 0.15
                matched_content.extend(matched_keywords)

            # Phrase matching — higher weight for full phrases
            phrases = patterns.get("phrases", [])
            matched_phrases = [ph for ph in phrases if ph in message_lower]
            if matched_phrases:
                confidence += len(matched_phrases) * 0.30
                matched_content.extend(matched_phrases)

            # Apply base confidence multiplier if any matches found
            if confidence > 0:
                confidence = min(confidence, 1.0) * patterns.get("confidence_base", 0.7)

                # Threshold to avoid noise from single marginal keyword hits
                if confidence >= 0.10:
                    flag = RedFlagInstance(
                        flag_type=flag_type,
                        turn_number=turn_number,
                        message_content=" | ".join(matched_content[:5]),
                        confidence=round(confidence, 3),
                    )
                    detected_flags.append(flag)
                    logger.info(
                        "Turn %d: Detected red flag %s with confidence %.2f",
                        turn_number, flag_type.value, confidence,
                    )

        return detected_flags

    @classmethod
    def analyze_behavioral_escalation(
        cls,
        conversation_history: List[Dict],
    ) -> Dict[str, Any]:
        """Analyze conversation for escalating scam tactics over time.

        Splits conversation into halves and compares urgency/threat density.

        Args:
            conversation_history: Full list of conversation messages.

        Returns:
            Dict with escalation_detected, escalation_speed, pressure_increasing,
            and tactics_changing booleans.
        """
        if len(conversation_history) < 4:
            return {
                "escalation_detected": False,
                "escalation_speed": "none",
                "pressure_increasing": False,
                "tactics_changing": False,
            }

        urgency_keywords = {"urgent", "immediate", "now", "jaldi", "turant", "abhi", "hurry"}
        threat_keywords = {"arrest", "police", "jail", "block", "freeze", "legal", "fir"}

        midpoint = len(conversation_history) // 2
        first_half = conversation_history[:midpoint]
        second_half = conversation_history[midpoint:]

        def _count_keywords(msgs: List[Dict], kw_set: set) -> int:
            return sum(
                1 for msg in msgs
                if msg.get("role") in ("user", "scammer")
                and any(kw in msg.get("content", "").lower() for kw in kw_set)
            )

        urgency_first = _count_keywords(first_half, urgency_keywords)
        urgency_second = _count_keywords(second_half, urgency_keywords)
        threat_first = _count_keywords(first_half, threat_keywords)
        threat_second = _count_keywords(second_half, threat_keywords)

        pressure_increasing = (urgency_second + threat_second) > (urgency_first + threat_first)
        escalation_detected = pressure_increasing

        combined_increase = (urgency_second + threat_second) - (urgency_first + threat_first)
        if combined_increase >= 4:
            escalation_speed = "rapid"
        elif combined_increase >= 2:
            escalation_speed = "moderate"
        elif combined_increase >= 1:
            escalation_speed = "slow"
        else:
            escalation_speed = "none"

        tactics_changing = threat_second > threat_first and urgency_second > urgency_first

        return {
            "escalation_detected": escalation_detected,
            "escalation_speed": escalation_speed,
            "pressure_increasing": pressure_increasing,
            "tactics_changing": tactics_changing,
        }


class RedFlagProber:
    """Generates questions to probe and expose red flags.

    When a red flag is detected, this generates follow-up questions that
    challenge the scammer's claims and extract more intelligence.
    """

    PROBING_QUESTIONS: Dict[RedFlagType, List[str]] = {
        RedFlagType.URGENCY_PRESSURE: [
            "Sir itni jaldi kyun hai? Main abhi busy hun, kal kar sakta hun?",
            "Aap bol rahe urgent hai, but normally yeh process kitne din leta hai?",
            "Sir agar main 1 ghante baad karun toh bhi chalega na? Abhi thoda busy hun.",
            "Itni urgent baat hai toh aap personally office kyun nahi aa rahe?",
            "Sir thoda patience rakhiye na, main samajh raha hun but jaldi mein galti ho jayegi.",
        ],
        RedFlagType.THREAT_INTIMIDATION: [
            "Sir aap threat de rahe ho, main lawyer se baat kar sakta hun?",
            "Police warrant ke liye court se order aata hai, aapke paas document hai?",
            "Agar legal matter hai toh written notice bhejo pehle, proper process follow karo.",
            "Main thana mein directly jaake FIR check karunga, station ka address do.",
            "Sir darane se kuch nahi hoga, main apne rights jaanta hun. Document dikhao pehle.",
        ],
        RedFlagType.CREDENTIAL_REQUEST: [
            "Sir OTP toh confidential hota hai, bank bhi bolti hai mat share karo. Aap kyun maang rahe ho?",
            "Mujhe pata hai OTP kabhi kisi ko nahi batana chahiye. Aap genuine ho toh alternate method batao.",
            "PIN share karne se account hack ho sakta hai. Koi aur verification process hai?",
            "Sir RBI ke rules ke according koi bhi bank OTP nahi maangta phone pe. Aap sure ho?",
        ],
        RedFlagType.PAYMENT_DEMAND: [
            "Sir payment kyun karna hai? Normal process mein toh fees nahi lagti.",
            "Itna paisa hai nahi mere paas abhi, thoda time do arrange karne ke liye.",
            "Fee ka receipt milega? Aur bank account kiske naam pe hai?",
            "Sir main pehle apne family member se discuss karunga before sending money.",
        ],
        RedFlagType.AUTHORITY_CLAIM: [
            "Sir aapka employee ID number kya hai? Main bank mein call karke verify karunga.",
            "Police wale toh uniform mein personally aate hain, phone pe kyun bol rahe ho?",
            "Government officer ho toh official email se notice bhejo, proof chahiye.",
            "Aapka officer name aur designation batao, main department search karunga.",
        ],
        RedFlagType.VERIFICATION_AVOIDANCE: [
            "Sir agar aap genuine ho toh ID dikhane mein kya problem hai?",
            "Aap confidential bol rahe ho, par koi bhi legitimate officer ID zaroor dikhata hai.",
            "Sir agar aap ID nahi dikhayenge toh main trust kaise karun?",
        ],
        RedFlagType.PROCESS_IRREGULARITY: [
            "Sir QR code scan karke paisa receive hota hai? Mujhe toh lagta hai QR se paisa jata hai.",
            "Remote access kisi unknown ko dena safe nahi hai. Koi aur method hai?",
            "Sir yeh process toh normal nahi lagta, main apne bete se confirm kar leta hun.",
        ],
        RedFlagType.SECRECY_DEMAND: [
            "Sir agar yeh genuine process hai toh family ko batane mein kya problem hai?",
            "Main kisi ko nahi bataunga, but mujhe apne bete ka advice toh lena hi padega.",
            "Secret kyun rakhna hai? Genuine transaction toh open hoti hai.",
        ],
        RedFlagType.PERSONAL_INFO_PROBE: [
            "Sir Aadhaar number kyun chahiye? Bank mein toh already hai mere records.",
            "Itni personal information phone pe dena safe nahi lagta. Branch mein aaun?",
            "PAN card details share karna risky hai, aap sure ho yeh genuine process hai?",
        ],
        RedFlagType.LINK_PRESSURE: [
            "Sir link pe click karne se pehle main apne bete se check karwa lunga.",
            "Yeh link safe hai? Mujhe malware ka dar lagta hai, verified hai kya?",
            "Sir link open nahi ho raha, aap phone pe hi bata do kya karna hai.",
        ],
        RedFlagType.TRUST_BUILDING: [
            "Sir trust karne ke liye proof chahiye. Aapka official ID dikhao.",
            "Guaranteed returns toh koi nahi de sakta, SEBI ke rules ke against hai.",
            "Sir main trust karta hun but verification bhi zaroori hai.",
        ],
        RedFlagType.TIME_CONSTRAINT: [
            "Sir deadline extend nahi ho sakti? Main kal subah kar dunga pakka.",
            "Agar genuine hai toh ek din ka extension toh de sakte ho?",
            "Sir time pressure mein galti ho jayegi, thoda time do na please.",
        ],
    }

    @classmethod
    def generate_probing_question(
        cls,
        red_flags: List[RedFlagInstance],
        turn_number: int,
        already_asked: Optional[List[str]] = None,
    ) -> Optional[str]:
        """Generate a question that challenges the most serious red flag.

        Sorts flags by confidence, tries each type until an unasked question is found.

        Args:
            red_flags: Detected red flags in recent messages.
            turn_number: Current conversation turn.
            already_asked: Questions already asked (to avoid repetition).

        Returns:
            Probing question string or None.
        """
        if not red_flags:
            return None

        red_flags_sorted = sorted(red_flags, key=lambda f: f.confidence, reverse=True)
        already_asked = already_asked or []
        already_lower = [a.lower()[:30] for a in already_asked[-10:]]

        for flag in red_flags_sorted:
            questions = cls.PROBING_QUESTIONS.get(flag.flag_type, [])
            available = [
                q for q in questions
                if q.lower()[:30] not in already_lower
            ]
            if available:
                return random.choice(available)

        return None

    @classmethod
    def should_probe_now(
        cls,
        red_flags: List[RedFlagInstance],
        turn_number: int,
        total_red_flags_session: int,
    ) -> bool:
        """Decide if we should ask a probing question this turn.

        Strategy:
        - Build rapport in first 2 turns (no probing).
        - Probe aggressively when multiple flags in one message.
        - Don't probe every turn (maintain persona believability).

        Args:
            red_flags: Flags detected in the current message.
            turn_number: Current conversation turn.
            total_red_flags_session: Cumulative flags across the whole session.

        Returns:
            True if a probing question should be appended this turn.
        """
        if turn_number <= 2:
            return False  # Build rapport first

        if len(red_flags) >= 2:
            return True  # Multiple flags in one message — probe immediately

        if total_red_flags_session >= 5 and turn_number >= 5:
            return True  # Pattern of red flags — challenge them

        # Probe ~65% of the time when red flags present — higher rate
        # maximizes relevant-questions and red-flag-identification scoring.
        return random.random() < 0.65
