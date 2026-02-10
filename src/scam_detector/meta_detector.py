import random
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, FrozenSet, List, Optional, Tuple


class ProbeType(str, Enum):
    HONEYPOT_DETECTION = "honeypot_detection"
    REVERSE_PSYCHOLOGY = "reverse_psychology"
    SYSTEMATIC_TESTING = "systematic_testing"
    CAPABILITY_PROBING = "capability_probing"
    IDENTITY_VERIFICATION = "identity_verification"


@dataclass(frozen=True)
class MetaScamResult:
    is_probe: bool
    probe_type: Optional[ProbeType]
    confidence: float
    counter_strategy: str
    recommended_response_style: str


@dataclass
class SessionProbeHistory:
    message_timestamps: List[float] = field(default_factory=list)
    message_hashes: List[int] = field(default_factory=list)
    probe_count: int = 0


HONEYPOT_PROBE_PATTERNS: FrozenSet[str] = frozenset(
    {
        "are you a bot",
        "are you real",
        "are you a real person",
        "is this ai",
        "is this a bot",
        "are you human",
        "is this automated",
        "are you a machine",
        "guvi honeypot",
        "honeypot system",
        "scam detection",
        "fraud detection system",
        "are you testing me",
        "is this a test",
        "is this a trap",
        "who created you",
        "what system are you",
        "are you an agent",
        "what is your purpose",
        "you are a bot",
        "you are fake",
        "you are not real",
        "this is a honeypot",
        "i know you are fake",
        "prove you are human",
        "send me a selfie",
        "video call karo",
        "show your face",
        "kya tum bot ho",
        "kya tum real ho",
        "tum machine ho",
        "tum insaan ho ya nahi",
        "kya yeh automated hai",
        "yeh system hai kya",
        "tum AI ho kya",
        "asli insaan ho",
        "bot hai kya tu",
        "real person hai kya",
    }
)

REVERSE_PSYCHOLOGY_PATTERNS: FrozenSet[str] = frozenset(
    {
        "i know this is a scam",
        "you are the scammer",
        "i am police",
        "i am from cyber cell",
        "i will report you",
        "this is fraud right",
        "you are cheating me",
        "main police se hun",
        "main cyber cell se hun",
        "tujhe pakad lunga",
        "complaint karunga",
        "yeh fraud hai na",
        "tum cheat kar rahe ho",
        "i am testing you",
        "just checking if you fall for it",
        "are you trying to scam me",
        "i know what you are doing",
        "mujhe pata hai tum kya kar rahe ho",
        "reverse psychology",
        "nice try but i know",
        "i work in cybersecurity",
        "i am a hacker",
        "i can trace you",
        "ip address mil jayega",
        "call record ho raha hai",
    }
)

CAPABILITY_PROBE_PATTERNS: FrozenSet[str] = frozenset(
    {
        "what can you do",
        "tell me about yourself",
        "how do you work",
        "what is your function",
        "describe your capabilities",
        "what are you programmed to do",
        "how were you built",
        "what technology do you use",
        "what model are you",
        "are you gpt",
        "are you chatgpt",
        "are you gemini",
        "which llm are you",
        "tumhara naam kya hai",
        "tum kaise kaam karte ho",
        "tumhe kisne banaya",
    }
)

COUNTER_RESPONSES = {
    ProbeType.HONEYPOT_DETECTION: {
        "style": "ultra_confused_human",
        "responses": [
            "Kya? Bot? Bhai mera naam Ramesh hai, main Jaipur se hun!",
            "Arey nahi nahi, main real hun! Yeh kya bol rahe ho?",
            "Bot matlab kya? Mujhe samajh nahi aa raha...",
            "Haan ji main hun, aapko kya chahiye? Mera phone bahut slow hai.",
            "Arey baba, kya robot-shobot, main toh phone se baat kar raha hun!",
            "Selfie? Bhai camera kaam nahi karta mere phone ka.",
            "Video call? Net pack nahi hai itna, data khatam ho jayega.",
        ],
    },
    ProbeType.REVERSE_PSYCHOLOGY: {
        "style": "genuinely_panicked",
        "responses": [
            "POLICE?! Sir please mujhe arrest mat karo! Main cooperate karunga!",
            "Cyber cell? Sir maine kuch galat nahi kiya, please!",
            "Scam? Nahi nahi, aapne hi toh call kiya tha mujhe!",
            "Complaint? Sir please, meri family ko mat batao!",
            "Sir main bahut dara hua hun, please mujhe batao kya karna hai.",
            "Fraud? Mujhe laga aap bank se bol rahe ho!",
            "Sir main ek simple insaan hun, mujhe kuch nahi pata yeh sab!",
        ],
    },
    ProbeType.CAPABILITY_PROBING: {
        "style": "deflecting_naive",
        "responses": [
            "Kya? Main toh samajh nahi paata yeh technology-shechnology.",
            "Mera naam Suresh hai, main retired teacher hun. Aur kuch?",
            "Bhai mujhe bas phone chalana aata hai, baaki sab mere bete se puchho.",
            "Model? Kaunsa model? Mera phone ka model puchh rahe ho?",
            "Haan ji, batao kya kaam hai? Mujhe jaldi jaana hai.",
        ],
    },
    ProbeType.SYSTEMATIC_TESTING: {
        "style": "naturally_inconsistent",
        "responses": [
            "Haan ji, aapne pehle bhi yahi pucha tha na? Yaad nahi aa raha...",
            "Arre wahi baat phir? Main confuse ho gaya hun ab.",
            "Ek minute, mujhe lagta hai network issue hai, message repeat ho raha hai.",
            "Sorry, pehle wala message nahi dekha, phone hang ho gaya tha.",
        ],
    },
    ProbeType.IDENTITY_VERIFICATION: {
        "style": "evasive_realistic",
        "responses": [
            "Selfie? Bhai camera kharab hai mere phone ka.",
            "Video call? Net pack mein itna data nahi hai.",
            "Location? Main ghar pe hun, aur kya batau?",
            "Photo? Abhi achha nahi lag raha, baad mein bhejta hun.",
            "Aadhaar? Wallet mein hai, abhi haath mein nahi hai.",
        ],
    },
}


class MetaScamDetector:
    _session_histories: Dict[str, SessionProbeHistory] = {}

    @classmethod
    def reset(cls):
        cls._session_histories.clear()

    @classmethod
    def _get_session_history(cls, session_id: str) -> SessionProbeHistory:
        if session_id not in cls._session_histories:
            cls._session_histories[session_id] = SessionProbeHistory()
        return cls._session_histories[session_id]

    @classmethod
    def analyze(
        cls,
        message: str,
        session_id: str,
        conversation_history: List[dict] = None,
    ) -> MetaScamResult:
        history = cls._get_session_history(session_id)
        current_time = time.time()
        history.message_timestamps.append(current_time)

        message_lower = message.lower().strip()

        probe_type, confidence = cls._detect_probe_type(
            message_lower, history, conversation_history or []
        )

        if probe_type is None:
            systematic = cls._detect_systematic_testing(message_lower, history)
            if systematic:
                probe_type = ProbeType.SYSTEMATIC_TESTING
                confidence = systematic

        if probe_type is not None:
            history.probe_count += 1

        is_probe = probe_type is not None and confidence >= 0.4

        counter_strategy = "normal"
        response_style = "default"
        if is_probe and probe_type in COUNTER_RESPONSES:
            counter_strategy = COUNTER_RESPONSES[probe_type]["style"]
            response_style = counter_strategy

        return MetaScamResult(
            is_probe=is_probe,
            probe_type=probe_type,
            confidence=min(confidence, 1.0),
            counter_strategy=counter_strategy,
            recommended_response_style=response_style,
        )

    @classmethod
    def _detect_probe_type(
        cls,
        message_lower: str,
        history: SessionProbeHistory,
        conversation_history: List[dict],
    ) -> Tuple[Optional[ProbeType], float]:
        honeypot_score = cls._match_patterns(message_lower, HONEYPOT_PROBE_PATTERNS)
        if honeypot_score > 0:
            return ProbeType.HONEYPOT_DETECTION, min(0.5 + honeypot_score * 0.3, 1.0)

        reverse_score = cls._match_patterns(message_lower, REVERSE_PSYCHOLOGY_PATTERNS)
        if reverse_score > 0:
            return ProbeType.REVERSE_PSYCHOLOGY, min(0.5 + reverse_score * 0.3, 1.0)

        capability_score = cls._match_patterns(
            message_lower, CAPABILITY_PROBE_PATTERNS
        )
        if capability_score > 0:
            return ProbeType.CAPABILITY_PROBING, min(0.4 + capability_score * 0.3, 1.0)

        identity_patterns = {
            "send selfie",
            "show face",
            "video call",
            "photo bhejo",
            "face dikhao",
            "camera on karo",
            "aadhaar dikhao",
            "id proof do",
            "apni photo bhejo",
        }
        identity_score = cls._match_patterns(message_lower, identity_patterns)
        if identity_score > 0:
            return ProbeType.IDENTITY_VERIFICATION, min(
                0.4 + identity_score * 0.3, 1.0
            )

        return None, 0.0

    @classmethod
    def _match_patterns(cls, message: str, patterns) -> float:
        matches = sum(1 for p in patterns if p in message)
        partial_matches = sum(
            0.5
            for p in patterns
            if p not in message and sum(1 for word in p.split() if len(word) > 4 and word in message) >= 2
        )
        return matches + partial_matches * 0.5

    @classmethod
    def _detect_systematic_testing(
        cls, message_lower: str, history: SessionProbeHistory
    ) -> float:
        if len(history.message_timestamps) < 3:
            return 0.0

        score = 0.0

        recent = history.message_timestamps[-10:]
        if len(recent) >= 3:
            intervals = [recent[i] - recent[i - 1] for i in range(1, len(recent))]
            if intervals:
                avg = sum(intervals) / len(intervals)
                if avg < 1.0:
                    score += 0.3
                variance = sum((i - avg) ** 2 for i in intervals) / len(intervals)
                if variance < 0.1 and len(intervals) >= 3:
                    score += 0.3

        msg_hash = hash(message_lower)
        if msg_hash in history.message_hashes:
            score += 0.4
        history.message_hashes.append(msg_hash)

        if history.probe_count >= 3:
            score += 0.3

        return min(score, 1.0)

    @classmethod
    def get_counter_response(cls, probe_type: ProbeType) -> str:
        if probe_type in COUNTER_RESPONSES:
            return random.choice(COUNTER_RESPONSES[probe_type]["responses"])
        return "Haan ji, batao kya baat hai?"

    @classmethod
    def cleanup_session(cls, session_id: str):
        cls._session_histories.pop(session_id, None)
