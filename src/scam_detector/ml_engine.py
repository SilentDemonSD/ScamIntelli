import json
import math
import re
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, FrozenSet, List, Optional, Tuple

from src.scam_detector.keywords import (
    CREDENTIAL_KEYWORDS,
    PAYMENT_KEYWORDS,
    THREAT_KEYWORDS,
    URGENCY_KEYWORDS,
)
from src.utils.logging import get_logger

logger = get_logger(__name__)

try:
    import lightgbm as lgb

    HAS_LIGHTGBM = True
except ImportError:
    HAS_LIGHTGBM = False
    lgb = None

try:
    import numpy as np

    HAS_NUMPY = True
except ImportError:
    HAS_NUMPY = False
    np = None

MODEL_PATH = Path("models/scam_detector.lgb")
TRAINING_DATA_PATH = Path("models/training_data.jsonl")
FEATURE_NAMES = [
    "msg_length",
    "word_count",
    "avg_word_length",
    "uppercase_ratio",
    "exclamation_count",
    "question_count",
    "url_count",
    "phone_count",
    "email_count",
    "upi_count",
    "urgency_keyword_count",
    "threat_keyword_count",
    "credential_keyword_count",
    "payment_keyword_count",
    "has_currency_symbol",
    "number_count",
    "special_char_ratio",
    "hindi_word_ratio",
    "consecutive_caps_count",
    "sentiment_negativity",
    "msg_entropy",
    "repeated_char_ratio",
    "session_turn_count",
    "escalation_score",
    "multi_vector_count",
]

HINDI_COMMON_WORDS: FrozenSet[str] = frozenset(
    {
        "hai", "hain", "kya", "kaise", "karo", "karna", "aap", "aapka",
        "mein", "mera", "meri", "mere", "haan", "nahi", "ji", "abhi",
        "jaldi", "bhejo", "batao", "ruko", "paisa", "paise", "rupay",
        "lakh", "crore", "turant", "aakhri", "mauka", "warna", "nahi",
        "kyun", "kaun", "kab", "kahan", "bahut", "bohot", "zyada",
    }
)


@dataclass
class MLFeatures:
    features: List[float] = field(default_factory=list)
    feature_names: List[str] = field(default_factory=lambda: FEATURE_NAMES.copy())


@dataclass
class MLPrediction:
    is_scam: bool
    confidence: float
    feature_importance: Dict[str, float]
    model_used: str


@dataclass
class ScamPattern:
    pattern_type: str
    pattern_text: str
    frequency: int
    first_seen: str
    last_seen: str
    confidence: float


class FeatureExtractor:
    _URL_PATTERN = re.compile(r"https?://\S+")
    _PHONE_PATTERN = re.compile(r"(?:\+91[\s\-]?)?[6-9]\d{9}")
    _EMAIL_PATTERN = re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}")
    _UPI_PATTERN = re.compile(r"[a-zA-Z0-9._\-]+@[a-zA-Z]+")
    _CONSECUTIVE_CAPS = re.compile(r"[A-Z]{3,}")
    _NUMBER_PATTERN = re.compile(r"\d+")

    @classmethod
    def extract(
        cls,
        message: str,
        session_messages: Optional[List[dict]] = None,
    ) -> MLFeatures:
        msg_lower = message.lower()
        words = msg_lower.split()
        word_count = len(words)

        features = [
            float(len(message)),
            float(word_count),
            float(sum(len(w) for w in words) / max(word_count, 1)),
            float(
                sum(1 for c in message if c.isupper()) / max(len(message), 1)
            ),
            float(message.count("!")),
            float(message.count("?")),
            float(len(cls._URL_PATTERN.findall(message))),
            float(len(cls._PHONE_PATTERN.findall(message))),
            float(len(cls._EMAIL_PATTERN.findall(message))),
            float(len(cls._UPI_PATTERN.findall(message))),
            float(
                sum(1 for kw in URGENCY_KEYWORDS if kw in msg_lower)
            ),
            float(
                sum(1 for kw in THREAT_KEYWORDS if kw in msg_lower)
            ),
            float(
                sum(1 for kw in CREDENTIAL_KEYWORDS if kw in msg_lower)
            ),
            float(
                sum(1 for kw in PAYMENT_KEYWORDS if kw in msg_lower)
            ),
            float(
                any(c in message for c in ("₹", "$", "€", "£"))
            ),
            float(len(cls._NUMBER_PATTERN.findall(message))),
            float(
                sum(1 for c in message if not c.isalnum() and not c.isspace())
                / max(len(message), 1)
            ),
            float(
                sum(1 for w in words if w in HINDI_COMMON_WORDS)
                / max(word_count, 1)
            ),
            float(
                len(cls._CONSECUTIVE_CAPS.findall(message))
            ),
            float(cls._estimate_negativity(msg_lower)),
            float(cls._message_entropy(message)),
            float(cls._repeated_char_ratio(message)),
            float(len(session_messages) if session_messages else 0),
            float(
                cls._escalation_score(session_messages) if session_messages else 0.0
            ),
            float(
                cls._multi_vector_count(msg_lower)
            ),
        ]

        return MLFeatures(features=features)

    @classmethod
    def _estimate_negativity(cls, text: str) -> float:
        negative_words = {
            "arrest", "jail", "police", "court", "penalty", "fine", "block",
            "suspend", "freeze", "terminate", "illegal", "crime", "warning",
            "danger", "threat", "risk", "violation", "fraud", "complaint",
        }
        words = text.split()
        count = sum(1 for w in words if w in negative_words)
        return min(count / max(len(words), 1), 1.0)

    @classmethod
    def _message_entropy(cls, text: str) -> float:
        if not text:
            return 0.0
        freq = Counter(text.lower())
        total = len(text)
        entropy = 0.0
        for count in freq.values():
            p = count / total
            if p > 0:
                entropy -= p * math.log2(p)
        return entropy

    @classmethod
    def _repeated_char_ratio(cls, text: str) -> float:
        if len(text) < 2:
            return 0.0
        repeats = sum(1 for i in range(1, len(text)) if text[i] == text[i - 1])
        return repeats / len(text)

    @classmethod
    def _escalation_score(cls, messages: List[dict]) -> float:
        if not messages:
            return 0.0
        recent = [
            m.get("content", "").lower()
            for m in messages[-6:]
            if m.get("role") in ("user", "scammer")
        ]
        if len(recent) < 2:
            return 0.0

        threat_counts = []
        for msg in recent:
            count = sum(1 for kw in THREAT_KEYWORDS if kw in msg)
            count += sum(1 for kw in URGENCY_KEYWORDS if kw in msg)
            threat_counts.append(count)

        if len(threat_counts) >= 2:
            escalation = sum(
                max(0, threat_counts[i] - threat_counts[i - 1])
                for i in range(1, len(threat_counts))
            )
            return min(escalation / 5.0, 1.0)
        return 0.0

    @classmethod
    def _multi_vector_count(cls, text: str) -> float:
        vectors = [
            bool(re.search(r"https?://", text)),
            bool(re.search(r"[a-zA-Z0-9]+@[a-zA-Z]+", text)),
            bool(re.search(r"(?:\+91)?[6-9]\d{9}", text)),
            any(kw in text for kw in ("otp", "pin", "password", "cvv")),
            any(kw in text for kw in ("arrest", "block", "legal", "police")),
            any(kw in text for kw in ("click", "scan", "download", "install")),
        ]
        return float(sum(vectors))


ADVANCED_FEATURE_NAMES = [
    "temporal_msg_rate",
    "temporal_avg_response_gap",
    "temporal_session_duration_ratio",
    "temporal_burst_score",
    "temporal_time_pressure_count",
    "temporal_deadline_mentions",
    "temporal_countdown_pattern",
    "temporal_recency_bias",
    "linguistic_vocabulary_richness",
    "linguistic_avg_sentence_length",
    "linguistic_readability_score",
    "linguistic_passive_voice_ratio",
    "linguistic_imperative_ratio",
    "linguistic_pronoun_ratio",
    "linguistic_formality_score",
    "linguistic_repetition_score",
    "linguistic_code_switch_count",
    "linguistic_punctuation_abuse",
    "psych_fear_appeal_score",
    "psych_authority_claim_score",
    "psych_social_proof_score",
    "psych_scarcity_score",
    "psych_reciprocity_score",
    "psych_commitment_score",
    "psych_anchoring_score",
    "psych_emotional_manipulation",
    "behav_message_length_trend",
    "behav_topic_shift_count",
    "behav_info_request_density",
    "behav_compliance_testing",
    "behav_rapport_vs_demand_ratio",
    "behav_grooming_score",
    "info_unique_phone_count",
    "info_unique_upi_count",
    "info_unique_url_count",
    "info_unique_email_count",
    "info_amount_mention_count",
    "info_credential_request_density",
    "info_personal_data_requests",
    "info_financial_entity_density",
]

FEAR_WORDS: FrozenSet[str] = frozenset(
    {
        "arrest", "jail", "prison", "police", "court", "lawsuit",
        "penalty", "fine", "block", "suspend", "freeze", "terminate",
        "giraftar", "saza", "kanoon", "warrant",
    }
)

AUTHORITY_PHRASES: FrozenSet[str] = frozenset(
    {
        "government", "rbi", "reserve bank", "income tax", "cyber cell",
        "ministry", "department", "official", "authorized", "certified",
        "sarkar", "sarkari", "adhikari",
    }
)

SOCIAL_PROOF_PHRASES: FrozenSet[str] = frozenset(
    {
        "everyone", "thousands", "many people", "lakhs of people",
        "others have", "already verified", "common practice",
        "sab log", "bahut log",
    }
)

SCARCITY_PHRASES: FrozenSet[str] = frozenset(
    {
        "limited time", "only today", "last chance", "offer expires",
        "few slots", "limited seats", "exclusive", "once in lifetime",
        "sirf aaj", "aakhri mauka", "limited period",
    }
)

TIME_PRESSURE_PHRASES: FrozenSet[str] = frozenset(
    {
        "immediately", "right now", "within minutes", "hurry",
        "don't delay", "time running out", "expiring soon",
        "abhi", "turant", "jaldi", "fauran",
    }
)

INFO_REQUEST_WORDS: FrozenSet[str] = frozenset(
    {
        "send", "share", "provide", "give", "tell", "enter",
        "submit", "upload", "verify", "confirm",
        "bhejo", "batao", "do", "dijiye",
    }
)

PERSONAL_DATA_WORDS: FrozenSet[str] = frozenset(
    {
        "aadhaar", "aadhar", "pan", "pan card", "passport",
        "driving license", "voter id", "date of birth", "dob",
        "mother name", "father name", "address",
    }
)

FORMAL_INDICATORS: FrozenSet[str] = frozenset(
    {
        "kindly", "please", "sir", "madam", "respected", "dear",
        "regarding", "hereby", "therefore", "furthermore",
    }
)

INFORMAL_INDICATORS: FrozenSet[str] = frozenset(
    {
        "bro", "dude", "yo", "lol", "ok", "gonna", "wanna",
        "yaar", "bhai", "arre",
    }
)


class AdvancedFeatureExtractor:

    _AMOUNT_PATTERN = re.compile(r"(?:₹|rs\.?|inr|usd|\$)\s*[\d,]+", re.IGNORECASE)
    _DEADLINE_PATTERN = re.compile(
        r"\b(\d+)\s*(hour|minute|min|second|sec|day)s?\b", re.IGNORECASE
    )
    _PASSIVE_PATTERN = re.compile(
        r"\b(is|are|was|were|been|being)\s+\w+ed\b", re.IGNORECASE
    )
    _IMPERATIVE_STARTERS = frozenset(
        {
            "click", "send", "share", "verify", "confirm", "pay", "transfer",
            "download", "install", "enter", "submit", "call", "dial",
            "tap", "scan", "open", "do", "act",
        }
    )
    _HINDI_CHAR_PATTERN = re.compile(r"[\u0900-\u097F]")

    @classmethod
    def extract_advanced_features(
        cls,
        message: str,
        session_messages: Optional[List[dict]] = None,
    ) -> Dict[str, float]:
        features: Dict[str, float] = {}
        msg_lower = message.lower()
        words = msg_lower.split()
        word_count = max(len(words), 1)
        msgs = session_messages or []

        cls._extract_temporal(features, msg_lower, words, msgs)
        cls._extract_linguistic(features, message, msg_lower, words, word_count)
        cls._extract_psychological(features, msg_lower, words, word_count)
        cls._extract_behavioral(features, msg_lower, words, msgs)
        cls._extract_info(features, message, msg_lower, words, word_count)

        return features

    @classmethod
    def _extract_temporal(
        cls,
        features: Dict[str, float],
        msg_lower: str,
        words: List[str],
        msgs: List[dict],
    ) -> None:
        msg_count = len(msgs)
        features["temporal_msg_rate"] = float(min(msg_count / 10.0, 1.0))

        if msg_count >= 2:
            scammer_msgs = [
                m for m in msgs if m.get("role") in ("user", "scammer")
            ]
            features["temporal_avg_response_gap"] = (
                1.0 / max(len(scammer_msgs), 1)
            )
        else:
            features["temporal_avg_response_gap"] = 0.0

        features["temporal_session_duration_ratio"] = min(msg_count / 20.0, 1.0)

        if msg_count >= 3:
            recent = msgs[-3:]
            recent_scammer = sum(
                1 for m in recent if m.get("role") in ("user", "scammer")
            )
            features["temporal_burst_score"] = recent_scammer / 3.0
        else:
            features["temporal_burst_score"] = 0.0

        features["temporal_time_pressure_count"] = float(
            min(sum(1 for p in TIME_PRESSURE_PHRASES if p in msg_lower) / 3.0, 1.0)
        )

        deadline_matches = cls._DEADLINE_PATTERN.findall(msg_lower)
        features["temporal_deadline_mentions"] = float(
            min(len(deadline_matches) / 2.0, 1.0)
        )

        countdown_score = 0.0
        if msgs:
            for i, m in enumerate(msgs[-5:]):
                content = m.get("content", "").lower()
                if cls._DEADLINE_PATTERN.search(content):
                    countdown_score += (i + 1) * 0.1
        features["temporal_countdown_pattern"] = min(countdown_score, 1.0)

        recency_words = {"now", "today", "tonight", "abhi", "aaj"}
        features["temporal_recency_bias"] = float(
            min(sum(1 for w in words if w in recency_words) / 2.0, 1.0)
        )

    @classmethod
    def _extract_linguistic(
        cls,
        features: Dict[str, float],
        message: str,
        msg_lower: str,
        words: List[str],
        word_count: int,
    ) -> None:
        unique_words = len(set(words))
        features["linguistic_vocabulary_richness"] = unique_words / word_count

        sentences = re.split(r"[.!?]+", msg_lower)
        sentences = [s.strip() for s in sentences if s.strip()]
        if sentences:
            features["linguistic_avg_sentence_length"] = float(
                min(sum(len(s.split()) for s in sentences) / len(sentences) / 30.0, 1.0)
            )
        else:
            features["linguistic_avg_sentence_length"] = 0.0

        avg_word_len = sum(len(w) for w in words) / word_count
        features["linguistic_readability_score"] = min(avg_word_len / 10.0, 1.0)

        passive_count = len(cls._PASSIVE_PATTERN.findall(message))
        features["linguistic_passive_voice_ratio"] = min(
            passive_count / max(len(sentences), 1), 1.0
        )

        imperative_count = 0
        for s in sentences:
            s_words = s.split()
            if s_words and s_words[0] in cls._IMPERATIVE_STARTERS:
                imperative_count += 1
        features["linguistic_imperative_ratio"] = min(
            imperative_count / max(len(sentences), 1), 1.0
        )

        pronouns = {"you", "your", "yours", "i", "my", "me", "we", "our", "aap", "aapka", "mera", "meri"}
        pronoun_count = sum(1 for w in words if w in pronouns)
        features["linguistic_pronoun_ratio"] = min(pronoun_count / word_count, 1.0)

        formal_count = sum(1 for w in words if w in FORMAL_INDICATORS)
        informal_count = sum(1 for w in words if w in INFORMAL_INDICATORS)
        diff = (formal_count - informal_count) / word_count
        features["linguistic_formality_score"] = min(max(diff + 0.5, 0.0), 1.0)

        word_freq = Counter(words)
        repeated = sum(1 for w, c in word_freq.items() if c >= 2)
        features["linguistic_repetition_score"] = min(
            repeated / max(len(word_freq), 1), 1.0
        )

        has_hindi = bool(cls._HINDI_CHAR_PATTERN.search(message))
        has_english = bool(re.search(r"[a-zA-Z]", message))
        hindi_words = sum(1 for w in words if w in HINDI_COMMON_WORDS)
        features["linguistic_code_switch_count"] = float(
            min((hindi_words / word_count + (1.0 if has_hindi and has_english else 0.0)) / 2.0, 1.0)
        )

        excess_punct = sum(1 for c in message if c in "!!!???...") - len(message) * 0.02
        features["linguistic_punctuation_abuse"] = min(
            max(excess_punct / 10.0, 0.0), 1.0
        )

    @classmethod
    def _extract_psychological(
        cls,
        features: Dict[str, float],
        msg_lower: str,
        words: List[str],
        word_count: int,
    ) -> None:
        fear_count = sum(1 for w in words if w in FEAR_WORDS)
        features["psych_fear_appeal_score"] = min(fear_count / 3.0, 1.0)

        authority_count = sum(1 for p in AUTHORITY_PHRASES if p in msg_lower)
        features["psych_authority_claim_score"] = min(authority_count / 2.0, 1.0)

        social_count = sum(1 for p in SOCIAL_PROOF_PHRASES if p in msg_lower)
        features["psych_social_proof_score"] = min(social_count / 2.0, 1.0)

        scarcity_count = sum(1 for p in SCARCITY_PHRASES if p in msg_lower)
        features["psych_scarcity_score"] = min(scarcity_count / 2.0, 1.0)

        reciprocity_words = {"free", "gift", "bonus", "reward", "cashback", "muft", "inaam"}
        recip_count = sum(1 for w in words if w in reciprocity_words)
        features["psych_reciprocity_score"] = min(recip_count / 2.0, 1.0)

        commitment_phrases = {"you agreed", "as promised", "you said", "already confirmed", "aapne kaha"}
        commit_count = sum(1 for p in commitment_phrases if p in msg_lower)
        features["psych_commitment_score"] = min(commit_count / 2.0, 1.0)

        anchor_patterns = re.findall(r"(?:₹|rs\.?)\s*[\d,]+", msg_lower)
        features["psych_anchoring_score"] = min(len(anchor_patterns) / 3.0, 1.0)

        emotional_words = {
            "congratulations", "winner", "lucky", "amazing", "special",
            "badhai", "jeet", "khushi",
        }
        emo_count = sum(1 for w in words if w in emotional_words)
        emo_count += sum(1 for w in words if w in FEAR_WORDS)
        features["psych_emotional_manipulation"] = min(emo_count / 4.0, 1.0)

    @classmethod
    def _extract_behavioral(
        cls,
        features: Dict[str, float],
        msg_lower: str,
        words: List[str],
        msgs: List[dict],
    ) -> None:
        if len(msgs) >= 3:
            scammer_msgs = [
                m.get("content", "")
                for m in msgs
                if m.get("role") in ("user", "scammer") and m.get("content")
            ]
            if len(scammer_msgs) >= 3:
                lengths = [len(m) for m in scammer_msgs[-5:]]
                if len(lengths) >= 2:
                    trend = (lengths[-1] - lengths[0]) / max(lengths[0], 1)
                    features["behav_message_length_trend"] = min(
                        max(trend + 0.5, 0.0), 1.0
                    )
                else:
                    features["behav_message_length_trend"] = 0.5
            else:
                features["behav_message_length_trend"] = 0.5
        else:
            features["behav_message_length_trend"] = 0.5

        if len(msgs) >= 4:
            topics_per_msg = []
            topic_keywords = {
                "payment": {"pay", "transfer", "send", "money", "amount", "paisa"},
                "identity": {"aadhaar", "pan", "name", "address", "dob"},
                "threat": {"police", "arrest", "court", "legal", "block"},
                "verification": {"verify", "otp", "confirm", "code", "pin"},
            }
            for m in msgs[-6:]:
                content = m.get("content", "").lower().split()
                active_topics = sum(
                    1 for topic_words in topic_keywords.values()
                    if any(w in content for w in topic_words)
                )
                topics_per_msg.append(active_topics)

            shifts = sum(
                1 for i in range(1, len(topics_per_msg))
                if topics_per_msg[i] != topics_per_msg[i - 1]
            )
            features["behav_topic_shift_count"] = min(shifts / 4.0, 1.0)
        else:
            features["behav_topic_shift_count"] = 0.0

        info_req_count = sum(1 for w in words if w in INFO_REQUEST_WORDS)
        features["behav_info_request_density"] = min(
            info_req_count / max(len(words), 1) * 10, 1.0
        )

        compliance_words = {"ok", "okay", "yes", "sure", "done", "sent", "haan", "theek"}
        if msgs:
            agent_msgs = [
                m.get("content", "").lower()
                for m in msgs
                if m.get("role") == "assistant" and m.get("content")
            ]
            compliant_count = sum(
                1 for m in agent_msgs
                if any(w in m.split() for w in compliance_words)
            )
            features["behav_compliance_testing"] = min(
                compliant_count / max(len(agent_msgs), 1), 1.0
            )
        else:
            features["behav_compliance_testing"] = 0.0

        rapport_words = {"hello", "hi", "how are", "good morning", "namaste", "namaskar"}
        demand_words = {"send", "pay", "transfer", "give", "share"}
        rapport_count = sum(1 for w in rapport_words if w in msg_lower)
        demand_count = sum(1 for w in demand_words if w in msg_lower)
        total = rapport_count + demand_count
        features["behav_rapport_vs_demand_ratio"] = (
            demand_count / max(total, 1)
        )

        if len(msgs) >= 3:
            early_msgs = msgs[: len(msgs) // 3]
            late_msgs = msgs[len(msgs) * 2 // 3 :]
            early_threats = sum(
                sum(1 for w in m.get("content", "").lower().split() if w in FEAR_WORDS)
                for m in early_msgs
            )
            late_demands = sum(
                sum(1 for w in m.get("content", "").lower().split() if w in INFO_REQUEST_WORDS)
                for m in late_msgs
            )
            features["behav_grooming_score"] = float(
                min((0.0 if early_threats > 0 else 0.3) + min(late_demands / 5.0, 0.7), 1.0)
            )
        else:
            features["behav_grooming_score"] = 0.0

    @classmethod
    def _extract_info(
        cls,
        features: Dict[str, float],
        message: str,
        msg_lower: str,
        words: List[str],
        word_count: int,
    ) -> None:
        phone_pattern = re.compile(r"(?:\+91[\s\-]?)?[6-9]\d{9}")
        upi_pattern = re.compile(r"[a-zA-Z0-9._\-]+@[a-zA-Z]+")
        url_pattern = re.compile(r"https?://\S+")
        email_pattern = re.compile(
            r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}"
        )

        features["info_unique_phone_count"] = float(
            min(len(set(phone_pattern.findall(message))) / 3.0, 1.0)
        )
        features["info_unique_upi_count"] = float(
            min(len(set(upi_pattern.findall(message))) / 3.0, 1.0)
        )
        features["info_unique_url_count"] = float(
            min(len(set(url_pattern.findall(message))) / 3.0, 1.0)
        )
        features["info_unique_email_count"] = float(
            min(len(set(email_pattern.findall(message))) / 2.0, 1.0)
        )

        amounts = cls._AMOUNT_PATTERN.findall(message)
        features["info_amount_mention_count"] = float(
            min(len(amounts) / 3.0, 1.0)
        )

        cred_words = {"otp", "pin", "password", "cvv", "mpin", "passcode"}
        cred_count = sum(1 for w in words if w in cred_words)
        features["info_credential_request_density"] = min(
            cred_count / word_count * 10, 1.0
        )

        personal_count = sum(1 for p in PERSONAL_DATA_WORDS if p in msg_lower)
        features["info_personal_data_requests"] = min(
            personal_count / 3.0, 1.0
        )

        financial_words = {
            "bank", "account", "transfer", "transaction", "balance",
            "neft", "rtgs", "imps", "upi", "payment",
        }
        fin_count = sum(1 for w in words if w in financial_words)
        features["info_financial_entity_density"] = min(
            fin_count / word_count * 5, 1.0
        )


class PatternLearner:
    _patterns: Dict[str, ScamPattern] = {}
    _pattern_file = Path("models/learned_patterns.json")

    @classmethod
    def learn_from_conversation(
        cls,
        messages: List[dict],
        scam_category: str,
        was_scam: bool,
    ) -> List[ScamPattern]:
        if not was_scam or not messages:
            return []

        new_patterns = []
        scammer_msgs = [
            m.get("content", "")
            for m in messages
            if m.get("role") in ("user", "scammer") and m.get("content")
        ]

        phrase_counter: Counter = Counter()
        for msg in scammer_msgs:
            words = msg.lower().split()
            for n in (2, 3, 4):
                for i in range(len(words) - n + 1):
                    phrase = " ".join(words[i : i + n])
                    if any(
                        kw in phrase
                        for kw_set in (URGENCY_KEYWORDS, THREAT_KEYWORDS, CREDENTIAL_KEYWORDS, PAYMENT_KEYWORDS)
                        for kw in kw_set
                    ):
                        phrase_counter[phrase] += 1

        now = datetime.now(timezone.utc).isoformat()
        for phrase, count in phrase_counter.most_common(10):
            if count >= 2 or len(phrase.split()) >= 3:
                pattern_key = f"{scam_category}:{phrase}"
                if pattern_key in cls._patterns:
                    cls._patterns[pattern_key].frequency += count
                    cls._patterns[pattern_key].last_seen = now
                    cls._patterns[pattern_key].confidence = min(
                        cls._patterns[pattern_key].confidence + 0.05, 0.99
                    )
                else:
                    pattern = ScamPattern(
                        pattern_type=scam_category,
                        pattern_text=phrase,
                        frequency=count,
                        first_seen=now,
                        last_seen=now,
                        confidence=0.6,
                    )
                    cls._patterns[pattern_key] = pattern
                    new_patterns.append(pattern)

        cls._save_patterns()
        return new_patterns

    @classmethod
    def get_pattern_score(cls, message: str) -> float:
        if not cls._patterns:
            cls._load_patterns()

        if not cls._patterns:
            return 0.0

        msg_lower = message.lower()
        total_score = 0.0
        matches = 0

        for pattern in cls._patterns.values():
            if pattern.pattern_text in msg_lower:
                total_score += pattern.confidence * min(pattern.frequency / 10.0, 1.0)
                matches += 1

        if matches == 0:
            return 0.0

        return min(total_score / max(matches, 1), 1.0)

    @classmethod
    def get_learned_pattern_count(cls) -> int:
        if not cls._patterns:
            cls._load_patterns()
        return len(cls._patterns)

    @classmethod
    def _save_patterns(cls) -> None:
        try:
            cls._pattern_file.parent.mkdir(parents=True, exist_ok=True)
            data = {
                k: {
                    "pattern_type": v.pattern_type,
                    "pattern_text": v.pattern_text,
                    "frequency": v.frequency,
                    "first_seen": v.first_seen,
                    "last_seen": v.last_seen,
                    "confidence": v.confidence,
                }
                for k, v in cls._patterns.items()
            }
            cls._pattern_file.write_text(json.dumps(data, indent=2))
        except Exception as e:
            logger.warning(f"Failed to save patterns: {e}")

    @classmethod
    def _load_patterns(cls) -> None:
        try:
            if cls._pattern_file.exists():
                data = json.loads(cls._pattern_file.read_text())
                cls._patterns = {
                    k: ScamPattern(**v) for k, v in data.items()
                }
        except Exception as e:
            logger.warning(f"Failed to load patterns: {e}")
            cls._patterns = {}


class MLScamDetector:
    _model = None
    _is_loaded = False

    @classmethod
    def _load_model(cls) -> bool:
        if cls._is_loaded:
            return cls._model is not None

        cls._is_loaded = True

        if not HAS_LIGHTGBM:
            logger.info("LightGBM not installed - using heuristic fallback")
            return False

        try:
            if MODEL_PATH.exists():
                cls._model = lgb.Booster(model_file=str(MODEL_PATH))
                logger.info("Loaded LightGBM scam detection model")
                return True
        except Exception as e:
            logger.warning(f"Failed to load LightGBM model: {e}")

        return False

    @classmethod
    async def predict(
        cls,
        message: str,
        session_messages: Optional[List[dict]] = None,
    ) -> MLPrediction:
        features = FeatureExtractor.extract(message, session_messages)

        if cls._load_model() and cls._model is not None and HAS_NUMPY:
            try:
                feature_array = np.array([features.features])
                raw_prediction = cls._model.predict(feature_array)[0]
                confidence = float(raw_prediction)

                importance = cls._model.feature_importance(importance_type="gain")
                importance_dict = dict(zip(FEATURE_NAMES, importance.tolist()))

                return MLPrediction(
                    is_scam=confidence >= 0.5,
                    confidence=confidence,
                    feature_importance=importance_dict,
                    model_used="lightgbm",
                )
            except Exception as e:
                logger.warning(f"LightGBM prediction failed: {e}")

        return cls._heuristic_predict(features)

    @classmethod
    def _heuristic_predict(cls, features: MLFeatures) -> MLPrediction:
        f = dict(zip(FEATURE_NAMES, features.features))

        score = 0.0
        weights = {
            "urgency_keyword_count": 0.15,
            "threat_keyword_count": 0.20,
            "credential_keyword_count": 0.20,
            "payment_keyword_count": 0.15,
            "url_count": 0.08,
            "phone_count": 0.05,
            "upi_count": 0.10,
            "multi_vector_count": 0.12,
            "escalation_score": 0.10,
            "sentiment_negativity": 0.08,
            "consecutive_caps_count": 0.05,
            "exclamation_count": 0.03,
        }

        for feat_name, weight in weights.items():
            val = f.get(feat_name, 0.0)
            if feat_name.endswith("_count"):
                val = min(val / 5.0, 1.0)
            score += val * weight

        pattern_score = PatternLearner.get_pattern_score(
            " ".join(str(v) for v in features.features)
        )
        if pattern_score > 0:
            score = max(score, score * 0.7 + pattern_score * 0.3)

        confidence = min(score, 1.0)

        importance_dict = {
            name: weights.get(name, 0.0) for name in FEATURE_NAMES
        }

        return MLPrediction(
            is_scam=confidence >= 0.55,
            confidence=round(confidence, 4),
            feature_importance=importance_dict,
            model_used="heuristic_fallback",
        )

    @classmethod
    async def train_from_sessions(
        cls,
        training_data: List[Tuple[str, bool]],
    ) -> bool:
        if not HAS_LIGHTGBM or not HAS_NUMPY:
            logger.warning("LightGBM/numpy not available for training")
            return False

        if len(training_data) < 20:
            logger.warning("Insufficient training data (need >= 20 samples)")
            return False

        try:
            X = []
            y = []
            for message, label in training_data:
                features = FeatureExtractor.extract(message)
                X.append(features.features)
                y.append(1.0 if label else 0.0)

            X_arr = np.array(X)
            y_arr = np.array(y)

            train_data = lgb.Dataset(
                X_arr, label=y_arr, feature_name=FEATURE_NAMES
            )

            params = {
                "objective": "binary",
                "metric": "binary_logloss",
                "boosting_type": "gbdt",
                "num_leaves": 31,
                "learning_rate": 0.05,
                "feature_fraction": 0.9,
                "bagging_fraction": 0.8,
                "bagging_freq": 5,
                "verbose": -1,
                "min_data_in_leaf": 5,
                "max_depth": 6,
            }

            cls._model = lgb.train(
                params,
                train_data,
                num_boost_round=100,
            )

            MODEL_PATH.parent.mkdir(parents=True, exist_ok=True)
            cls._model.save_model(str(MODEL_PATH))
            cls._is_loaded = True
            logger.info(f"Trained LightGBM model with {len(training_data)} samples")
            return True

        except Exception as e:
            logger.error(f"Model training failed: {e}")
            return False

    @classmethod
    def save_training_sample(cls, message: str, is_scam: bool) -> None:
        try:
            TRAINING_DATA_PATH.parent.mkdir(parents=True, exist_ok=True)
            sample = {
                "message": message,
                "is_scam": is_scam,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
            with open(TRAINING_DATA_PATH, "a", encoding="utf-8") as f:
                f.write(json.dumps(sample) + "\n")
        except Exception as e:
            logger.warning(f"Failed to save training sample: {e}")

    @classmethod
    def get_model_info(cls) -> Dict:
        cls._load_model()
        training_samples = 0
        try:
            if TRAINING_DATA_PATH.exists():
                with open(TRAINING_DATA_PATH, encoding="utf-8") as f:
                    training_samples = sum(1 for _ in f)
        except Exception:
            pass

        return {
            "model_loaded": cls._model is not None,
            "model_type": "lightgbm" if cls._model is not None else "heuristic_fallback",
            "lightgbm_available": HAS_LIGHTGBM,
            "numpy_available": HAS_NUMPY,
            "model_path": str(MODEL_PATH),
            "training_samples_stored": training_samples,
            "learned_patterns": PatternLearner.get_learned_pattern_count(),
            "feature_count": len(FEATURE_NAMES),
        }
