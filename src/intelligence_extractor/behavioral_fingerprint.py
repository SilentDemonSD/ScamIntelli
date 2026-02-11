import hashlib
import math
import re
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, FrozenSet, List, Optional, Set, Tuple

from src.utils.logging import get_logger

logger = get_logger(__name__)

MIN_MESSAGES_FOR_FINGERPRINT = 3
SIMILARITY_THRESHOLD = 0.75
MAX_STORED_FINGERPRINTS = 10000
SIGNATURE_NGRAM_SIZE = 3


@dataclass
class TimingPattern:
    avg_message_length: float
    length_variance: float
    avg_word_count: float
    punctuation_density: float
    capitalization_ratio: float


@dataclass
class LanguagePattern:
    vocabulary_richness: float
    avg_sentence_length: float
    top_bigrams: List[Tuple[str, int]]
    language_mix_ratio: float
    formality_score: float
    filler_word_ratio: float


@dataclass
class EscalationPattern:
    escalation_speed: float
    threat_density: float
    urgency_progression: float
    pressure_pattern: str


@dataclass
class BehavioralFingerprint:
    fingerprint_id: str
    session_id: str
    timing: TimingPattern
    language: LanguagePattern
    escalation: EscalationPattern
    entity_patterns: Dict[str, int]
    signature_hash: str
    created_at: str
    message_count: int


@dataclass
class FingerprintMatch:
    source_fingerprint_id: str
    matched_fingerprint_id: str
    similarity_score: float
    matched_session_id: str
    timing_similarity: float
    language_similarity: float
    pattern_similarity: float


HINDI_FILLERS: FrozenSet[str] = frozenset(
    {"ji", "haan", "accha", "theek", "bas", "bhai", "yaar", "dekho", "suno"}
)

ENGLISH_FILLERS: FrozenSet[str] = frozenset(
    {"um", "uh", "like", "okay", "well", "so", "basically", "actually", "just"}
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

THREAT_WORDS: FrozenSet[str] = frozenset(
    {
        "arrest", "jail", "police", "court", "penalty", "block",
        "suspend", "freeze", "terminate", "legal", "warrant",
        "giraftar", "thana", "kanoon",
    }
)

URGENCY_WORDS: FrozenSet[str] = frozenset(
    {
        "immediately", "urgent", "now", "hurry", "quick", "fast",
        "deadline", "expiring", "last", "final",
        "turant", "jaldi", "abhi", "fauran",
    }
)


class BehavioralFingerprinter:

    def __init__(self) -> None:
        self._stored_fingerprints: Dict[str, BehavioralFingerprint] = {}
        self._session_fingerprints: Dict[str, str] = {}

    def create_fingerprint(
        self, session_id: str, messages: List[dict]
    ) -> Optional[BehavioralFingerprint]:
        scammer_messages = [
            m.get("content", "")
            for m in messages
            if m.get("role") in ("user", "scammer") and m.get("content")
        ]

        if len(scammer_messages) < MIN_MESSAGES_FOR_FINGERPRINT:
            return None

        timing = self._analyze_timing(scammer_messages)
        language = self._analyze_language(scammer_messages)
        escalation = self._analyze_escalation(scammer_messages)
        entity_patterns = self._analyze_entity_patterns(scammer_messages)
        signature_hash = self._compute_signature_hash(
            timing, language, escalation
        )

        fingerprint_id = hashlib.sha256(
            f"{session_id}:{signature_hash}".encode()
        ).hexdigest()[:20]

        fp = BehavioralFingerprint(
            fingerprint_id=fingerprint_id,
            session_id=session_id,
            timing=timing,
            language=language,
            escalation=escalation,
            entity_patterns=entity_patterns,
            signature_hash=signature_hash,
            created_at=datetime.now(timezone.utc).isoformat(),
            message_count=len(scammer_messages),
        )

        return fp

    def store_fingerprint(self, fp: BehavioralFingerprint) -> None:
        if len(self._stored_fingerprints) >= MAX_STORED_FINGERPRINTS:
            oldest_key = next(iter(self._stored_fingerprints))
            old_fp = self._stored_fingerprints.pop(oldest_key)
            self._session_fingerprints.pop(old_fp.session_id, None)

        self._stored_fingerprints[fp.fingerprint_id] = fp
        self._session_fingerprints[fp.session_id] = fp.fingerprint_id

    def match_fingerprint(
        self, fp: BehavioralFingerprint, top_n: int = 5
    ) -> List[FingerprintMatch]:
        matches = []

        for stored_id, stored_fp in self._stored_fingerprints.items():
            if stored_fp.session_id == fp.session_id:
                continue

            timing_sim = self._timing_similarity(fp.timing, stored_fp.timing)
            language_sim = self._language_similarity(fp.language, stored_fp.language)
            pattern_sim = self._pattern_similarity(
                fp.escalation, stored_fp.escalation,
                fp.entity_patterns, stored_fp.entity_patterns,
            )

            overall = (
                timing_sim * 0.3
                + language_sim * 0.4
                + pattern_sim * 0.3
            )

            if overall >= SIMILARITY_THRESHOLD:
                matches.append(
                    FingerprintMatch(
                        source_fingerprint_id=fp.fingerprint_id,
                        matched_fingerprint_id=stored_id,
                        similarity_score=round(overall, 4),
                        matched_session_id=stored_fp.session_id,
                        timing_similarity=round(timing_sim, 4),
                        language_similarity=round(language_sim, 4),
                        pattern_similarity=round(pattern_sim, 4),
                    )
                )

        matches.sort(key=lambda m: m.similarity_score, reverse=True)
        return matches[:top_n]

    def get_fingerprint_by_session(
        self, session_id: str
    ) -> Optional[BehavioralFingerprint]:
        fp_id = self._session_fingerprints.get(session_id)
        if fp_id:
            return self._stored_fingerprints.get(fp_id)
        return None

    def get_stored_count(self) -> int:
        return len(self._stored_fingerprints)

    def _analyze_timing(self, messages: List[str]) -> TimingPattern:
        lengths = [len(m) for m in messages]
        word_counts = [len(m.split()) for m in messages]

        avg_length = sum(lengths) / max(len(lengths), 1)
        variance = (
            sum((l - avg_length) ** 2 for l in lengths) / max(len(lengths), 1)
        )
        avg_words = sum(word_counts) / max(len(word_counts), 1)

        total_chars = sum(lengths)
        punct_count = sum(
            sum(1 for c in m if c in ".,!?;:-")
            for m in messages
        )
        punct_density = punct_count / max(total_chars, 1)

        upper_count = sum(sum(1 for c in m if c.isupper()) for m in messages)
        cap_ratio = upper_count / max(total_chars, 1)

        return TimingPattern(
            avg_message_length=round(avg_length, 2),
            length_variance=round(variance, 2),
            avg_word_count=round(avg_words, 2),
            punctuation_density=round(punct_density, 6),
            capitalization_ratio=round(cap_ratio, 6),
        )

    def _analyze_language(self, messages: List[str]) -> LanguagePattern:
        all_text = " ".join(messages).lower()
        words = all_text.split()
        total_words = len(words)

        unique_words = len(set(words))
        vocab_richness = unique_words / max(total_words, 1)

        sentences = re.split(r"[.!?]+", all_text)
        sentences = [s.strip() for s in sentences if s.strip()]
        avg_sentence_len = (
            sum(len(s.split()) for s in sentences) / max(len(sentences), 1)
        )

        bigrams = []
        for i in range(len(words) - 1):
            bigrams.append((words[i], words[i + 1]))
        bigram_counter = Counter(bigrams)
        top_bigrams = [
            (f"{b[0]} {b[1]}", c) for b, c in bigram_counter.most_common(10)
        ]

        hindi_pattern = re.compile(r"[\u0900-\u097F]")
        hindi_chars = len(hindi_pattern.findall(all_text))
        alpha_chars = sum(1 for c in all_text if c.isalpha())
        lang_mix = hindi_chars / max(alpha_chars, 1)

        formal_count = sum(1 for w in words if w in FORMAL_INDICATORS)
        informal_count = sum(1 for w in words if w in INFORMAL_INDICATORS)
        formality = (formal_count - informal_count) / max(total_words, 1)

        filler_count = sum(
            1 for w in words if w in HINDI_FILLERS or w in ENGLISH_FILLERS
        )
        filler_ratio = filler_count / max(total_words, 1)

        return LanguagePattern(
            vocabulary_richness=round(vocab_richness, 4),
            avg_sentence_length=round(avg_sentence_len, 2),
            top_bigrams=top_bigrams,
            language_mix_ratio=round(lang_mix, 4),
            formality_score=round(formality, 4),
            filler_word_ratio=round(filler_ratio, 4),
        )

    def _analyze_escalation(self, messages: List[str]) -> EscalationPattern:
        if not messages:
            return EscalationPattern(
                escalation_speed=0.0,
                threat_density=0.0,
                urgency_progression=0.0,
                pressure_pattern="none",
            )

        threat_per_msg = []
        urgency_per_msg = []

        for msg in messages:
            msg_lower = msg.lower()
            words = msg_lower.split()
            word_count = max(len(words), 1)

            threat_count = sum(1 for w in words if w in THREAT_WORDS)
            urgency_count = sum(1 for w in words if w in URGENCY_WORDS)

            threat_per_msg.append(threat_count / word_count)
            urgency_per_msg.append(urgency_count / word_count)

        total_threat = sum(threat_per_msg)
        threat_density = total_threat / max(len(messages), 1)

        escalation_speed = 0.0
        if len(threat_per_msg) >= 2:
            first_half = sum(threat_per_msg[: len(threat_per_msg) // 2])
            second_half = sum(threat_per_msg[len(threat_per_msg) // 2 :])
            escalation_speed = second_half - first_half

        urgency_progression = 0.0
        if len(urgency_per_msg) >= 2:
            first_half = sum(urgency_per_msg[: len(urgency_per_msg) // 2])
            second_half = sum(urgency_per_msg[len(urgency_per_msg) // 2 :])
            urgency_progression = second_half - first_half

        if escalation_speed > 0.1 and urgency_progression > 0.1:
            pattern = "aggressive_escalation"
        elif escalation_speed > 0.05:
            pattern = "gradual_escalation"
        elif threat_density > 0.1:
            pattern = "sustained_pressure"
        elif urgency_progression > 0.05:
            pattern = "urgency_buildup"
        else:
            pattern = "low_pressure"

        return EscalationPattern(
            escalation_speed=round(max(escalation_speed, 0.0), 4),
            threat_density=round(threat_density, 4),
            urgency_progression=round(max(urgency_progression, 0.0), 4),
            pressure_pattern=pattern,
        )

    def _analyze_entity_patterns(self, messages: List[str]) -> Dict[str, int]:
        patterns = {
            "urls": 0,
            "phones": 0,
            "upis": 0,
            "emails": 0,
            "amounts": 0,
        }

        url_re = re.compile(r"https?://\S+")
        phone_re = re.compile(r"(?:\+91[\s\-]?)?[6-9]\d{9}")
        upi_re = re.compile(r"[a-zA-Z0-9._\-]+@[a-zA-Z]+")
        email_re = re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}")
        amount_re = re.compile(r"(?:₹|rs\.?|inr)\s*[\d,]+", re.IGNORECASE)

        for msg in messages:
            patterns["urls"] += len(url_re.findall(msg))
            patterns["phones"] += len(phone_re.findall(msg))
            patterns["upis"] += len(upi_re.findall(msg))
            patterns["emails"] += len(email_re.findall(msg))
            patterns["amounts"] += len(amount_re.findall(msg))

        return patterns

    def _compute_signature_hash(
        self,
        timing: TimingPattern,
        language: LanguagePattern,
        escalation: EscalationPattern,
    ) -> str:
        sig_parts = [
            f"len:{int(timing.avg_message_length / 50)}",
            f"vocab:{int(language.vocabulary_richness * 10)}",
            f"formal:{int(language.formality_score * 10)}",
            f"esc:{escalation.pressure_pattern}",
            f"threat:{int(escalation.threat_density * 100)}",
            f"cap:{int(timing.capitalization_ratio * 100)}",
        ]
        sig_string = "|".join(sig_parts)
        return hashlib.sha256(sig_string.encode()).hexdigest()[:16]

    def _timing_similarity(self, a: TimingPattern, b: TimingPattern) -> float:
        length_sim = 1.0 - min(
            abs(a.avg_message_length - b.avg_message_length)
            / max(a.avg_message_length, b.avg_message_length, 1.0),
            1.0,
        )

        word_sim = 1.0 - min(
            abs(a.avg_word_count - b.avg_word_count)
            / max(a.avg_word_count, b.avg_word_count, 1.0),
            1.0,
        )

        punct_sim = 1.0 - min(
            abs(a.punctuation_density - b.punctuation_density) * 100, 1.0
        )

        cap_sim = 1.0 - min(
            abs(a.capitalization_ratio - b.capitalization_ratio) * 50, 1.0
        )

        return (length_sim * 0.3 + word_sim * 0.3 + punct_sim * 0.2 + cap_sim * 0.2)

    def _language_similarity(self, a: LanguagePattern, b: LanguagePattern) -> float:
        vocab_sim = 1.0 - abs(a.vocabulary_richness - b.vocabulary_richness)

        sent_sim = 1.0 - min(
            abs(a.avg_sentence_length - b.avg_sentence_length)
            / max(a.avg_sentence_length, b.avg_sentence_length, 1.0),
            1.0,
        )

        a_bigrams = set(bg for bg, _ in a.top_bigrams)
        b_bigrams = set(bg for bg, _ in b.top_bigrams)
        if a_bigrams or b_bigrams:
            bigram_sim = len(a_bigrams & b_bigrams) / max(
                len(a_bigrams | b_bigrams), 1
            )
        else:
            bigram_sim = 0.5

        lang_sim = 1.0 - abs(a.language_mix_ratio - b.language_mix_ratio)

        formality_sim = 1.0 - min(
            abs(a.formality_score - b.formality_score) * 10, 1.0
        )

        return (
            vocab_sim * 0.2
            + sent_sim * 0.2
            + bigram_sim * 0.3
            + lang_sim * 0.15
            + formality_sim * 0.15
        )

    def _pattern_similarity(
        self,
        a_esc: EscalationPattern,
        b_esc: EscalationPattern,
        a_entities: Dict[str, int],
        b_entities: Dict[str, int],
    ) -> float:
        pattern_match = 1.0 if a_esc.pressure_pattern == b_esc.pressure_pattern else 0.3

        threat_sim = 1.0 - min(
            abs(a_esc.threat_density - b_esc.threat_density) * 10, 1.0
        )

        speed_sim = 1.0 - min(
            abs(a_esc.escalation_speed - b_esc.escalation_speed) * 5, 1.0
        )

        all_keys = set(a_entities.keys()) | set(b_entities.keys())
        if all_keys:
            entity_sim = sum(
                1.0 - min(
                    abs(a_entities.get(k, 0) - b_entities.get(k, 0))
                    / max(a_entities.get(k, 0), b_entities.get(k, 0), 1),
                    1.0,
                )
                for k in all_keys
            ) / len(all_keys)
        else:
            entity_sim = 0.5

        return (
            pattern_match * 0.3
            + threat_sim * 0.25
            + speed_sim * 0.2
            + entity_sim * 0.25
        )

    def reset(self) -> None:
        self._stored_fingerprints.clear()
        self._session_fingerprints.clear()


_global_fingerprinter: Optional[BehavioralFingerprinter] = None


def get_fingerprinter() -> BehavioralFingerprinter:
    global _global_fingerprinter
    if _global_fingerprinter is None:
        _global_fingerprinter = BehavioralFingerprinter()
    return _global_fingerprinter
