import re
from dataclasses import dataclass
from typing import Any, Dict, FrozenSet, List

from src.scam_detector.classifier import (
    calculate_intent_score,
    calculate_keyword_score,
    calculate_pattern_score,
)
from src.scam_detector.keywords import (
    CREDENTIAL_KEYWORDS,
    THREAT_KEYWORDS,
    URGENCY_KEYWORDS,
)
from src.scam_detector.ml_engine import (
    AdvancedFeatureExtractor,
    MLScamDetector,
    PatternLearner,
)


@dataclass(frozen=True)
class HybridDetectionResult:
    is_scam: bool
    confidence: float
    breakdown: Dict[str, float]
    has_hard_indicators: bool
    detection_layers_used: List[str]


HARD_INDICATOR_PATTERNS = (
    re.compile(r"[a-zA-Z0-9._\-]+@[a-zA-Z]+"),
    re.compile(r"https?://\S+"),
    re.compile(r"(?:\+91[\s\-]?)?[6-9]\d{9}"),
)

HARD_INDICATOR_PHRASES: FrozenSet[str] = frozenset(
    {
        "verify immediately",
        "account block",
        "urgent action",
        "send otp",
        "share otp",
        "otp batao",
        "otp bhejo",
        "turant verify",
        "account suspend",
        "arrest warrant",
        "digital arrest",
        "transfer now",
        "pay immediately",
    }
)

BEHAVIORAL_ESCALATION_INDICATORS: FrozenSet[str] = frozenset(
    {
        "last chance", "final warning", "time running out",
        "act now or else", "only 5 minutes", "do it now",
        "aakhri mauka", "samay khatam", "abhi karo warna",
    }
)

MULTI_VECTOR_PATTERNS: FrozenSet[str] = frozenset(
    {
        "click the link and enter otp",
        "scan qr code and pay",
        "download app and share screen",
        "video call pe aao aur",
        "link pe click karo aur otp",
        "qr scan karo paisa aayega",
    }
)


class HybridScamDetectionEngine:

    @classmethod
    async def detect(
        cls,
        message: str,
        session_messages: List[dict] = None,
        emotional_score: float = 0.0,
        multilingual_keywords: List[str] = None,
        url_threat_score: float = 0.0,
    ) -> HybridDetectionResult:
        scores: Dict[str, float] = {}
        layers_used = []

        keyword_score, matched_keywords = await calculate_keyword_score(message)
        scores["keyword"] = keyword_score
        layers_used.append("keyword")

        if keyword_score < 0.1 and url_threat_score < 0.2 and emotional_score < 0.2:
            return HybridDetectionResult(
                is_scam=False,
                confidence=0.95,
                breakdown=scores,
                has_hard_indicators=False,
                detection_layers_used=layers_used,
            )

        intent_score = await calculate_intent_score(message)
        scores["intent"] = intent_score
        layers_used.append("intent")

        pattern_score = await calculate_pattern_score(message)
        scores["pattern"] = pattern_score
        layers_used.append("pattern")

        scores["emotion"] = emotional_score
        if emotional_score > 0:
            layers_used.append("emotion")

        behavioral_score = cls._analyze_behavioral_signals(
            message, session_messages or []
        )
        scores["behavioral"] = behavioral_score
        if behavioral_score > 0:
            layers_used.append("behavioral")

        scores["url_threat"] = url_threat_score
        if url_threat_score > 0:
            layers_used.append("url_threat")

        multilingual_boost = 0.0
        if multilingual_keywords:
            multilingual_boost = min(len(multilingual_keywords) * 0.05, 0.3)
        scores["multilingual"] = multilingual_boost
        if multilingual_boost > 0:
            layers_used.append("multilingual")

        multi_vector = cls._detect_multi_vector_attack(message)
        scores["multi_vector"] = multi_vector
        if multi_vector > 0:
            layers_used.append("multi_vector")

        ml_prediction = await MLScamDetector.predict(message, session_messages)
        scores["ml_model"] = ml_prediction.confidence
        layers_used.append(f"ml:{ml_prediction.model_used}")

        pattern_score_learned = PatternLearner.get_pattern_score(message)
        scores["learned_patterns"] = pattern_score_learned
        if pattern_score_learned > 0:
            layers_used.append("learned_patterns")

        MLScamDetector.save_training_sample(message, True if scores["keyword"] > 0.3 else False)

        final_score = (
            scores["keyword"] * 0.12
            + scores["intent"] * 0.25
            + scores["pattern"] * 0.12
            + scores["emotion"] * 0.08
            + scores["behavioral"] * 0.08
            + scores["url_threat"] * 0.08
            + scores["multilingual"] * 0.04
            + scores["multi_vector"] * 0.05
            + scores["ml_model"] * 0.12
            + scores["learned_patterns"] * 0.06
        )

        has_hard = cls._has_hard_indicators(message)

        if final_score > 0.75 and not has_hard:
            final_score *= 0.7

        if has_hard and final_score > 0.3:
            final_score = max(final_score, 0.72)

        if multi_vector > 0.5:
            final_score = max(final_score, 0.8)

        is_scam = (
            final_score >= 0.72
            or intent_score >= 0.5
            or (keyword_score >= 0.4 and pattern_score >= 0.3)
            or (url_threat_score >= 0.7 and keyword_score >= 0.2)
        )

        return HybridDetectionResult(
            is_scam=is_scam,
            confidence=round(min(final_score, 1.0), 4),
            breakdown=scores,
            has_hard_indicators=has_hard,
            detection_layers_used=layers_used,
        )

    @classmethod
    def _has_hard_indicators(cls, message: str) -> bool:
        for pattern in HARD_INDICATOR_PATTERNS:
            if pattern.search(message):
                return True
        message_lower = message.lower()
        return any(phrase in message_lower for phrase in HARD_INDICATOR_PHRASES)

    @classmethod
    def _analyze_behavioral_signals(
        cls, message: str, session_messages: List[dict]
    ) -> float:
        score = 0.0
        message_lower = message.lower()

        escalation_count = sum(
            1 for kw in BEHAVIORAL_ESCALATION_INDICATORS if kw in message_lower
        )
        score += min(escalation_count * 0.15, 0.4)

        if not session_messages:
            return score

        recent_scammer = [
            m.get("content", "").lower()
            for m in session_messages[-8:]
            if m.get("role") in ("user", "scammer")
        ]

        if len(recent_scammer) >= 3:
            threat_escalation = 0
            for i, msg in enumerate(recent_scammer[-3:]):
                threat_count = sum(1 for kw in THREAT_KEYWORDS if kw in msg)
                threat_escalation += threat_count * (i + 1)
            if threat_escalation > 5:
                score += 0.3

        if len(recent_scammer) >= 2:
            urgency_count = sum(
                sum(1 for kw in URGENCY_KEYWORDS if kw in msg)
                for msg in recent_scammer[-3:]
            )
            if urgency_count >= 4:
                score += 0.2

        if len(recent_scammer) >= 2:
            credential_pressure = sum(
                sum(1 for kw in CREDENTIAL_KEYWORDS if kw in msg)
                for msg in recent_scammer[-3:]
            )
            if credential_pressure >= 3:
                score += 0.25

        return min(score, 1.0)

    @classmethod
    def _detect_multi_vector_attack(cls, message: str) -> float:
        message_lower = message.lower()

        if any(pattern in message_lower for pattern in MULTI_VECTOR_PATTERNS):
            return 0.8

        vectors = {
            "url": bool(re.search(r"https?://", message_lower)),
            "upi": bool(re.search(r"[a-zA-Z0-9]+@[a-zA-Z]+", message_lower)),
            "phone": bool(re.search(r"(?:\+91)?[6-9]\d{9}", message)),
            "credential_ask": any(
                kw in message_lower for kw in ("otp", "pin", "password", "cvv")
            ),
            "threat": any(
                kw in message_lower for kw in ("arrest", "block", "legal", "police")
            ),
            "action": any(
                kw in message_lower
                for kw in ("click", "scan", "download", "install", "share screen")
            ),
        }

        active_vectors = sum(1 for v in vectors.values() if v)

        if active_vectors >= 3:
            return min(active_vectors * 0.2, 0.9)
        return 0.0

    @classmethod
    async def detect_with_explanation(
        cls,
        message: str,
        session_messages: List[dict] = None,
        emotional_score: float = 0.0,
        multilingual_keywords: List[str] = None,
        url_threat_score: float = 0.0,
    ) -> Dict[str, Any]:
        result = await cls.detect(
            message, session_messages, emotional_score,
            multilingual_keywords, url_threat_score,
        )

        advanced_features = AdvancedFeatureExtractor.extract_advanced_features(
            message, session_messages
        )

        layer_weights = {
            "keyword": 0.12,
            "intent": 0.25,
            "pattern": 0.12,
            "emotion": 0.08,
            "behavioral": 0.08,
            "url_threat": 0.08,
            "multilingual": 0.04,
            "multi_vector": 0.05,
            "ml_model": 0.12,
            "learned_patterns": 0.06,
        }

        layer_contributions = {}
        for layer_name, weight in layer_weights.items():
            score = result.breakdown.get(layer_name, 0.0)
            contribution = score * weight
            layer_contributions[layer_name] = {
                "raw_score": round(score, 4),
                "weight": weight,
                "contribution": round(contribution, 4),
                "percentage": round(
                    contribution / max(result.confidence, 0.001) * 100, 2
                ),
            }

        sorted_layers = sorted(
            layer_contributions.items(),
            key=lambda x: x[1]["contribution"],
            reverse=True,
        )

        top_signals = []
        for layer_name, details in sorted_layers[:5]:
            if details["raw_score"] > 0:
                top_signals.append({
                    "signal": layer_name,
                    "strength": details["raw_score"],
                    "impact": details["percentage"],
                })

        risk_factors = []
        if result.breakdown.get("keyword", 0) > 0.3:
            risk_factors.append("High scam keyword density detected")
        if result.breakdown.get("intent", 0) > 0.4:
            risk_factors.append("Strong malicious intent signals")
        if result.breakdown.get("behavioral", 0) > 0.3:
            risk_factors.append("Behavioral escalation pattern detected")
        if result.breakdown.get("url_threat", 0) > 0.5:
            risk_factors.append("Suspicious URL/link detected")
        if result.breakdown.get("multi_vector", 0) > 0.3:
            risk_factors.append("Multi-vector attack pattern")
        if result.has_hard_indicators:
            risk_factors.append("Hard indicators present (UPI/phone/link)")

        psych_tactics = []
        if advanced_features.get("psych_fear_appeal_score", 0) > 0.3:
            psych_tactics.append("Fear/threat appeals")
        if advanced_features.get("psych_authority_claim_score", 0) > 0.3:
            psych_tactics.append("Authority impersonation")
        if advanced_features.get("psych_scarcity_score", 0) > 0.3:
            psych_tactics.append("Artificial scarcity")
        if advanced_features.get("psych_social_proof_score", 0) > 0.3:
            psych_tactics.append("Social proof manipulation")
        if advanced_features.get("psych_reciprocity_score", 0) > 0.3:
            psych_tactics.append("Reciprocity exploitation")
        if advanced_features.get("psych_emotional_manipulation", 0) > 0.3:
            psych_tactics.append("Emotional manipulation")

        if result.confidence >= 0.85:
            risk_level = "critical"
        elif result.confidence >= 0.72:
            risk_level = "high"
        elif result.confidence >= 0.5:
            risk_level = "medium"
        elif result.confidence >= 0.3:
            risk_level = "low"
        else:
            risk_level = "minimal"

        return {
            "detection_result": {
                "is_scam": result.is_scam,
                "confidence": result.confidence,
                "risk_level": risk_level,
                "has_hard_indicators": result.has_hard_indicators,
            },
            "layer_breakdown": dict(sorted_layers),
            "top_signals": top_signals,
            "risk_factors": risk_factors,
            "psychological_tactics": psych_tactics,
            "advanced_features": {
                k: round(v, 4) for k, v in advanced_features.items()
            },
            "detection_layers_used": result.detection_layers_used,
            "score_breakdown": result.breakdown,
        }
