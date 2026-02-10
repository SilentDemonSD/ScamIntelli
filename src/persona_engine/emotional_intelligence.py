import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, FrozenSet, List, Tuple


class EmotionalState(str, Enum):
    FEAR = "fear"
    GREED = "greed"
    URGENCY = "urgency"
    TRUST = "trust"
    CONFUSION = "confusion"
    ANGER = "anger"
    SADNESS = "sadness"
    EXCITEMENT = "excitement"
    NEUTRAL = "neutral"


class ManipulationPattern(str, Enum):
    FEAR_ESCALATION = "fear_escalation"
    URGENCY_PRESSURE = "urgency_pressure"
    GREED_EXPLOITATION = "greed_exploitation"
    AUTHORITY_INTIMIDATION = "authority_intimidation"
    EMOTIONAL_BLACKMAIL = "emotional_blackmail"
    TRUST_BUILDING = "trust_building"
    ISOLATION_TACTICS = "isolation_tactics"
    SHAME_INDUCEMENT = "shame_inducement"
    NONE = "none"


@dataclass(frozen=True)
class EmotionalAnalysis:
    detected_emotion: EmotionalState
    emotion_intensity: float
    manipulation_pattern: ManipulationPattern
    emoji_sentiment: str
    recommended_persona_emotion: str
    response_style: str
    emoji_to_mirror: List[str]
    typing_pattern: str


@dataclass
class EmotionalHistory:
    emotion_timeline: List[Tuple[EmotionalState, float]] = field(default_factory=list)
    manipulation_count: int = 0
    escalation_rate: float = 0.0
    dominant_emotion: EmotionalState = EmotionalState.NEUTRAL


EMOJI_SENTIMENT_MAP: Dict[str, Tuple[str, float]] = {
    "😡": ("anger", 0.9),
    "🤬": ("anger", 1.0),
    "😠": ("anger", 0.7),
    "😤": ("anger", 0.6),
    "😱": ("fear", 0.9),
    "😨": ("fear", 0.8),
    "😰": ("fear", 0.7),
    "😥": ("fear", 0.5),
    "🥺": ("sadness", 0.6),
    "😢": ("sadness", 0.7),
    "😭": ("sadness", 0.9),
    "💰": ("greed", 0.7),
    "🤑": ("greed", 0.9),
    "💵": ("greed", 0.6),
    "💸": ("greed", 0.5),
    "🎉": ("excitement", 0.7),
    "🎊": ("excitement", 0.6),
    "🏆": ("excitement", 0.8),
    "🔥": ("urgency", 0.6),
    "⚠️": ("urgency", 0.8),
    "🚨": ("urgency", 0.9),
    "⏰": ("urgency", 0.7),
    "❗": ("urgency", 0.6),
    "‼️": ("urgency", 0.8),
    "❌": ("fear", 0.5),
    "✅": ("trust", 0.4),
    "🙏": ("trust", 0.5),
    "👍": ("trust", 0.3),
    "🤝": ("trust", 0.6),
    "❤️": ("trust", 0.7),
    "💔": ("sadness", 0.6),
    "😊": ("trust", 0.4),
    "😇": ("trust", 0.5),
    "🙄": ("anger", 0.3),
    "😏": ("manipulation", 0.5),
    "👮": ("fear", 0.7),
    "⚖️": ("fear", 0.6),
    "🏦": ("urgency", 0.4),
    "📞": ("urgency", 0.3),
    "🔒": ("fear", 0.5),
    "🔓": ("urgency", 0.4),
}

FEAR_KEYWORDS: FrozenSet[str] = frozenset(
    {
        "arrest", "jail", "police", "court", "warrant", "legal action",
        "case filed", "fir", "investigation", "suspend", "block",
        "freeze account", "terminate", "penalty", "fine", "prison",
        "giraftar", "thana", "kaid", "adalat", "saza", "jurmana",
        "band kar denge", "block ho jayega", "cancel ho jayega",
        "pakad lenge", "andar kar denge", "complaint filed",
    }
)

URGENCY_KEYWORDS: FrozenSet[str] = frozenset(
    {
        "immediately", "right now", "urgent", "last chance", "deadline",
        "within 24 hours", "today only", "time running out", "hurry",
        "quickly", "fast", "asap", "expires", "limited time",
        "abhi", "turant", "jaldi", "abhi ke abhi", "fauran",
        "der mat karo", "samay nahi hai", "aakhri mauka",
        "sirf aaj", "waqt khatam ho raha", "jaldi karo",
    }
)

GREED_KEYWORDS: FrozenSet[str] = frozenset(
    {
        "guaranteed returns", "double money", "100% profit", "risk free",
        "lottery won", "prize money", "jackpot", "inheritance",
        "million dollars", "lakh rupees", "crore", "bonus",
        "free money", "easy money", "high returns", "investment opportunity",
        "paisa double", "guaranteed profit", "lakho kamao",
        "crore mil jayega", "inaam", "jeet gaye", "lottery lagi",
        "muft paisa", "aasan kamai", "bada return",
    }
)

AUTHORITY_KEYWORDS: FrozenSet[str] = frozenset(
    {
        "i am officer", "this is official", "government order",
        "reserve bank", "rbi", "income tax", "cbi", "enforcement directorate",
        "supreme court", "high court", "narcotics bureau", "customs department",
        "ministry", "commissioner", "inspector", "superintendent",
        "sarkari order", "sarkar ki taraf se", "adhikari",
        "aadesh hai", "order hai", "kanoon ke mutabiq",
    }
)

EMOTIONAL_BLACKMAIL_KEYWORDS: FrozenSet[str] = frozenset(
    {
        "family will suffer", "children future", "reputation damage",
        "everyone will know", "social media leak", "photos shared",
        "video viral", "life ruined", "shame", "disgrace",
        "parivar barbad", "bacchon ka future", "izzat ka sawaal",
        "sabko pata chal jayega", "video viral ho jayega",
        "zindagi barbaad", "sharam", "badnami",
    }
)

TRUST_KEYWORDS: FrozenSet[str] = frozenset(
    {
        "trust me", "believe me", "i promise", "guaranteed",
        "i am here to help", "for your safety", "protection",
        "we care", "your benefit", "helping you",
        "bharosa karo", "vishwas karo", "main madad karunga",
        "aapki safety", "aapke bhale ke liye", "hum aapki madad",
    }
)

PERSONA_EMOTION_MIRROR = {
    EmotionalState.FEAR: {
        "response_style": "terrified_compliant",
        "emojis": ["😰", "🥺", "😱"],
        "typing_pattern": "shaky_fast",
    },
    EmotionalState.GREED: {
        "response_style": "excited_eager",
        "emojis": ["🤩", "😍", "💰"],
        "typing_pattern": "enthusiastic",
    },
    EmotionalState.URGENCY: {
        "response_style": "panicked_rushing",
        "emojis": ["😰", "🏃", "⏰"],
        "typing_pattern": "hurried_typos",
    },
    EmotionalState.TRUST: {
        "response_style": "warm_compliant",
        "emojis": ["🙏", "😊", "👍"],
        "typing_pattern": "normal_calm",
    },
    EmotionalState.CONFUSION: {
        "response_style": "lost_helpless",
        "emojis": ["😵", "🤔", "❓"],
        "typing_pattern": "slow_hesitant",
    },
    EmotionalState.ANGER: {
        "response_style": "meek_apologetic",
        "emojis": ["🥺", "🙏", "😢"],
        "typing_pattern": "careful_slow",
    },
    EmotionalState.SADNESS: {
        "response_style": "sympathetic_trusting",
        "emojis": ["😢", "🥺", "💔"],
        "typing_pattern": "slow_emotional",
    },
    EmotionalState.EXCITEMENT: {
        "response_style": "matching_excitement",
        "emojis": ["🎉", "😃", "🤩"],
        "typing_pattern": "fast_eager",
    },
    EmotionalState.NEUTRAL: {
        "response_style": "curious_engaged",
        "emojis": [],
        "typing_pattern": "normal",
    },
}

_EMOJI_PATTERN = re.compile(
    "["
    "\U0001f600-\U0001f64f"
    "\U0001f300-\U0001f5ff"
    "\U0001f680-\U0001f6ff"
    "\U0001f1e0-\U0001f1ff"
    "\U00002702-\U000027b0"
    "\U000024c2-\U0001f251"
    "\U0000200d"
    "\U0000fe0f"
    "\u2640-\u2642"
    "\u2600-\u2B55"
    "\u200d"
    "\u23cf"
    "\u23e9"
    "\u231a"
    "\ufe0f"
    "\u3030"
    "‼️⁉️❗❌✅⚠️🚨❓❔"
    "]+",
    flags=re.UNICODE,
)


class EmotionalIntelligenceEngine:
    _session_emotions: Dict[str, EmotionalHistory] = {}

    @classmethod
    def reset(cls):
        cls._session_emotions.clear()

    @classmethod
    def _get_history(cls, session_id: str) -> EmotionalHistory:
        if session_id not in cls._session_emotions:
            cls._session_emotions[session_id] = EmotionalHistory()
        return cls._session_emotions[session_id]

    @classmethod
    def analyze(
        cls,
        message: str,
        session_id: str,
        conversation_history: List[dict] = None,
    ) -> EmotionalAnalysis:
        history = cls._get_history(session_id)

        emojis = cls._extract_emojis(message)
        emoji_sentiment = cls._analyze_emoji_sentiment(emojis)
        detected_emotion, intensity = cls._detect_emotion(message, emoji_sentiment)
        manipulation = cls._detect_manipulation(message, conversation_history or [])

        history.emotion_timeline.append((detected_emotion, intensity))
        if manipulation != ManipulationPattern.NONE:
            history.manipulation_count += 1

        cls._update_escalation_rate(history)
        history.dominant_emotion = cls._calculate_dominant_emotion(history)

        mirror = PERSONA_EMOTION_MIRROR.get(
            detected_emotion, PERSONA_EMOTION_MIRROR[EmotionalState.NEUTRAL]
        )

        return EmotionalAnalysis(
            detected_emotion=detected_emotion,
            emotion_intensity=intensity,
            manipulation_pattern=manipulation,
            emoji_sentiment=emoji_sentiment,
            recommended_persona_emotion=mirror["response_style"],
            response_style=mirror["response_style"],
            emoji_to_mirror=mirror["emojis"],
            typing_pattern=mirror["typing_pattern"],
        )

    @classmethod
    def _extract_emojis(cls, text: str) -> List[str]:
        return _EMOJI_PATTERN.findall(text)

    @classmethod
    def _analyze_emoji_sentiment(cls, emojis: List[str]) -> str:
        if not emojis:
            return "neutral"

        sentiments: Dict[str, float] = {}
        for emoji in emojis:
            if emoji in EMOJI_SENTIMENT_MAP:
                sentiment, weight = EMOJI_SENTIMENT_MAP[emoji]
                sentiments[sentiment] = sentiments.get(sentiment, 0) + weight

        if not sentiments:
            return "neutral"

        return max(sentiments, key=sentiments.get)

    @classmethod
    def _detect_emotion(
        cls, message: str, emoji_sentiment: str
    ) -> Tuple[EmotionalState, float]:
        message_lower = message.lower()

        scores: Dict[EmotionalState, float] = {e: 0.0 for e in EmotionalState}

        keyword_map = {
            EmotionalState.FEAR: FEAR_KEYWORDS,
            EmotionalState.URGENCY: URGENCY_KEYWORDS,
            EmotionalState.GREED: GREED_KEYWORDS,
            EmotionalState.TRUST: TRUST_KEYWORDS,
        }

        for emotion, keywords in keyword_map.items():
            matches = sum(1 for kw in keywords if kw in message_lower)
            if matches:
                scores[emotion] += min(matches * 0.2, 0.8)

        sentiment_to_emotion = {
            "anger": EmotionalState.ANGER,
            "fear": EmotionalState.FEAR,
            "sadness": EmotionalState.SADNESS,
            "greed": EmotionalState.GREED,
            "excitement": EmotionalState.EXCITEMENT,
            "trust": EmotionalState.TRUST,
            "urgency": EmotionalState.URGENCY,
            "manipulation": EmotionalState.FEAR,
        }

        if emoji_sentiment in sentiment_to_emotion:
            scores[sentiment_to_emotion[emoji_sentiment]] += 0.3

        caps_ratio = sum(1 for c in message if c.isupper()) / max(len(message), 1)
        if caps_ratio > 0.5 and len(message) > 5:
            scores[EmotionalState.ANGER] += 0.2
            scores[EmotionalState.URGENCY] += 0.2

        exclamation_count = message.count("!")
        if exclamation_count >= 3:
            scores[EmotionalState.URGENCY] += 0.2
        elif exclamation_count >= 1:
            scores[EmotionalState.URGENCY] += 0.1

        question_count = message.count("?")
        if question_count >= 2:
            scores[EmotionalState.CONFUSION] += 0.2

        max_emotion = max(scores, key=scores.get)
        max_score = scores[max_emotion]

        if max_score < 0.1:
            return EmotionalState.NEUTRAL, 0.0

        return max_emotion, min(max_score, 1.0)

    @classmethod
    def _detect_manipulation(
        cls, message: str, conversation_history: List[dict]
    ) -> ManipulationPattern:
        message_lower = message.lower()

        fear_matches = sum(1 for kw in FEAR_KEYWORDS if kw in message_lower)
        authority_matches = sum(1 for kw in AUTHORITY_KEYWORDS if kw in message_lower)
        if fear_matches >= 2 and authority_matches >= 1:
            return ManipulationPattern.AUTHORITY_INTIMIDATION

        if fear_matches >= 2:
            return ManipulationPattern.FEAR_ESCALATION

        urgency_matches = sum(1 for kw in URGENCY_KEYWORDS if kw in message_lower)
        if urgency_matches >= 2:
            return ManipulationPattern.URGENCY_PRESSURE

        greed_matches = sum(1 for kw in GREED_KEYWORDS if kw in message_lower)
        if greed_matches >= 2:
            return ManipulationPattern.GREED_EXPLOITATION

        blackmail_matches = sum(
            1 for kw in EMOTIONAL_BLACKMAIL_KEYWORDS if kw in message_lower
        )
        if blackmail_matches >= 1:
            return ManipulationPattern.EMOTIONAL_BLACKMAIL

        if authority_matches >= 2:
            return ManipulationPattern.AUTHORITY_INTIMIDATION

        isolation_patterns = {
            "don't tell anyone",
            "keep this secret",
            "between us",
            "kisi ko mat batana",
            "secret rakhna",
            "akele mein karo",
            "family ko mat batao",
        }
        if any(p in message_lower for p in isolation_patterns):
            return ManipulationPattern.ISOLATION_TACTICS

        shame_patterns = {
            "shame on you",
            "how dare you",
            "disgraceful",
            "sharam karo",
            "tameez nahi hai",
            "badtameez",
        }
        if any(p in message_lower for p in shame_patterns):
            return ManipulationPattern.SHAME_INDUCEMENT

        if conversation_history:
            recent_scammer = [
                m.get("content", "").lower()
                for m in conversation_history[-6:]
                if m.get("role") in ("user", "scammer")
            ]
            if len(recent_scammer) >= 3:
                recent_fear = sum(
                    sum(1 for kw in FEAR_KEYWORDS if kw in msg)
                    for msg in recent_scammer[-3:]
                )
                if recent_fear >= 4:
                    return ManipulationPattern.FEAR_ESCALATION

        return ManipulationPattern.NONE

    @classmethod
    def _update_escalation_rate(cls, history: EmotionalHistory):
        if len(history.emotion_timeline) < 2:
            history.escalation_rate = 0.0
            return

        recent = history.emotion_timeline[-5:]
        intensities = [i for _, i in recent]

        if len(intensities) >= 2:
            increases = sum(
                1 for i in range(1, len(intensities)) if intensities[i] > intensities[i - 1]
            )
            history.escalation_rate = increases / (len(intensities) - 1)

    @classmethod
    def _calculate_dominant_emotion(cls, history: EmotionalHistory) -> EmotionalState:
        if not history.emotion_timeline:
            return EmotionalState.NEUTRAL

        emotion_weights: Dict[EmotionalState, float] = {}
        total = len(history.emotion_timeline)

        for idx, (emotion, intensity) in enumerate(history.emotion_timeline):
            recency_weight = (idx + 1) / total
            weighted = intensity * recency_weight
            emotion_weights[emotion] = emotion_weights.get(emotion, 0) + weighted

        return max(emotion_weights, key=emotion_weights.get)

    @classmethod
    def get_emotion_hint(cls, analysis: EmotionalAnalysis) -> str:
        hints = {
            ManipulationPattern.FEAR_ESCALATION: "Scammer escalating fear. Show increasing panic and compliance. Ask what to do.",
            ManipulationPattern.URGENCY_PRESSURE: "Scammer creating urgency. Show rushing but struggling with technology.",
            ManipulationPattern.GREED_EXPLOITATION: "Scammer exploiting greed. Show excitement but ask naive questions about details.",
            ManipulationPattern.AUTHORITY_INTIMIDATION: "Scammer using authority. Show deep respect and fear of government.",
            ManipulationPattern.EMOTIONAL_BLACKMAIL: "Scammer using emotional blackmail. Show genuine distress and desperation.",
            ManipulationPattern.TRUST_BUILDING: "Scammer building trust. Show growing comfort and openness.",
            ManipulationPattern.ISOLATION_TACTICS: "Scammer isolating victim. Agree to keep secret but mention wanting to tell family.",
            ManipulationPattern.SHAME_INDUCEMENT: "Scammer shaming. Show embarrassment and desire to fix things.",
        }

        base_hint = hints.get(
            analysis.manipulation_pattern,
            f"Match {analysis.detected_emotion.value} emotional tone naturally.",
        )

        if analysis.emotion_intensity > 0.7:
            base_hint += " HIGH INTENSITY: Show strong emotional reaction."

        return base_hint

    @classmethod
    def cleanup_session(cls, session_id: str):
        cls._session_emotions.pop(session_id, None)
