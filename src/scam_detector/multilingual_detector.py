import re
from contextlib import suppress
from dataclasses import dataclass
from enum import Enum
from typing import FrozenSet, List, Optional, Tuple

import httpx

from src.config import get_settings
from src.persona_engine.personas import HINDI_PATTERNS as ROMANIZED_HINDI_MARKERS
from src.utils.logging import get_logger

logger = get_logger(__name__)


class DetectedLanguage(str, Enum):
    HINDI = "hindi"
    ENGLISH = "english"
    HINGLISH = "hinglish"
    BENGALI = "bengali"
    TAMIL = "tamil"
    TELUGU = "telugu"
    MARATHI = "marathi"
    GUJARATI = "gujarati"
    KANNADA = "kannada"
    MALAYALAM = "malayalam"
    PUNJABI = "punjabi"
    UNKNOWN = "unknown"


class CodeSwitchType(str, Enum):
    NONE = "none"
    INTER_SENTENTIAL = "inter_sentential"
    INTRA_SENTENTIAL = "intra_sentential"
    TAG_SWITCHING = "tag_switching"


@dataclass(frozen=True)
class MultiLingualResult:
    primary_language: DetectedLanguage
    secondary_language: Optional[DetectedLanguage]
    code_switch_type: CodeSwitchType
    hindi_ratio: float
    english_ratio: float
    script_detected: str
    translated_text: Optional[str]
    scam_keywords_multilingual: List[str]
    confidence: float


DEVANAGARI_RANGE = re.compile(r"[\u0900-\u097F]")
BENGALI_RANGE = re.compile(r"[\u0980-\u09FF]")
TAMIL_RANGE = re.compile(r"[\u0B80-\u0BFF]")
TELUGU_RANGE = re.compile(r"[\u0C00-\u0C7F]")
KANNADA_RANGE = re.compile(r"[\u0C80-\u0CFF]")
MALAYALAM_RANGE = re.compile(r"[\u0D00-\u0D7F]")
GUJARATI_RANGE = re.compile(r"[\u0A80-\u0AFF]")
GURMUKHI_RANGE = re.compile(r"[\u0A00-\u0A7F]")
LATIN_RANGE = re.compile(r"[a-zA-Z]")

HINDI_SCAM_KEYWORDS: FrozenSet[str] = frozenset(
    {
        "giraftar", "giraftaar", "thana", "FIR", "case darj",
        "paisa bhejo", "paise transfer", "jaldi karo", "turant",
        "khaata band", "account block", "arrest warrant",
        "court ka order", "police aayegi", "jail hogi",
        "otp batao", "otp bhejo", "pin batao", "password do",
        "link pe click", "app download", "anydesk install",
        "teamviewer lagao", "screen share", "remote access",
        "lottery jeet", "inaam mila", "crore rupay",
        "investment return", "double paisa", "guarantee profit",
        "KYC update", "aadhar verify", "pan verify",
        "bank se hun", "rbi se hun", "police se hun",
        "customs se", "narcotics se", "income tax se",
        "parcel roka", "drugs mila", "illegal saman",
        "sim block hoga", "number band", "4g to 5g",
        "QR scan karo", "receive karne ke liye scan",
        "refund pending", "extra paisa", "wapas bhej do",
        "private photos", "video leak", "izzat loot",
        "naukri pakki", "job confirm", "registration fee",
    }
)

HINGLISH_SCAM_KEYWORDS: FrozenSet[str] = frozenset(
    {
        "urgent hai", "abhi karo", "jaldi se", "time nahi hai",
        "account freeze ho jayega", "penalty lag jayegi",
        "legal action hoga", "arrest ho jaoge",
        "otp share karo", "password batao", "pin de do",
        "link open karo", "app install karo",
        "guaranteed return milega", "double ho jayega",
        "risk free hai", "100% safe hai",
        "main officer hun", "main bank se bol raha",
        "government order hai", "court se notice aaya",
        "family ko batayenge", "social media pe dalenge",
        "video viral kar denge", "photos bhej denge sabko",
        "kisi ko mat batana", "secret rakhna yeh",
    }
)

TAMIL_SCAM_KEYWORDS: FrozenSet[str] = frozenset(
    {
        "kaival", "eppoluthe", "arrest", "police",
        "panam anuppu", "udane", "OTP sollu",
    }
)

BENGALI_SCAM_KEYWORDS: FrozenSet[str] = frozenset(
    {
        "taka pathao", "grefter", "police ashbe",
        "OTP bolo", "jodi", "tara tari",
    }
)

TELUGU_SCAM_KEYWORDS: FrozenSet[str] = frozenset(
    {
        "dabbu pampu", "arrest", "police vastundi",
        "OTP cheppu", "urgent", "ventane",
    }
)

SARVAM_LANGUAGE_MAP = {
    DetectedLanguage.HINDI: "hi-IN",
    DetectedLanguage.BENGALI: "bn-IN",
    DetectedLanguage.TAMIL: "ta-IN",
    DetectedLanguage.TELUGU: "te-IN",
    DetectedLanguage.MARATHI: "mr-IN",
    DetectedLanguage.GUJARATI: "gu-IN",
    DetectedLanguage.KANNADA: "kn-IN",
    DetectedLanguage.MALAYALAM: "ml-IN",
    DetectedLanguage.PUNJABI: "pa-IN",
    DetectedLanguage.ENGLISH: "en-IN",
}



class MultiLingualDetector:

    @classmethod
    async def analyze(
        cls,
        message: str,
        session_id: str = "",
    ) -> MultiLingualResult:
        script = cls._detect_script(message)
        primary, secondary = cls._detect_language(message, script)
        code_switch = cls._detect_code_switching(message, primary, secondary)
        hindi_ratio, english_ratio = cls._calculate_ratios(message)
        keywords = cls._extract_multilingual_keywords(message, primary)

        translated = None
        if primary not in (DetectedLanguage.ENGLISH, DetectedLanguage.HINGLISH):
            translated = await cls._translate_to_english(message, primary)
            if translated:
                english_keywords = cls._extract_multilingual_keywords(
                    translated, DetectedLanguage.ENGLISH
                )
                keywords = list(set(keywords + english_keywords))

        confidence = cls._calculate_confidence(
            message, primary, hindi_ratio, english_ratio, script
        )

        return MultiLingualResult(
            primary_language=primary,
            secondary_language=secondary if secondary != primary else None,
            code_switch_type=code_switch,
            hindi_ratio=hindi_ratio,
            english_ratio=english_ratio,
            script_detected=script,
            translated_text=translated,
            scam_keywords_multilingual=keywords,
            confidence=confidence,
        )

    @classmethod
    def _detect_script(cls, text: str) -> str:
        scripts = {
            "devanagari": len(DEVANAGARI_RANGE.findall(text)),
            "bengali": len(BENGALI_RANGE.findall(text)),
            "tamil": len(TAMIL_RANGE.findall(text)),
            "telugu": len(TELUGU_RANGE.findall(text)),
            "kannada": len(KANNADA_RANGE.findall(text)),
            "malayalam": len(MALAYALAM_RANGE.findall(text)),
            "gujarati": len(GUJARATI_RANGE.findall(text)),
            "gurmukhi": len(GURMUKHI_RANGE.findall(text)),
            "latin": len(LATIN_RANGE.findall(text)),
        }

        total = sum(scripts.values())
        if total == 0:
            return "unknown"

        dominant = max(scripts, key=scripts.get)
        if scripts[dominant] / total < 0.3:
            return "mixed"
        return dominant

    @classmethod
    def _detect_language(
        cls, text: str, script: str
    ) -> Tuple[DetectedLanguage, DetectedLanguage]:
        script_to_language = {
            "bengali": DetectedLanguage.BENGALI,
            "tamil": DetectedLanguage.TAMIL,
            "telugu": DetectedLanguage.TELUGU,
            "kannada": DetectedLanguage.KANNADA,
            "malayalam": DetectedLanguage.MALAYALAM,
            "gujarati": DetectedLanguage.GUJARATI,
            "gurmukhi": DetectedLanguage.PUNJABI,
        }

        if script in script_to_language:
            primary = script_to_language[script]
            has_latin = bool(LATIN_RANGE.search(text))
            secondary = DetectedLanguage.ENGLISH if has_latin else primary
            return primary, secondary

        if script == "devanagari":
            has_latin = bool(LATIN_RANGE.search(text))
            if has_latin:
                return DetectedLanguage.HINDI, DetectedLanguage.ENGLISH
            return DetectedLanguage.HINDI, DetectedLanguage.HINDI

        words = set(re.findall(r"\b[a-zA-Z]+\b", text.lower()))
        hindi_marker_count = len(words & ROMANIZED_HINDI_MARKERS)
        total_words = len(words)

        if total_words == 0:
            return DetectedLanguage.UNKNOWN, DetectedLanguage.UNKNOWN

        hindi_ratio = hindi_marker_count / total_words

        if hindi_ratio > 0.25:
            return DetectedLanguage.HINGLISH, DetectedLanguage.ENGLISH
        elif hindi_ratio > 0.1:
            return DetectedLanguage.HINGLISH, DetectedLanguage.HINDI
        elif hindi_ratio > 0.03:
            return DetectedLanguage.ENGLISH, DetectedLanguage.HINGLISH
        return DetectedLanguage.ENGLISH, DetectedLanguage.ENGLISH

    @classmethod
    def _detect_code_switching(
        cls,
        text: str,
        primary: DetectedLanguage,
        secondary: DetectedLanguage,
    ) -> CodeSwitchType:
        if primary == secondary:
            return CodeSwitchType.NONE

        sentences = re.split(r"[.!?\n]+", text)
        sentences = [s.strip() for s in sentences if s.strip()]

        if len(sentences) < 2:
            hindi_words = set(re.findall(r"\b[a-zA-Z]+\b", text.lower())) & ROMANIZED_HINDI_MARKERS
            has_devanagari = bool(DEVANAGARI_RANGE.search(text))
            has_latin = bool(LATIN_RANGE.search(text))

            if (hindi_words or has_devanagari) and has_latin:
                return CodeSwitchType.INTRA_SENTENTIAL
            return CodeSwitchType.NONE

        language_per_sentence = []
        for sent in sentences:
            sent_words = set(re.findall(r"\b[a-zA-Z]+\b", sent.lower()))
            hindi_count = len(sent_words & ROMANIZED_HINDI_MARKERS)
            has_native = bool(
                DEVANAGARI_RANGE.search(sent)
                or BENGALI_RANGE.search(sent)
                or TAMIL_RANGE.search(sent)
            )
            total = len(sent_words)

            if has_native:
                language_per_sentence.append("native")
            elif total > 0 and hindi_count / total > 0.3:
                language_per_sentence.append("hindi")
            else:
                language_per_sentence.append("english")

        unique_languages = set(language_per_sentence)
        if len(unique_languages) > 1:
            return CodeSwitchType.INTER_SENTENTIAL

        return CodeSwitchType.NONE

    @classmethod
    def _calculate_ratios(cls, text: str) -> Tuple[float, float]:
        words = re.findall(r"\b[a-zA-Z]+\b", text.lower())
        if not words:
            has_devanagari = bool(DEVANAGARI_RANGE.search(text))
            return (1.0, 0.0) if has_devanagari else (0.0, 0.0)

        total = len(words)
        hindi_count = sum(1 for w in words if w in ROMANIZED_HINDI_MARKERS)
        english_count = total - hindi_count

        return hindi_count / total, english_count / total

    @classmethod
    def _extract_multilingual_keywords(
        cls, message: str, language: DetectedLanguage
    ) -> List[str]:
        message_lower = message.lower()
        matched = []

        keyword_sets = {
            DetectedLanguage.HINDI: [HINDI_SCAM_KEYWORDS, HINGLISH_SCAM_KEYWORDS],
            DetectedLanguage.HINGLISH: [HINGLISH_SCAM_KEYWORDS, HINDI_SCAM_KEYWORDS],
            DetectedLanguage.BENGALI: [BENGALI_SCAM_KEYWORDS],
            DetectedLanguage.TAMIL: [TAMIL_SCAM_KEYWORDS],
            DetectedLanguage.TELUGU: [TELUGU_SCAM_KEYWORDS],
        }

        sets_to_check = keyword_sets.get(language, [HINGLISH_SCAM_KEYWORDS])
        for kw_set in sets_to_check:
            matched.extend(kw for kw in kw_set if kw in message_lower)

        return list(set(matched))

    @classmethod
    async def _translate_to_english(
        cls, text: str, source_language: DetectedLanguage
    ) -> Optional[str]:
        settings = get_settings()
        api_key = settings.sarvam_api_key
        if not api_key or api_key.startswith("default_"):
            return None

        source_code = SARVAM_LANGUAGE_MAP.get(source_language)
        if not source_code:
            return None

        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                response = await client.post(
                    "https://api.sarvam.ai/translate",
                    headers={
                        "api-subscription-key": api_key,
                        "Content-Type": "application/json",
                    },
                    json={
                        "input": text[:2000],
                        "source_language_code": source_code,
                        "target_language_code": "en-IN",
                        "model": "mayura:v1",
                        "mode": "formal",
                    },
                )
                if response.status_code == 200:
                    data = response.json()
                    return data.get("translated_text")
                logger.warning(
                    "Sarvam translation failed: status=%d, body=%s",
                    response.status_code, response.text[:200],
                )
        except Exception as exc:
            logger.warning("Sarvam translation error: %s", exc)

        return None

    @classmethod
    def _calculate_confidence(
        cls,
        text: str,
        language: DetectedLanguage,
        hindi_ratio: float,
        english_ratio: float,
        script: str,
    ) -> float:
        if script in (
            "devanagari", "bengali", "tamil", "telugu",
            "kannada", "malayalam", "gujarati", "gurmukhi",
        ):
            return 0.95

        if language == DetectedLanguage.ENGLISH and english_ratio > 0.8:
            return 0.9

        if language == DetectedLanguage.HINGLISH:
            if hindi_ratio > 0.3:
                return 0.85
            if hindi_ratio > 0.1:
                return 0.7
            return 0.5

        if language == DetectedLanguage.HINDI and script == "latin":
            return 0.7

        return 0.5
