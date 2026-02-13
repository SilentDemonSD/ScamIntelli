import math
import re
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, FrozenSet, List, Optional

import joblib

from src.scam_detector.keywords import (
    THREAT_KEYWORDS,
    URGENCY_KEYWORDS,
    get_all_scam_keywords,
    get_keyword_categories,
)
from src.utils.logging import get_logger

logger = get_logger(__name__)

try:
    import numpy as np

    HAS_NUMPY = True
except ImportError:
    HAS_NUMPY = False
    np = None

try:
    from sklearn.feature_extraction.text import TfidfVectorizer

    HAS_SKLEARN = True
except ImportError:
    HAS_SKLEARN = False
    TfidfVectorizer = None

HINDI_STOPWORDS: FrozenSet[str] = frozenset(
    {
        "hai", "hain", "ka", "ki", "ke", "ko", "se", "mein", "par", "pe",
        "aur", "ya", "toh", "bhi", "jo", "jab", "tab", "yeh", "woh", "is",
        "us", "ek", "do", "haan", "nahi", "na", "mat", "kuch", "sab",
        "koi", "kahin", "kab", "ab", "jaise", "waisa", "bahut", "bohot",
        "thoda", "zyada", "kam", "ye", "wo", "unka", "unki", "inke",
    }
)

ENGLISH_STOPWORDS: FrozenSet[str] = frozenset(
    {
        "the", "a", "an", "is", "are", "was", "were", "be", "been", "being",
        "have", "has", "had", "do", "does", "did", "will", "would", "shall",
        "should", "may", "might", "can", "could", "must", "am", "i", "me",
        "my", "we", "our", "you", "your", "he", "she", "it", "they", "them",
        "this", "that", "these", "those", "in", "on", "at", "to", "for",
        "of", "with", "by", "from", "as", "into", "about", "but", "or",
        "and", "not", "no", "if", "so", "than", "too", "very", "just",
    }
)

ALL_STOPWORDS = HINDI_STOPWORDS | ENGLISH_STOPWORDS

_HINDI_CONTENT_WORDS: FrozenSet[str] = frozenset({
    "hai", "hain", "kya", "kaise", "karo", "karna", "aap", "aapka",
    "mein", "mera", "meri", "mere", "haan", "nahi", "ji", "abhi",
    "jaldi", "bhejo", "batao", "ruko", "paisa", "paise", "rupay",
    "lakh", "crore", "turant", "aakhri", "mauka", "warna",
})
_URL_RE = re.compile(r"https?://\S+|www\.\S+", re.IGNORECASE)
_EMAIL_RE = re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}")
_PHONE_RE = re.compile(r"(?:\+91[\s\-]?)?[6-9]\d{9}")
_UPI_RE = re.compile(r"[a-zA-Z0-9._\-]+@[a-zA-Z]{2,}(?!\.[a-zA-Z])")
_CURRENCY_RE = re.compile(r"[₹$€£]\s?\d[\d,]*\.?\d*|\d[\d,]*\.?\d*\s?(?:rs|rupees|inr|usd|dollar)", re.IGNORECASE)
_REPEATS_RE = re.compile(r"(.)\1{2,}")
_WHITESPACE_RE = re.compile(r"\s+")
_NUMBERS_RE = re.compile(r"\d+")


@dataclass
class TextFeatures:
    message_length: int = 0
    word_count: int = 0
    avg_word_length: float = 0.0
    uppercase_ratio: float = 0.0
    exclamation_count: int = 0
    question_mark_count: int = 0
    special_char_ratio: float = 0.0
    urgency_keywords: int = 0
    fake_fee_mentions: int = 0
    emotional_manipulation: int = 0
    isolation_attempts: int = 0
    authority_claims: int = 0
    threat_indicators: int = 0
    total_scam_indicators: int = 0
    contains_verification: bool = False
    contains_refusal: bool = False
    contains_expertise: bool = False
    response_strength: float = 0.0
    flesch_reading_ease: float = 0.0
    gunning_fog_index: float = 0.0
    entropy: float = 0.0
    repeated_char_ratio: float = 0.0
    url_count: int = 0
    phone_count: int = 0
    email_count: int = 0
    upi_count: int = 0
    currency_mention_count: int = 0
    number_count: int = 0
    hindi_word_ratio: float = 0.0
    category_keyword_scores: Dict[str, int] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        d = {
            "message_length": self.message_length,
            "word_count": self.word_count,
            "avg_word_length": self.avg_word_length,
            "uppercase_ratio": self.uppercase_ratio,
            "exclamation_count": self.exclamation_count,
            "question_mark_count": self.question_mark_count,
            "special_char_ratio": self.special_char_ratio,
            "urgency_keywords": self.urgency_keywords,
            "fake_fee_mentions": self.fake_fee_mentions,
            "emotional_manipulation": self.emotional_manipulation,
            "isolation_attempts": self.isolation_attempts,
            "authority_claims": self.authority_claims,
            "threat_indicators": self.threat_indicators,
            "total_scam_indicators": self.total_scam_indicators,
            "contains_verification": int(self.contains_verification),
            "contains_refusal": int(self.contains_refusal),
            "contains_expertise": int(self.contains_expertise),
            "response_strength": self.response_strength,
            "flesch_reading_ease": self.flesch_reading_ease,
            "gunning_fog_index": self.gunning_fog_index,
            "entropy": self.entropy,
            "repeated_char_ratio": self.repeated_char_ratio,
            "url_count": self.url_count,
            "phone_count": self.phone_count,
            "email_count": self.email_count,
            "upi_count": self.upi_count,
            "currency_mention_count": self.currency_mention_count,
            "number_count": self.number_count,
            "hindi_word_ratio": self.hindi_word_ratio,
        }
        for cat, score in self.category_keyword_scores.items():
            d[f"cat_{cat}"] = score
        return d

    def to_vector(self, feature_order: Optional[List[str]] = None) -> List[float]:
        d = self.to_dict()
        if feature_order:
            return [float(d.get(k, 0)) for k in feature_order]
        return [float(v) for v in d.values()]


_EMOTIONAL_KEYWORDS = frozenset({
    "please", "help", "urgent", "scared", "worried", "afraid", "crying",
    "begging", "desperate", "panic", "anxiety", "stress", "tension",
    "god", "promise", "swear", "trust", "believe", "love", "care",
    "darling", "dear", "sweetheart", "baby", "jaan", "pyaar",
})

_ISOLATION_KEYWORDS = frozenset({
    "don't tell", "secret", "confidential", "between us", "nobody",
    "alone", "private", "kisi ko mat", "kisiko mat batana",
    "akele", "sirf tum", "only you",
})

_AUTHORITY_KEYWORDS = frozenset({
    "police", "cbi", "enforcement", "court", "judge", "officer",
    "inspector", "commissioner", "ips", "ias", "government", "ministry",
    "rbi", "sebi", "income tax", "customs", "narcotics", "ncb",
    "cyber cell", "it department", "trai", "telecom",
})

_FEE_KEYWORDS = frozenset({
    "fee", "charges", "payment", "deposit", "advance", "processing",
    "registration", "gst", "tax", "duty", "fine", "penalty",
    "subscription", "renewal", "activation",
})

_VERIFICATION_KEYWORDS = frozenset({
    "verify", "confirm", "check", "validate", "authenticate",
    "proof", "evidence", "document", "certificate", "id proof",
})

_REFUSAL_KEYWORDS = frozenset({
    "no", "refuse", "reject", "decline", "deny", "stop", "cancel",
    "don't want", "not interested", "nahi chahiye", "band karo",
    "mat karo", "nahi karunga",
})

_EXPERTISE_KEYWORDS = frozenset({
    "report", "complaint", "cyber crime", "block", "authority",
    "bank manager", "police station", "consumer forum", "lawyer",
})


class TextPreprocessor:

    VECTORIZER_PATH = Path("models/tfidf_vectorizer.joblib")

    def __init__(self):
        self._tfidf: Optional[Any] = None
        self._keyword_categories = get_keyword_categories()
        self._all_keywords = get_all_scam_keywords()
        self._load_vectorizer()

    @staticmethod
    def clean(text: str) -> str:
        if not text:
            return ""
        text = _URL_RE.sub(" __URL__ ", text)
        text = _EMAIL_RE.sub(" __EMAIL__ ", text)
        text = _PHONE_RE.sub(" __PHONE__ ", text)
        text = _UPI_RE.sub(" __UPI__ ", text)
        text = _CURRENCY_RE.sub(" __CURRENCY__ ", text)
        text = _REPEATS_RE.sub(r"\1\1", text)
        text = _WHITESPACE_RE.sub(" ", text).strip()
        return text

    @staticmethod
    def tokenize(text: str, remove_stopwords: bool = True) -> List[str]:
        text = text.lower()
        tokens = re.findall(r"[a-z\u0900-\u097f]+(?:'[a-z]+)?|\b__\w+__\b", text)
        if remove_stopwords:
            tokens = [t for t in tokens if t not in ALL_STOPWORDS and len(t) > 1]
        return tokens

    def extract_features(self, text: str) -> TextFeatures:
        features = TextFeatures()
        if not text:
            return features

        text_lower = text.lower()
        words = text_lower.split()
        n_chars = max(len(text), 1)
        n_words = max(len(words), 1)

        features.message_length = len(text)
        features.word_count = len(words)
        features.avg_word_length = sum(len(w) for w in words) / n_words
        features.uppercase_ratio = sum(1 for c in text if c.isupper()) / n_chars
        features.exclamation_count = text.count("!")
        features.question_mark_count = text.count("?")
        features.special_char_ratio = (
            sum(1 for c in text if not c.isalnum() and not c.isspace()) / n_chars
        )

        features.url_count = len(_URL_RE.findall(text))
        features.phone_count = len(_PHONE_RE.findall(text))
        features.email_count = len(_EMAIL_RE.findall(text))
        features.upi_count = len(_UPI_RE.findall(text))
        features.currency_mention_count = len(_CURRENCY_RE.findall(text))
        features.number_count = len(_NUMBERS_RE.findall(text))

        features.hindi_word_ratio = sum(1 for w in words if w in _HINDI_CONTENT_WORDS) / n_words

        features.urgency_keywords = sum(1 for kw in URGENCY_KEYWORDS if kw in text_lower)
        features.fake_fee_mentions = sum(1 for kw in _FEE_KEYWORDS if kw in text_lower)
        features.emotional_manipulation = sum(1 for kw in _EMOTIONAL_KEYWORDS if kw in text_lower)
        features.isolation_attempts = sum(1 for kw in _ISOLATION_KEYWORDS if kw in text_lower)
        features.authority_claims = sum(1 for kw in _AUTHORITY_KEYWORDS if kw in text_lower)
        features.threat_indicators = sum(1 for kw in THREAT_KEYWORDS if kw in text_lower)
        features.total_scam_indicators = (
            features.urgency_keywords
            + features.fake_fee_mentions
            + features.emotional_manipulation
            + features.isolation_attempts
            + features.authority_claims
            + features.threat_indicators
        )

        features.contains_verification = any(kw in text_lower for kw in _VERIFICATION_KEYWORDS)
        features.contains_refusal = any(kw in text_lower for kw in _REFUSAL_KEYWORDS)
        features.contains_expertise = any(kw in text_lower for kw in _EXPERTISE_KEYWORDS)
        quality_score = 0.0
        if features.contains_verification:
            quality_score += 0.3
        if features.contains_refusal:
            quality_score += 0.4
        if features.contains_expertise:
            quality_score += 0.3
        features.response_strength = quality_score

        features.flesch_reading_ease = self._flesch_reading_ease(text, words)
        features.gunning_fog_index = self._gunning_fog(text, words)
        features.entropy = self._text_entropy(text)
        features.repeated_char_ratio = self._repeated_char_ratio(text)

        for cat_name, cat_keywords in self._keyword_categories.items():
            features.category_keyword_scores[cat_name] = sum(
                1 for kw in cat_keywords if kw in text_lower
            )

        return features

    # ── TF-IDF vectorization ─────────────────────────────────────────────

    def fit_tfidf(self, texts: List[str], max_features: int = 500) -> None:
        if not HAS_SKLEARN:
            logger.warning("scikit-learn not installed, cannot fit TF-IDF")
            return

        cleaned = [self.clean(t) for t in texts]
        self._tfidf = TfidfVectorizer(
            max_features=max_features,
            ngram_range=(1, 2),
            stop_words=None,  # We handle stopwords in clean/tokenize
            sublinear_tf=True,
            min_df=2,
            max_df=0.95,
        )
        self._tfidf.fit(cleaned)
        self._save_vectorizer()
        logger.info("TF-IDF vectorizer fitted on %d documents, %d features", len(texts), max_features)

    def tfidf_transform(self, texts: List[str]) -> Optional[Any]:
        if self._tfidf is None:
            logger.warning("TF-IDF vectorizer not fitted/loaded")
            return None
        cleaned = [self.clean(t) for t in texts]
        return self._tfidf.transform(cleaned)

    def get_combined_features(self, texts: List[str]) -> Optional[Any]:
        if not HAS_NUMPY:
            return None

        # Hand-crafted features
        hand_features = []
        for text in texts:
            tf = self.extract_features(text)
            hand_features.append(tf.to_vector())
        hand_arr = np.array(hand_features, dtype=np.float64)

        # TF-IDF features
        tfidf_matrix = self.tfidf_transform(texts)
        if tfidf_matrix is not None:
            tfidf_arr = tfidf_matrix.toarray() if hasattr(tfidf_matrix, "toarray") else np.array(tfidf_matrix)
            return np.hstack([hand_arr, tfidf_arr])
        return hand_arr

    def _load_vectorizer(self):
        if self.VECTORIZER_PATH.exists():
            try:
                self._tfidf = joblib.load(self.VECTORIZER_PATH)
                logger.info("Loaded TF-IDF vectorizer from %s", self.VECTORIZER_PATH)
            except Exception as e:
                logger.warning("Failed to load TF-IDF vectorizer: %s", e)

    def _save_vectorizer(self):
        if self._tfidf is not None:
            try:
                self.VECTORIZER_PATH.parent.mkdir(parents=True, exist_ok=True)
                joblib.dump(self._tfidf, self.VECTORIZER_PATH)
                logger.info("Saved TF-IDF vectorizer to %s", self.VECTORIZER_PATH)
            except Exception as e:
                logger.warning("Failed to save TF-IDF vectorizer: %s", e)

    @staticmethod
    def _syllable_count(word: str) -> int:
        word = word.lower().strip()
        if len(word) <= 3:
            return 1
        count = 0
        vowels = "aeiouy"
        prev_vowel = False
        for char in word:
            is_vowel = char in vowels
            if is_vowel and not prev_vowel:
                count += 1
            prev_vowel = is_vowel
        if word.endswith("e"):
            count -= 1
        return max(count, 1)

    @classmethod
    def _flesch_reading_ease(cls, text: str, words: List[str]) -> float:
        sentences = max(len(re.split(r"[.!?]+", text)), 1)
        n_words = max(len(words), 1)
        syllables = sum(cls._syllable_count(w) for w in words)
        try:
            return 206.835 - 1.015 * (n_words / sentences) - 84.6 * (syllables / n_words)
        except ZeroDivisionError:
            return 0.0

    @classmethod
    def _gunning_fog(cls, text: str, words: List[str]) -> float:
        sentences = max(len(re.split(r"[.!?]+", text)), 1)
        n_words = max(len(words), 1)
        complex_words = sum(1 for w in words if cls._syllable_count(w) >= 3)
        try:
            return 0.4 * ((n_words / sentences) + 100.0 * (complex_words / n_words))
        except ZeroDivisionError:
            return 0.0

    @staticmethod
    def _text_entropy(text: str) -> float:
        if not text:
            return 0.0
        freq = Counter(text.lower())
        total = len(text)
        return -sum(
            (count / total) * math.log2(count / total)
            for count in freq.values()
            if count > 0
        )

    @staticmethod
    def _repeated_char_ratio(text: str) -> float:
        if len(text) < 2:
            return 0.0
        repeats = sum(1 for i in range(1, len(text)) if text[i] == text[i - 1])
        return repeats / len(text)


_preprocessor: Optional[TextPreprocessor] = None


def get_preprocessor() -> TextPreprocessor:
    global _preprocessor
    if _preprocessor is None:
        _preprocessor = TextPreprocessor()
    return _preprocessor
