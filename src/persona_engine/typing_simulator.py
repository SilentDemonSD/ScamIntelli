import random
from dataclasses import dataclass
from typing import Dict, Optional, Tuple

from src.persona_engine.age_adaptive import AgeGroup


@dataclass(frozen=True)
class TypingSimulation:
    delay_seconds: float
    typing_indicator_duration: float
    include_typo: bool
    message_with_typo: str
    correction: Optional[str]


AGE_WPM: Dict[AgeGroup, int] = {
    AgeGroup.YOUNG_ADULT: 55,
    AgeGroup.MIDDLE_AGED: 40,
    AgeGroup.SENIOR: 15,
}

ADJACENT_KEYS: Dict[str, str] = {
    "a": "sq", "b": "vn", "c": "xv", "d": "sf", "e": "wr",
    "f": "dg", "g": "fh", "h": "gj", "i": "uo", "j": "hk",
    "k": "jl", "l": "ko", "m": "n", "n": "bm", "o": "ip",
    "p": "ol", "q": "wa", "r": "et", "s": "ad", "t": "ry",
    "u": "yi", "v": "cb", "w": "qe", "x": "zc", "y": "tu", "z": "x",
}

COMMON_TYPOS: Dict[str, str] = {
    "the": "teh",
    "and": "adn",
    "you": "yuo",
    "for": "fro",
    "that": "taht",
    "have": "hvae",
    "with": "wiht",
    "this": "tihs",
    "from": "form",
    "what": "waht",
    "nahi": "nhai",
    "karo": "krao",
    "jaldi": "jalid",
    "paisa": "piasa",
    "batao": "btaao",
    "bhejo": "bhjeo",
    "ruko": "rkuo",
    "theek": "tehek",
    "samajh": "smajh",
    "dekho": "dehko",
}

SENIOR_DOUBLE_SPACES_RATE = 0.15
SENIOR_RANDOM_CAPS_RATE = 0.12
SENIOR_PUNCTUATION_ERRORS = ("...", "..", ",,", "!!", "??")

YOUNG_TYPO_RATE = 0.08
MIDDLE_TYPO_RATE = 0.05
SENIOR_TYPO_RATE = 0.18

CORRECTION_FORMATS = (
    "*{correct}",
    "sorry *{correct}",
    "*{correct} sorry",
    "{correct}*",
)

SENIOR_CORRECTIONS = (
    "sorry galat ho gaya",
    "arre phir se galti",
    "yeh phone bhi na",
)


class HumanTypingSimulator:

    @classmethod
    def calculate_typing_delay(
        cls, message: str, age_group: AgeGroup, turn_count: int = 0
    ) -> TypingSimulation:
        wpm = AGE_WPM.get(age_group, 40)
        word_count = max(len(message.split()), 1)

        base_delay = (word_count / wpm) * 60

        thinking_pause = cls._thinking_pause(age_group, turn_count)
        error_delay = cls._error_correction_delay(age_group)

        total_delay = base_delay + thinking_pause + error_delay

        include_typo, typo_msg, correction = cls._generate_typo(message, age_group)

        return TypingSimulation(
            delay_seconds=round(total_delay, 2),
            typing_indicator_duration=round(base_delay, 2),
            include_typo=include_typo,
            message_with_typo=typo_msg if include_typo else message,
            correction=correction,
        )

    @classmethod
    def apply_typing_artifacts(cls, message: str, age_group: AgeGroup) -> str:
        if age_group == AgeGroup.SENIOR:
            return cls._apply_senior_typing(message)
        elif age_group == AgeGroup.YOUNG_ADULT:
            return cls._apply_young_typing(message)
        return cls._apply_middle_typing(message)

    @classmethod
    def _thinking_pause(cls, age_group: AgeGroup, turn_count: int) -> float:
        base = {
            AgeGroup.YOUNG_ADULT: random.uniform(0.5, 2.0),
            AgeGroup.MIDDLE_AGED: random.uniform(1.5, 4.0),
            AgeGroup.SENIOR: random.uniform(3.0, 8.0),
        }.get(age_group, random.uniform(1.0, 3.0))

        if turn_count <= 1:
            base += random.uniform(1.0, 3.0)

        return base

    @classmethod
    def _error_correction_delay(cls, age_group: AgeGroup) -> float:
        rate = {
            AgeGroup.YOUNG_ADULT: YOUNG_TYPO_RATE,
            AgeGroup.MIDDLE_AGED: MIDDLE_TYPO_RATE,
            AgeGroup.SENIOR: SENIOR_TYPO_RATE,
        }.get(age_group, MIDDLE_TYPO_RATE)

        if random.random() < rate:
            return random.uniform(0.5, 2.5)
        return 0.0

    @classmethod
    def _generate_typo(
        cls, message: str, age_group: AgeGroup
    ) -> Tuple[bool, str, Optional[str]]:
        rate = {
            AgeGroup.YOUNG_ADULT: 0.08,
            AgeGroup.MIDDLE_AGED: 0.05,
            AgeGroup.SENIOR: 0.20,
        }.get(age_group, 0.05)

        if random.random() > rate:
            return False, message, None

        words = message.split()
        if len(words) < 2:
            return False, message, None

        typo_candidates = [
            (i, w) for i, w in enumerate(words)
            if len(w) > 2 and w.isalpha()
        ]
        if not typo_candidates:
            return False, message, None

        idx, original = random.choice(typo_candidates)
        typo_word = cls._introduce_typo(original)

        if typo_word == original:
            return False, message, None

        words[idx] = typo_word
        typo_message = " ".join(words)

        correction = random.choice(CORRECTION_FORMATS).format(correct=original)
        if age_group == AgeGroup.SENIOR and random.random() < 0.4:
            correction = f"*{original} ... {random.choice(SENIOR_CORRECTIONS)}"

        return True, typo_message, correction

    @classmethod
    def _introduce_typo(cls, word: str) -> str:
        lower = word.lower()
        if lower in COMMON_TYPOS and random.random() < 0.6:
            return COMMON_TYPOS[lower]

        strategy = random.choice(["swap", "adjacent", "double", "skip"])

        if strategy == "swap" and len(word) > 3:
            i = random.randint(1, len(word) - 2)
            chars = list(word)
            chars[i], chars[i + 1] = chars[i + 1], chars[i]
            return "".join(chars)

        elif strategy == "adjacent" and len(word) > 2:
            i = random.randint(0, len(word) - 1)
            c = word[i].lower()
            if c in ADJACENT_KEYS:
                replacement = random.choice(ADJACENT_KEYS[c])
                chars = list(word)
                chars[i] = replacement if word[i].islower() else replacement.upper()
                return "".join(chars)

        elif strategy == "double" and len(word) > 2:
            i = random.randint(1, len(word) - 1)
            return word[:i] + word[i] + word[i:]

        elif strategy == "skip" and len(word) > 3:
            i = random.randint(1, len(word) - 2)
            return word[:i] + word[i + 1:]

        return word

    @classmethod
    def _apply_senior_typing(cls, message: str) -> str:
        if random.random() < SENIOR_DOUBLE_SPACES_RATE:
            words = message.split()
            if len(words) > 2:
                idx = random.randint(1, len(words) - 1)
                words[idx] = "  " + words[idx]
                message = " ".join(words)

        if random.random() < SENIOR_RANDOM_CAPS_RATE:
            words = message.split()
            if words:
                idx = random.randint(0, len(words) - 1)
                words[idx] = words[idx].upper()
                message = " ".join(words)

        return message

    @classmethod
    def _apply_young_typing(cls, message: str) -> str:
        if random.random() < 0.3:
            message = message.lower()
        return message

    @classmethod
    def _apply_middle_typing(cls, message: str) -> str:
        return message

    @classmethod
    def get_delay_metadata(
        cls, message: str, age_group: AgeGroup, turn_count: int = 0
    ) -> Dict[str, float]:
        sim = cls.calculate_typing_delay(message, age_group, turn_count)
        return {
            "delay_seconds": sim.delay_seconds,
            "typing_indicator_duration": sim.typing_indicator_duration,
            "has_typo": sim.include_typo,
        }
