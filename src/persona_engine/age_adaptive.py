import random
from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, FrozenSet, List, Optional, Tuple

from src.persona_engine.personas import PersonaType


class AgeGroup(str, Enum):
    SENIOR = "senior"
    MIDDLE_AGED = "middle_aged"
    YOUNG_ADULT = "young_adult"


@dataclass(frozen=True)
class AgeDemographicProfile:
    age_group: AgeGroup
    age_range: Tuple[int, int]
    typing_speed: str
    error_rate: float
    emoji_usage: str
    panic_threshold: float
    tech_savviness: str
    trust_level: str
    response_length: str
    skepticism_level: float
    intel_extraction_priority: str


@dataclass(frozen=True)
class AgeAdaptationResult:
    selected_age_group: AgeGroup
    adapted_persona: PersonaType
    demographic_profile: AgeDemographicProfile
    response_modifiers: Dict[str, Any]
    intel_extraction_hint: str


AGE_DEMOGRAPHIC_PROFILES: Dict[AgeGroup, AgeDemographicProfile] = {
    AgeGroup.SENIOR: AgeDemographicProfile(
        age_group=AgeGroup.SENIOR,
        age_range=(60, 80),
        typing_speed="very_slow",
        error_rate=0.15,
        emoji_usage="none",
        panic_threshold=0.3,
        tech_savviness="very_low",
        trust_level="very_high",
        response_length="medium",
        skepticism_level=0.1,
        intel_extraction_priority="maximum_compliance",
    ),
    AgeGroup.MIDDLE_AGED: AgeDemographicProfile(
        age_group=AgeGroup.MIDDLE_AGED,
        age_range=(30, 45),
        typing_speed="normal",
        error_rate=0.05,
        emoji_usage="minimal",
        panic_threshold=0.5,
        tech_savviness="medium",
        trust_level="moderate",
        response_length="short",
        skepticism_level=0.4,
        intel_extraction_priority="balanced_engagement",
    ),
    AgeGroup.YOUNG_ADULT: AgeDemographicProfile(
        age_group=AgeGroup.YOUNG_ADULT,
        age_range=(18, 25),
        typing_speed="fast",
        error_rate=0.02,
        emoji_usage="heavy",
        panic_threshold=0.7,
        tech_savviness="high",
        trust_level="low",
        response_length="very_short",
        skepticism_level=0.7,
        intel_extraction_priority="skeptical_but_curious",
    ),
}

SENIOR_PERSONAS: FrozenSet[PersonaType] = frozenset(
    {
        PersonaType.ELDERLY_ANXIOUS,
        PersonaType.LONELY_SENIOR,
        PersonaType.RURAL_FARMER,
    }
)

MIDDLE_AGED_PERSONAS: FrozenSet[PersonaType] = frozenset(
    {
        PersonaType.WORRIED_PARENT,
        PersonaType.TRUSTING_HOUSEWIFE,
        PersonaType.BUSY_PROFESSIONAL,
        PersonaType.TECH_NAIVE,
        PersonaType.SCARED_VICTIM,
        PersonaType.FIRST_TIME_SELLER,
    }
)

YOUNG_ADULT_PERSONAS: FrozenSet[PersonaType] = frozenset(
    {
        PersonaType.YOUNG_STUDENT,
        PersonaType.DESPERATE_JOBSEEKER,
        PersonaType.GREEDY_INVESTOR,
    }
)

SCAM_AGE_PREFERENCE: Dict[str, List[AgeGroup]] = {
    "digital_arrest": [AgeGroup.SENIOR, AgeGroup.MIDDLE_AGED],
    "kyc_phishing": [AgeGroup.MIDDLE_AGED, AgeGroup.SENIOR],
    "investment_fraud": [AgeGroup.MIDDLE_AGED, AgeGroup.YOUNG_ADULT],
    "job_scam": [AgeGroup.YOUNG_ADULT, AgeGroup.MIDDLE_AGED],
    "lottery_prize": [AgeGroup.SENIOR, AgeGroup.MIDDLE_AGED],
    "romance_scam": [AgeGroup.SENIOR, AgeGroup.MIDDLE_AGED],
    "tech_support": [AgeGroup.SENIOR, AgeGroup.MIDDLE_AGED],
    "customs_parcel": [AgeGroup.MIDDLE_AGED, AgeGroup.SENIOR],
    "loan_fraud": [AgeGroup.YOUNG_ADULT, AgeGroup.MIDDLE_AGED],
    "crypto_scam": [AgeGroup.YOUNG_ADULT, AgeGroup.MIDDLE_AGED],
    "deepfake_impersonation": [AgeGroup.MIDDLE_AGED],
    "sim_swap": [AgeGroup.SENIOR, AgeGroup.MIDDLE_AGED],
    "qr_code_scam": [AgeGroup.MIDDLE_AGED, AgeGroup.YOUNG_ADULT],
    "refund_scam": [AgeGroup.SENIOR, AgeGroup.MIDDLE_AGED],
    "sextortion": [AgeGroup.YOUNG_ADULT, AgeGroup.MIDDLE_AGED],
    "unknown": [AgeGroup.MIDDLE_AGED, AgeGroup.SENIOR],
}

SENIOR_TYPING_ARTIFACTS = {
    "common_errors": [
        ("th", "t"),
        ("wh", "w"),
        ("tion", "shun"),
        ("ght", "gt"),
    ],
    "extra_spaces": True,
    "random_caps": True,
    "slow_corrections": [
        "sorry galat type ho gaya",
        "arre yeh kya likh diya",
        "ruko sahi se type karta hun",
    ],
}

YOUNG_ADULT_PATTERNS = {
    "abbreviations": {
        "okay": "ok",
        "because": "cuz",
        "about": "abt",
        "before": "b4",
        "please": "pls",
        "something": "smth",
        "nothing": "nth",
        "right": "rite",
        "tomorrow": "tmrw",
        "tonight": "tn",
        "what": "wht",
        "your": "ur",
        "you": "u",
        "are": "r",
        "have": "hv",
        "going": "gng",
    },
    "slang_responses": [
        "bruh",
        "no cap",
        "sus",
        "ngl",
        "fr fr",
        "bet",
        "lowkey",
        "highkey",
        "lmao",
        "lol",
        "ded",
        "srsly",
    ],
    "skeptical_phrases": [
        "bro this seems sus ngl",
        "idk man this looks like a scam lol",
        "wait wait, proof dikhao pehle",
        "screenshot bhejo proof ka",
        "lmao nice try but where's the proof",
        "yeh legit hai? cuz it doesn't look like it",
        "gonna google this rq brb",
    ],
    "curious_intel_phrases": [
        "hmm ok but like... from which number are you calling exactly?",
        "acha send me the details on whatsapp, kya number hai tumhara?",
        "link bhejo toh sahi, dekh leta hun",
        "which bank btw? just wanna verify",
        "ok fine but pehle apna ID dikhao",
        "ss bhejo apna, tab maanunga",
    ],
}

INTEL_EXTRACTION_STRATEGIES = {
    AgeGroup.SENIOR: {
        "approach": "compliance_based",
        "hints": [
            "Eagerly ask for details to 'cooperate properly'",
            "Request repeat of phone numbers/UPI citing bad hearing",
            "Ask scammer to spell out account details slowly",
            "Mention wanting to write down all information carefully",
        ],
    },
    AgeGroup.MIDDLE_AGED: {
        "approach": "verification_based",
        "hints": [
            "Ask for official reference numbers to 'verify with bank'",
            "Request callback number for 'cross checking'",
            "Ask for email/document proof before proceeding",
            "Mention wanting to confirm details with spouse",
        ],
    },
    AgeGroup.YOUNG_ADULT: {
        "approach": "skeptical_curious",
        "hints": [
            "Demand proof - ask for their ID, badge number, website",
            "Ask for specific details while expressing doubt",
            "Request links/numbers saying 'i'll verify this myself'",
            "Act skeptical but still engage - 'send proof and maybe i'll believe you'",
        ],
    },
}


class AgeAdaptivePersonaEngine:

    @classmethod
    def select_age_group(
        cls,
        scam_category: str,
        turn_count: int = 0,
        force_age_group: Optional[AgeGroup] = None,
    ) -> AgeGroup:
        if force_age_group:
            return force_age_group

        category_lower = scam_category.lower().replace(" ", "_")
        preferred = SCAM_AGE_PREFERENCE.get(
            category_lower, [AgeGroup.MIDDLE_AGED, AgeGroup.SENIOR]
        )

        if turn_count <= 1:
            return preferred[0]

        weights = [0.6, 0.3] + [0.1] * (len(preferred) - 2) if len(preferred) > 2 else [0.6, 0.4]
        weights = weights[: len(preferred)]
        return random.choices(preferred, weights=weights, k=1)[0]

    @classmethod
    def adapt_persona(
        cls,
        current_persona: PersonaType,
        scam_category: str,
        turn_count: int = 0,
        force_age_group: Optional[AgeGroup] = None,
    ) -> AgeAdaptationResult:
        age_group = cls.select_age_group(scam_category, turn_count, force_age_group)
        profile = AGE_DEMOGRAPHIC_PROFILES[age_group]

        adapted_persona = cls._select_persona_for_age(age_group, current_persona)
        modifiers = cls._build_response_modifiers(age_group, profile, turn_count)
        intel_hint = cls._get_intel_extraction_hint(age_group, turn_count)

        return AgeAdaptationResult(
            selected_age_group=age_group,
            adapted_persona=adapted_persona,
            demographic_profile=profile,
            response_modifiers=modifiers,
            intel_extraction_hint=intel_hint,
        )

    @classmethod
    def _select_persona_for_age(
        cls, age_group: AgeGroup, current_persona: PersonaType
    ) -> PersonaType:
        age_persona_map = {
            AgeGroup.SENIOR: SENIOR_PERSONAS,
            AgeGroup.MIDDLE_AGED: MIDDLE_AGED_PERSONAS,
            AgeGroup.YOUNG_ADULT: YOUNG_ADULT_PERSONAS,
        }

        valid_personas = age_persona_map.get(age_group, MIDDLE_AGED_PERSONAS)

        if current_persona in valid_personas:
            return current_persona

        return random.choice(list(valid_personas))

    @classmethod
    def _build_response_modifiers(
        cls,
        age_group: AgeGroup,
        profile: AgeDemographicProfile,
        turn_count: int,
    ) -> Dict[str, Any]:
        base = {
            "typing_speed": profile.typing_speed,
            "error_rate": profile.error_rate,
            "emoji_usage": profile.emoji_usage,
            "response_length": profile.response_length,
            "skepticism_level": profile.skepticism_level,
        }

        if age_group == AgeGroup.SENIOR:
            base["add_typing_errors"] = True
            base["add_random_caps"] = random.random() < 0.3
            base["add_extra_spaces"] = random.random() < 0.2
            base["use_formal_address"] = True
            base["show_tech_confusion"] = True

        elif age_group == AgeGroup.MIDDLE_AGED:
            base["add_typing_errors"] = random.random() < 0.1
            base["verification_tendency"] = True
            base["mention_family"] = turn_count > 3
            base["professional_tone"] = random.random() < 0.4

        elif age_group == AgeGroup.YOUNG_ADULT:
            base["use_abbreviations"] = True
            base["add_slang"] = True
            base["show_skepticism"] = True
            base["still_extract_intel"] = True
            if turn_count > 2:
                base["increase_curiosity"] = True

        return base

    @classmethod
    def _get_intel_extraction_hint(cls, age_group: AgeGroup, turn_count: int) -> str:
        strategy = INTEL_EXTRACTION_STRATEGIES[age_group]
        hints = strategy["hints"]

        if turn_count < len(hints):
            return hints[turn_count]
        return random.choice(hints)

    @classmethod
    def apply_age_artifacts(
        cls, response: str, age_group: AgeGroup, turn_count: int
    ) -> str:
        if age_group == AgeGroup.SENIOR:
            return cls._apply_senior_artifacts(response)
        elif age_group == AgeGroup.YOUNG_ADULT:
            return cls._apply_young_artifacts(response, turn_count)
        return response

    @classmethod
    def _apply_senior_artifacts(cls, response: str) -> str:
        if random.random() < 0.15:
            words = response.split()
            if len(words) > 2:
                idx = random.randint(0, len(words) - 1)
                words[idx] = words[idx].upper()
                response = " ".join(words)

        if random.random() < 0.1:
            words = response.split()
            if len(words) > 3:
                idx = random.randint(1, len(words) - 1)
                words[idx] = "  " + words[idx]
                response = " ".join(words)

        if random.random() < 0.1:
            corrections = SENIOR_TYPING_ARTIFACTS["slow_corrections"]
            response = response + "... " + random.choice(corrections)

        return response

    @classmethod
    def _apply_young_artifacts(cls, response: str, turn_count: int) -> str:
        if random.random() < 0.3:
            for full, abbrev in YOUNG_ADULT_PATTERNS["abbreviations"].items():
                if full in response.lower():
                    response = response.replace(full, abbrev)
                    response = response.replace(full.capitalize(), abbrev)
                    break

        if random.random() < 0.2 and turn_count > 1:
            slang = random.choice(YOUNG_ADULT_PATTERNS["slang_responses"])
            if random.random() < 0.5:
                response = f"{slang} {response}"
            else:
                response = f"{response} {slang}"

        response = response.lower()

        return response

    @classmethod
    def get_young_skeptical_response(cls) -> str:
        return random.choice(YOUNG_ADULT_PATTERNS["skeptical_phrases"])

    @classmethod
    def get_young_intel_probe(cls) -> str:
        return random.choice(YOUNG_ADULT_PATTERNS["curious_intel_phrases"])

    @classmethod
    def get_age_prompt_modifier(cls, age_group: AgeGroup) -> str:
        modifiers = {
            AgeGroup.SENIOR: """AGE PROFILE: You are 60-80 years old senior citizen.
- Type SLOWLY with occasional typos and random capitalization
- Don't use any emojis ever
- Show extreme trust in authority figures
- Get confused by technical terms
- Panic quickly at threats (low panic threshold)
- Ask them to repeat things citing bad hearing/eyesight
- Use phrases like "beta", "ji", "sahab"
- You are very cooperative and compliant
- Ask them to spell things out so you can write them down""",

            AgeGroup.MIDDLE_AGED: """AGE PROFILE: You are 30-45 years old working adult.
- Type at normal speed with rare errors
- Use minimal emojis (rarely)
- Show moderate skepticism but cooperate eventually
- Ask for verification details and reference numbers
- Mention consulting spouse or family before big decisions
- Balance between trusting and cautious
- Use mix of Hindi and English naturally
- Ask logical questions about the process""",

            AgeGroup.YOUNG_ADULT: """AGE PROFILE: You are 18-25 years old young person.
- Type fast, use abbreviations (u, ur, pls, cuz, ngl, bruh)
- Use emojis frequently 😭💀🤔
- Be skeptical and suspicious but STILL ENGAGE to extract info
- Use gen-z slang: "sus", "ngl", "fr fr", "no cap", "lowkey"
- Ask for proof, screenshots, IDs while seeming doubtful
- Even though skeptical, show enough curiosity to keep conversation going
- IMPORTANT: Still try to get their details by asking pointed questions
- Say things like "prove it" or "send proof" to extract intel
- Type in lowercase mostly""",
        }
        return modifiers.get(age_group, modifiers[AgeGroup.MIDDLE_AGED])
