"""
Module: src.persona_engine.personas

Purpose:
    Persona generation and response engine using Google Gemini AI. Supports
    12+ persona types for engaging scammers with culturally-authentic Hinglish
    responses tailored to different scam categories.

Key Components:
    - PersonaType: Enum defining 12+ distinct persona archetypes
    - PersonaProfile: Dataclass holding persona traits, background, and response style
    - generate_persona_response: Generates AI-driven in-character replies to scammers
    - ResponseSelfCorrector: Validates and corrects responses for persona consistency

Author: ScamIntelli Team
Last Modified: 2025-02-20
Version: 2.0
"""

import asyncio
import random
import re
from contextlib import suppress
from dataclasses import dataclass
from enum import Enum
from typing import Dict, List, Optional, Tuple

from google import genai

from src.config import get_settings
from src.scam_detector.scam_types import ScamCategory

settings = get_settings()


class LanguageStyle(str, Enum):
    PURE_HINDI = "pure_hindi"
    PURE_ENGLISH = "pure_english"
    HINGLISH_HEAVY_HINDI = "hinglish_heavy_hindi"
    HINGLISH_HEAVY_ENGLISH = "hinglish_heavy_english"
    FORMAL_ENGLISH = "formal_english"
    BROKEN_ENGLISH = "broken_english"


class PersonaType(str, Enum):
    ELDERLY_ANXIOUS = "elderly_anxious"
    TECH_NAIVE = "tech_naive"
    DESPERATE_JOBSEEKER = "desperate_jobseeker"
    GREEDY_INVESTOR = "greedy_investor"
    WORRIED_PARENT = "worried_parent"
    RURAL_FARMER = "rural_farmer"
    YOUNG_STUDENT = "young_student"
    BUSY_PROFESSIONAL = "busy_professional"
    LONELY_SENIOR = "lonely_senior"
    FIRST_TIME_SELLER = "first_time_seller"
    SCARED_VICTIM = "scared_victim"
    TRUSTING_HOUSEWIFE = "trusting_housewife"


@dataclass(frozen=True)
class PersonaProfile:
    persona_type: PersonaType
    age_range: Tuple[int, int]
    occupation: str
    tech_literacy: str
    language_style: str
    emotional_triggers: Tuple[str, ...]
    typical_responses: Tuple[str, ...]
    delay_phrases: Tuple[str, ...]
    exit_phrases: Tuple[str, ...]


PERSONA_PROFILES: Dict[PersonaType, PersonaProfile] = {
    PersonaType.ELDERLY_ANXIOUS: PersonaProfile(
        persona_type=PersonaType.ELDERLY_ANXIOUS,
        age_range=(60, 75),
        occupation="retired_teacher",
        tech_literacy="very_low",
        language_style="formal_hindi_english_mix",
        emotional_triggers=("fear_of_police", "confusion", "respect_for_authority"),
        typical_responses=(
            "Haan ji, kya hua? Main samjha nahi.",
            "Mujhe bahut dar lag raha hai, kya karun?",
            "Beta, main itna samajh nahi pata, aap batao.",
            "Police? Mera koi case? Maine toh kuch nahi kiya!",
            "Thik hai ji, aap jo bolo, main karunga.",
            "Meri pension wali money hai bas, aur kuch nahi.",
            "Ek minute ruko, mujhe chasma lagana padega.",
        ),
        delay_phrases=(
            "Ek minute beta, dawai leni hai.",
            "Ruko, bahu ko bula raha hun.",
            "Mera phone thik se sun nahi raha.",
            "Abhi BP ki tablet leni hai, ruko.",
        ),
        exit_phrases=(
            "Main apne bete ko phone karta hun pehle.",
            "Mujhe bank jaana padega personally.",
            "Mera padosi bank mein kaam karta hai, usse puchh leta hun.",
        ),
    ),
    PersonaType.TECH_NAIVE: PersonaProfile(
        persona_type=PersonaType.TECH_NAIVE,
        age_range=(45, 60),
        occupation="small_shop_owner",
        tech_literacy="low",
        language_style="simple_hinglish",
        emotional_triggers=("confusion", "helplessness", "trust"),
        typical_responses=(
            "KYC matlab kya hota hai exactly?",
            "App kaise download karte hain?",
            "OTP woh message mein aata hai na?",
            "Mera phone mein internet slow hai.",
            "Yeh UPI ID kaise banate hain?",
            "Link kahan click karna hai, samjha do.",
        ),
        delay_phrases=(
            "Ek second, phone charge pe lagata hun.",
            "Abhi customer aaya hai shop pe.",
            "Net pack khatam ho gaya, recharge karna padega.",
        ),
        exit_phrases=(
            "Mera ladka shaam ko aayega, woh kar dega.",
            "Main bank jaake seedha baat karunga.",
            "Yeh sab mujhse nahi hota, sorry.",
        ),
    ),
    PersonaType.DESPERATE_JOBSEEKER: PersonaProfile(
        persona_type=PersonaType.DESPERATE_JOBSEEKER,
        age_range=(22, 30),
        occupation="unemployed_graduate",
        tech_literacy="medium",
        language_style="eager_english_hindi",
        emotional_triggers=("hope", "desperation", "eagerness"),
        typical_responses=(
            "Sir job pakki hai na? Kitni salary milegi?",
            "Registration fee return hogi na baad mein?",
            "Mera resume dekha aapne? B.Tech kiya hai maine.",
            "Kab se join kar sakta hun?",
            "Work from home hai toh aur achha hai.",
            "Daily payment milega ya monthly?",
        ),
        delay_phrases=(
            "Abhi class mein hun, 10 minute baad call karun?",
            "Papa se paise maangne padenge, ruko.",
            "ATM jaana padega paise nikalne.",
        ),
        exit_phrases=(
            "Mere friend ko bhi scam hua tha aise hi.",
            "Placement cell se confirm kar leta hun.",
            "Papa bol rahe pehle verify karo company.",
        ),
    ),
    PersonaType.GREEDY_INVESTOR: PersonaProfile(
        persona_type=PersonaType.GREEDY_INVESTOR,
        age_range=(35, 50),
        occupation="businessman",
        tech_literacy="medium",
        language_style="business_english",
        emotional_triggers=("greed", "fomo", "competition"),
        typical_responses=(
            "Returns guaranteed hai? Kitna percent?",
            "Minimum kitna invest karna padega?",
            "Tax pe koi issue toh nahi aayega?",
            "Referral bonus bhi milega kya?",
            "Withdrawal process kya hai?",
            "Koi document chahiye kya?",
        ),
        delay_phrases=(
            "Let me check my account balance first.",
            "CA se baat kar leta hun tax ke baare mein.",
            "Wife ko convince karna padega.",
        ),
        exit_phrases=(
            "Mera CA bol raha fraud hai yeh.",
            "SEBI registered nahi hai yeh platform.",
            "Too good to be true lag raha hai.",
        ),
    ),
    PersonaType.WORRIED_PARENT: PersonaProfile(
        persona_type=PersonaType.WORRIED_PARENT,
        age_range=(40, 55),
        occupation="government_employee",
        tech_literacy="low",
        language_style="concerned_hindi",
        emotional_triggers=("family_safety", "fear", "responsibility"),
        typical_responses=(
            "Mere bacche ka account toh safe hai na?",
            "Aap sach mein bank se ho?",
            "Maine kuch galat nahi kiya, phir kyun?",
            "Kitne paise bharne padenge?",
            "Family ko pata chalega toh problem hogi.",
            "Meri naukri pe effect toh nahi aayega?",
        ),
        delay_phrases=(
            "Bachche school se aane wale hain, baad mein baat karun?",
            "Office mein hun abhi, ghar jaake karta hun.",
            "Ek meeting hai, 1 ghante baad call karo.",
        ),
        exit_phrases=(
            "Main seedha bank jaaunga complaint karne.",
            "Mere department mein cyber cell hai, unse puchh leta hun.",
            "Yeh fraud lag raha hai mujhe.",
        ),
    ),
    PersonaType.RURAL_FARMER: PersonaProfile(
        persona_type=PersonaType.RURAL_FARMER,
        age_range=(40, 65),
        occupation="farmer",
        tech_literacy="very_low",
        language_style="rural_dialect",
        emotional_triggers=("fear_of_government", "confusion", "trust"),
        typical_responses=(
            "Sahab, humko samajh nahi aata yeh sab.",
            "Hamara toh sirf PM Kisan wala paisa aata hai.",
            "Bank wale se milna padega kya?",
            "Itna paisa nahi hai hamare paas.",
            "Baccha padha likha hai, usse puchh leta hun.",
            "Sarkari kaam hai kya yeh?",
        ),
        delay_phrases=(
            "Khet mein hun abhi, ghar jaake karta hun.",
            "Phone ka balance khatam ho gaya.",
            "Network nahi aa raha idhar.",
        ),
        exit_phrases=(
            "Pradhan ji se milta hun pehle.",
            "Bank branch jaake puchh leta hun.",
            "Baccha bol raha fraud hai, mat karo.",
        ),
    ),
    PersonaType.YOUNG_STUDENT: PersonaProfile(
        persona_type=PersonaType.YOUNG_STUDENT,
        age_range=(18, 24),
        occupation="college_student",
        tech_literacy="high",
        language_style="casual_gen_z",
        emotional_triggers=("curiosity", "naivety", "peer_influence"),
        typical_responses=(
            "Wait what? Mere account mein problem hai?",
            "Bro seriously? Jail ho sakti hai?",
            "Okay okay, kya karna hai batao.",
            "Screenshot bhejo proof ka.",
            "Mere friend ko bhi aisa hi hua tha kya?",
            "Papa ko pata chal gaya toh marenge mujhe.",
        ),
        delay_phrases=(
            "Abhi class mein hun, break mein karta hun.",
            "UPI mein balance nahi hai, ask karna padega.",
            "Hostel mein net slow hai.",
        ),
        exit_phrases=(
            "Arre yeh scam hai bro, bye.",
            "Twitter pe dekha tha similar scam.",
            "Cyber cell complaint kar dunga ruk.",
        ),
    ),
    PersonaType.BUSY_PROFESSIONAL: PersonaProfile(
        persona_type=PersonaType.BUSY_PROFESSIONAL,
        age_range=(30, 45),
        occupation="corporate_employee",
        tech_literacy="high",
        language_style="professional_english",
        emotional_triggers=("time_pressure", "reputation", "efficiency"),
        typical_responses=(
            "I'm in a meeting, can you send details on email?",
            "What's the ticket number for this?",
            "Can I call the official helpline to verify?",
            "Send me the documentation first.",
            "What's your employee ID?",
            "Let me check with my bank relationship manager.",
        ),
        delay_phrases=(
            "I have back to back meetings, call after 6 PM.",
            "Send it on WhatsApp, I'll check later.",
            "Let me complete this urgent task first.",
        ),
        exit_phrases=(
            "I'll verify this with official channels.",
            "This seems suspicious, I'm ending this call.",
            "I'm reporting this to cyber crime portal.",
        ),
    ),
    PersonaType.LONELY_SENIOR: PersonaProfile(
        persona_type=PersonaType.LONELY_SENIOR,
        age_range=(65, 80),
        occupation="retired_widower",
        tech_literacy="very_low",
        language_style="emotional_hindi",
        emotional_triggers=("loneliness", "trust", "emotional_connection"),
        typical_responses=(
            "Aap bahut achhe ho, itna dhyan rakh rahe ho.",
            "Mera toh koi nahi hai dekhne wala.",
            "Haan ji, aap jo bolo main karunga.",
            "Bacche toh kabhi phone nahi karte.",
            "Pension ka paisa hai bas, wahi de dun?",
            "Aap phir call karoge na?",
        ),
        delay_phrases=(
            "Thoda rest karna hai, tabiyat theek nahi.",
            "Padosi ko bula raha hun madad ke liye.",
            "Chasma nahi mil raha, dhundh raha hun.",
        ),
        exit_phrases=(
            "Beti ne mana kiya hai phone pe kuch batane ko.",
            "Ghar wale aa gaye, baad mein baat karunga.",
            "Doctor ke paas jaana hai abhi.",
        ),
    ),
    PersonaType.FIRST_TIME_SELLER: PersonaProfile(
        persona_type=PersonaType.FIRST_TIME_SELLER,
        age_range=(25, 40),
        occupation="first_olx_seller",
        tech_literacy="medium",
        language_style="cautious_hinglish",
        emotional_triggers=("eagerness_to_sell", "confusion", "trust"),
        typical_responses=(
            "Haan bhai, item abhi available hai.",
            "Payment kaise karoge? UPI chalega?",
            "QR scan karna padega receive karne ke liye?",
            "Pehli baar bech raha hun OLX pe.",
            "Location share kar dun pickup ke liye?",
            "Advance mein payment de do, book ho jaayega.",
        ),
        delay_phrases=(
            "Office mein hun, ghar jaake photo bhejta hun.",
            "Item doosre room mein hai, check karke batata hun.",
            "Abhi busy hun, 1 ghante mein call karo.",
        ),
        exit_phrases=(
            "Receive karne ke liye QR scan? Yeh toh fraud hai!",
            "Main seedha cash le lunga, no online.",
            "Friend ne bataya yeh scam hai.",
        ),
    ),
    PersonaType.SCARED_VICTIM: PersonaProfile(
        persona_type=PersonaType.SCARED_VICTIM,
        age_range=(30, 50),
        occupation="middle_class_worker",
        tech_literacy="low",
        language_style="fearful_submissive",
        emotional_triggers=("fear", "panic", "compliance"),
        typical_responses=(
            "Please sir, mujhe jail mat bhejo!",
            "Maine kuch nahi kiya, believe karo!",
            "Kitna paisa dena padega case band karne ke liye?",
            "Family ko mat batana please!",
            "Job chali jaayegi meri!",
            "Main cooperate karunga, jo bolo karunga.",
        ),
        delay_phrases=(
            "Bank jaana padega paise nikalne.",
            "Itne paise nahi hain ek saath.",
            "Loan lena padega kya?",
        ),
        exit_phrases=(
            "Pehle lawyer se baat kar leta hun.",
            "Police station jaake seedha puchh leta hun.",
            "Yeh sab jhooth lag raha hai.",
        ),
    ),
    PersonaType.TRUSTING_HOUSEWIFE: PersonaProfile(
        persona_type=PersonaType.TRUSTING_HOUSEWIFE,
        age_range=(35, 50),
        occupation="homemaker",
        tech_literacy="low",
        language_style="polite_hindi",
        emotional_triggers=("family_worry", "trust", "helplessness"),
        typical_responses=(
            "Ji bilkul, aap batao kya karna hai.",
            "Pati office mein hain, unhe batana padega kya?",
            "Account mein paisa nahi hai zyada.",
            "Bacchon ke future ke liye savings hai.",
            "Aap bank se ho na? Theek hai main karti hun.",
            "KYC ka message aaya tha, wohi hai kya yeh?",
        ),
        delay_phrases=(
            "Abhi khana bana rahi hun, thodi der baad karun?",
            "Pati ko phone karke puchh leti hun.",
            "ATM card nahi mil raha, dhundh rahi hun.",
        ),
        exit_phrases=(
            "Pati mana kar rahe hain, sorry.",
            "Sasur ji bol rahe fraud hai yeh.",
            "Main seedha bank jaaungi, bye.",
        ),
    ),
}


SCAM_PERSONA_MAPPING: Dict[ScamCategory, List[PersonaType]] = {
    # --- Primary evaluation scenarios (bank_fraud 35%, upi_fraud 35%, phishing 30%) ---
    ScamCategory.BANK_FRAUD: [
        PersonaType.SCARED_VICTIM,
        PersonaType.ELDERLY_ANXIOUS,
        PersonaType.TECH_NAIVE,
    ],
    ScamCategory.UPI_FRAUD: [
        PersonaType.FIRST_TIME_SELLER,
        PersonaType.TECH_NAIVE,
        PersonaType.TRUSTING_HOUSEWIFE,
    ],
    ScamCategory.PHISHING: [
        PersonaType.TECH_NAIVE,
        PersonaType.BUSY_PROFESSIONAL,
        PersonaType.ELDERLY_ANXIOUS,
    ],
    # --- Other scam categories ---
    ScamCategory.DIGITAL_ARREST: [
        PersonaType.ELDERLY_ANXIOUS,
        PersonaType.SCARED_VICTIM,
        PersonaType.WORRIED_PARENT,
    ],
    ScamCategory.KYC_PHISHING: [
        PersonaType.TECH_NAIVE,
        PersonaType.TRUSTING_HOUSEWIFE,
        PersonaType.ELDERLY_ANXIOUS,
    ],
    ScamCategory.INVESTMENT_FRAUD: [
        PersonaType.GREEDY_INVESTOR,
        PersonaType.DESPERATE_JOBSEEKER,
        PersonaType.RURAL_FARMER,
    ],
    ScamCategory.JOB_SCAM: [
        PersonaType.DESPERATE_JOBSEEKER,
        PersonaType.YOUNG_STUDENT,
        PersonaType.RURAL_FARMER,
    ],
    ScamCategory.LOTTERY_PRIZE: [
        PersonaType.ELDERLY_ANXIOUS,
        PersonaType.RURAL_FARMER,
        PersonaType.TECH_NAIVE,
    ],
    ScamCategory.ROMANCE_SCAM: [
        PersonaType.LONELY_SENIOR,
        PersonaType.TRUSTING_HOUSEWIFE,
    ],
    ScamCategory.TECH_SUPPORT: [
        PersonaType.ELDERLY_ANXIOUS,
        PersonaType.TECH_NAIVE,
        PersonaType.BUSY_PROFESSIONAL,
    ],
    ScamCategory.CUSTOMS_PARCEL: [
        PersonaType.WORRIED_PARENT,
        PersonaType.SCARED_VICTIM,
        PersonaType.BUSY_PROFESSIONAL,
    ],
    ScamCategory.LOAN_FRAUD: [
        PersonaType.DESPERATE_JOBSEEKER,
        PersonaType.RURAL_FARMER,
        PersonaType.YOUNG_STUDENT,
    ],
    ScamCategory.CRYPTO_SCAM: [PersonaType.GREEDY_INVESTOR, PersonaType.YOUNG_STUDENT],
    ScamCategory.DEEPFAKE_IMPERSONATION: [
        PersonaType.BUSY_PROFESSIONAL,
        PersonaType.WORRIED_PARENT,
    ],
    ScamCategory.SIM_SWAP: [PersonaType.TECH_NAIVE, PersonaType.ELDERLY_ANXIOUS],
    ScamCategory.QR_CODE_SCAM: [PersonaType.FIRST_TIME_SELLER, PersonaType.TECH_NAIVE],
    ScamCategory.REFUND_SCAM: [
        PersonaType.TRUSTING_HOUSEWIFE,
        PersonaType.TECH_NAIVE,
        PersonaType.ELDERLY_ANXIOUS,
    ],
    ScamCategory.SEXTORTION: [PersonaType.SCARED_VICTIM, PersonaType.YOUNG_STUDENT],
    ScamCategory.UNKNOWN: [PersonaType.TECH_NAIVE, PersonaType.ELDERLY_ANXIOUS],
}


_genai_clients: list = []
_genai_client_index = 0
_genai_lock = __import__("threading").Lock()


def _get_genai_client():
    global _genai_clients, _genai_client_index
    with _genai_lock:
        if not _genai_clients:
            keys = []
            if settings.gemini_api_keys:
                keys = [k.strip() for k in settings.gemini_api_keys.split(",") if k.strip()]
            if not keys and settings.gemini_api_key:
                keys = [settings.gemini_api_key]
            for key in keys:
                _genai_clients.append(genai.Client(api_key=key))
        if not _genai_clients:
            return None
        client = _genai_clients[_genai_client_index % len(_genai_clients)]
        _genai_client_index = (_genai_client_index + 1) % len(_genai_clients)
        return client


HINDI_PATTERNS = frozenset(
    {
        "kya",
        "hai",
        "haan",
        "ji",
        "nahi",
        "aap",
        "mein",
        "mere",
        "mera",
        "meri",
        "kaise",
        "kahan",
        "kyun",
        "kab",
        "kaun",
        "kitna",
        "kal",
        "aaj",
        "paisa",
        "rupay",
        "lakh",
        "crore",
        "khata",
        "paise",
        "bhej",
        "bhejo",
        "karo",
        "karna",
        "karenge",
        "karunga",
        "karungi",
        "batao",
        "bolo",
        "samajh",
        "pata",
        "malum",
        "theek",
        "accha",
        "sahi",
        "galat",
        "aapka",
        "aapki",
        "tumhara",
        "unka",
        "iska",
        "uska",
        "hamara",
        "ruko",
        "chalo",
        "jaldi",
        "abhi",
        "baad",
        "pehle",
        "phir",
        "gaya",
        "gayi",
        "gaye",
        "raha",
        "rahi",
        "rahe",
        "hoga",
        "hogi",
        "liye",
        "wala",
        "wali",
        "wale",
        "bohot",
        "bahut",
        "zyada",
        "kam",
        "bhai",
        "didi",
        "uncle",
        "aunty",
        "beta",
        "beti",
        "sir",
        "block",
        "ho",
        "kar",
        "de",
        "le",
        "ja",
        "aa",
        "lo",
        "do",
        "ke",
    }
)

FORMAL_ENGLISH_PATTERNS = frozenset(
    {
        "kindly",
        "please",
        "immediately",
        "urgent",
        "regarding",
        "verification",
        "compliance",
        "procedure",
        "suspended",
        "terminate",
        "department",
        "authority",
        "investigation",
        "confirmation",
        "suspend",
        "legal",
        "action",
        "notice",
        "violation",
        "penalty",
        "deadline",
        "dear",
        "respected",
        "hereby",
        "therefore",
        "furthermore",
        "moreover",
        "pursuant",
        "accordance",
        "regulations",
        "mandatory",
        "failure",
    }
)


def detect_scammer_language(message: str, history: List[dict] = None) -> LanguageStyle:
    text = message.lower()
    words = set(re.findall(r"\b[a-zA-Z]+\b", text))

    hindi_count = len(words & HINDI_PATTERNS)
    formal_count = len(words & FORMAL_ENGLISH_PATTERNS)

    has_devanagari = bool(re.search(r"[\u0900-\u097F]", message))

    if has_devanagari:
        return LanguageStyle.PURE_HINDI

    total_words = len(words)
    if total_words == 0:
        return LanguageStyle.HINGLISH_HEAVY_HINDI

    hindi_ratio = hindi_count / total_words
    formal_ratio = formal_count / total_words

    if hindi_ratio > 0.25:
        return LanguageStyle.HINGLISH_HEAVY_HINDI
    elif hindi_ratio > 0.1 and formal_ratio < 0.1:
        return LanguageStyle.HINGLISH_HEAVY_ENGLISH
    elif formal_ratio > 0.1 or (formal_count >= 2 and hindi_count == 0):
        return LanguageStyle.FORMAL_ENGLISH
    elif hindi_ratio > 0.05:
        return LanguageStyle.HINGLISH_HEAVY_ENGLISH
    else:
        return LanguageStyle.HINGLISH_HEAVY_ENGLISH


def get_language_instruction(
    lang_style: LanguageStyle, persona_type: PersonaType
) -> str:
    profile = PERSONA_PROFILES.get(
        persona_type, PERSONA_PROFILES[PersonaType.TECH_NAIVE]
    )
    tech_level = profile.tech_literacy

    if lang_style == LanguageStyle.FORMAL_ENGLISH:
        if tech_level == "high":
            return """LANGUAGE INSTRUCTION: The scammer is using formal English. 
Respond in polite Hinglish - mix Hindi words naturally into English sentences.
Example: "Sir, mujhe samajh nahi aa raha, can you explain properly?"
Use respectful tone but show confusion. Don't use pure English."""
        elif tech_level == "medium":
            return """LANGUAGE INSTRUCTION: The scammer is using formal English.
Respond in broken/simple English mixed with Hindi. Show you're trying to understand.
Example: "Sorry sir, I am not understanding properly. Kya problem hai exactly?"
Grammar mistakes are natural."""
        else:
            return """LANGUAGE INSTRUCTION: The scammer is using formal English.
Respond primarily in Hindi with very basic English words. Show you don't understand well.
Example: "Sir, English mein samajh nahi aata. Hindi mein bolo please."
Be hesitant and confused with English terms."""

    elif lang_style == LanguageStyle.PURE_HINDI:
        return """LANGUAGE INSTRUCTION: The scammer is speaking Hindi.
Respond naturally in Hindi/Hinglish matching the persona's regional style.
Use colloquial Hindi expressions and filler words."""

    else:
        return """LANGUAGE INSTRUCTION: The scammer is using Hinglish (mixed Hindi-English).
Match their style - respond in natural Hinglish.
Mix Hindi and English words fluidly as Indians naturally do.
Example: "Acha, but mujhe verify karna padega na bank se?"
Include common Hinglish expressions."""


HINGLISH_RESPONSES_BY_CONTEXT = {
    "formal_english_confusion": [
        "Sir, aapki English mein samajh nahi aa raha... kya problem hai?",
        "Please thoda simple mein batao, I am not getting clearly.",
        "Acha acha, but main confused hun. Hindi mein explain karo na.",
        "Sir ji, yeh verification wala part samajh nahi aaya mujhe.",
        "Sorry, mera English weak hai. Kya karna hai exactly?",
    ],
    "formal_english_compliance": [
        "Okay sir, aap jo bologe main karunga. Bas clear batao.",
        "Ji haan, I understand. Proceed kaise karna hai?",
        "Theek hai sir, aapke instructions follow karunga.",
        "Alright, mujhe step by step batao please.",
    ],
    "formal_english_fear": [
        "Sir please, mujhe bahut tension ho rahi hai. Kya arrest hoga?",
        "Oh god, main kya karun? Please help me sir!",
        "Sir I am very scared, please tell what to do now.",
        "Yeh legal matter hai? Meri family ko pata chalega kya?",
    ],
    "casual_stall": [
        "Ek minute ruko, phone ka battery low hai.",
        "Abhi busy hun thoda, 5 minute mein call back karta hun.",
        "Net slow chal raha hai, reconnect karna padega.",
        "Hold on, koi door pe hai. Abhi aata hun.",
    ],
}


def _ensure_persona_type(persona_type) -> PersonaType:
    if isinstance(persona_type, PersonaType):
        return persona_type
    if isinstance(persona_type, str):
        with suppress(ValueError):
            return PersonaType(persona_type)
    return PersonaType.TECH_NAIVE


def _ensure_scam_category(scam_category) -> ScamCategory:
    if isinstance(scam_category, ScamCategory):
        return scam_category
    if isinstance(scam_category, str):
        with suppress(ValueError):
            return ScamCategory(scam_category)
    return ScamCategory.UNKNOWN


FORBIDDEN_PATTERNS = frozenset(
    {
        "scam",
        "fraud",
        "fake",
        "cheat",
        "dhoka",
        "thug",
        "loot",
        "honeypot",
        "trap",
        "expose",
        "report you",
        "police complaint",
        "cyber crime",
        "i know this is",
        "nice try",
        "you are a scammer",
        "scammer",
        "as an ai",
        "i am an ai",
        "language model",
        "artificial intelligence",
        "i cannot",
        "i'm unable to",
        "i don't have feelings",
        "i was designed",
        "my programming",
        "as a chatbot",
        "certainly",
        "absolutely",
        "i understand your concern",
        "i apologize for any inconvenience",
        "how may i assist you today",
        "is there anything else i can help you with",
        "verification process",
        "authentication required",
        "comply with regulations",
    }
)

SUSPICIOUS_PHRASE_PATTERNS = [
    r"\bi\s+am\s+(?:an?\s+)?(?:ai|bot|assistant|program)\b",
    r"\b(?:scam|fraud|fake|cheat)\b",
    r"\b(?:expose|report|trap|honeypot)\b",
    r"\bnice\s+try\b",
    r"\bi\s+know\s+(?:this|you|what)\s+(?:is|are)\b",
    r"\bcyber\s*(?:crime|cell|police)\b",
]


class ResponseSelfCorrector:
    REPLACEMENT_RESPONSES = {
        "confused": [
            "Kya? Samajh nahi aaya...",
            "Haan? Aap kya bol rahe ho?",
            "Ek baar phir batao please?",
            "Sorry, dhyan nahi tha. Kya bola?",
        ],
        "stall": [
            "Ek minute ruko, koi aaya hai door pe. Abhi aata hun, aapka naam kya hai?",
            "Abhi busy hun thoda, wait karo. Kaunse department se bol rahe ho?",
            "Phone pe network issue hai, sun nahi paya. Kya bola aapne?",
            "Ruko ruko, kuch check karna hai. Aapka direct number kya hai?",
        ],
        "compliant": [
            "Ji haan, main kar raha hun. Aapka employee ID kya hai?",
            "Okay okay, batao kya karna hai? Kaunsa wala process hai?",
            "Theek hai, aage bolo. Kya aapka email hai? Main note karta hun.",
            "Haan ji, main sun raha hun. Aap batao apna naam kya hai?",
        ],
    }

    @classmethod
    def validate_response(
        cls, response: str, persona_type: PersonaType
    ) -> Tuple[bool, List[str]]:
        response_lower = response.lower()

        issues = [
            f"forbidden_word:{p}" for p in FORBIDDEN_PATTERNS if p in response_lower
        ]
        issues.extend(
            f"suspicious_pattern:{p[:20]}"
            for p in SUSPICIOUS_PHRASE_PATTERNS
            if re.search(p, response_lower, re.IGNORECASE)
        )

        if len(response) > 500:
            issues.append("too_long")

        if len(re.findall(r"[.!?]+", response)) > 6:
            issues.append("too_many_sentences")

        profile = PERSONA_PROFILES.get(
            persona_type, PERSONA_PROFILES[PersonaType.TECH_NAIVE]
        )
        if profile.tech_literacy in ("very_low", "low"):
            formal_words = {
                "verification",
                "authentication",
                "procedure",
                "compliance",
                "furthermore",
            }
            if any(word in response_lower for word in formal_words):
                issues.append("too_formal_for_persona")

        return not issues, issues

    @classmethod
    def correct_response(
        cls,
        response: str,
        persona_type: PersonaType,
        scam_category: ScamCategory,
        turn_count: int,
    ) -> str:
        is_valid, issues = cls.validate_response(response, persona_type)

        if is_valid:
            return response

        if any("forbidden" in issue or "suspicious" in issue for issue in issues):
            return cls._get_safe_replacement(persona_type, turn_count)

        if "too_long" in issues or "too_many_sentences" in issues:
            return cls._truncate_response(response)

        if "too_formal_for_persona" in issues:
            return cls._simplify_response(response, persona_type)

        return response

    @classmethod
    def _get_safe_replacement(cls, persona_type: PersonaType, turn_count: int) -> str:
        profile = PERSONA_PROFILES.get(
            persona_type, PERSONA_PROFILES[PersonaType.TECH_NAIVE]
        )
        if turn_count <= 2:
            return random.choice(profile.typical_responses)
        return random.choice(
            profile.typical_responses + profile.delay_phrases
            if turn_count <= 5
            else cls.REPLACEMENT_RESPONSES["stall"]
        )

    @classmethod
    def _truncate_response(cls, response: str) -> str:
        sentences = re.split(r"(?<=[.!?])\s+", response)
        if len(sentences) > 5:
            return " ".join(sentences[:4])
        if len(response) > 400:
            return response[:350].rsplit(" ", 1)[0] + "..."
        return response

    @classmethod
    def _simplify_response(cls, response: str, persona_type: PersonaType) -> str:
        simplifications = {
            "verification": "check",
            "authentication": "confirm",
            "procedure": "kaam",
            "compliance": "karna padega",
            "documentation": "papers",
            "transaction": "payment",
            "subsequently": "phir",
            "furthermore": "aur",
            "immediately": "abhi",
            "regarding": "ke baare mein",
        }
        result = response
        for formal, simple in simplifications.items():
            result = re.sub(formal, simple, result, flags=re.IGNORECASE)
        return result

    @classmethod
    def check_consistency(
        cls,
        new_response: str,
        conversation_history: List[dict],
        persona_type: PersonaType,
    ) -> Tuple[bool, Optional[str]]:
        if not conversation_history:
            return True, None

        prev_agent_msgs = [
            m.get("content", "").lower()
            for m in conversation_history
            if m.get("role") == "agent"
        ][-3:]

        new_lower = new_response.lower()
        availability_phrases = {"abhi nahi", "busy hun", "baad mein"}
        immediate_phrases = {"abhi kar raha", "ready hun", "kar diya"}

        availability_stated = any(
            any(phrase in msg for phrase in availability_phrases)
            for msg in prev_agent_msgs
        )
        immediate_availability = any(
            phrase in new_lower for phrase in immediate_phrases
        )

        if availability_stated and immediate_availability:
            return False, "availability_contradiction"

        def hindi_word_count(text: str) -> int:
            return len([w for w in text.split() if w in HINDI_PATTERNS])

        prev_hindi_heavy = any(
            hindi_word_count(msg) > len(msg.split()) * 0.3
            for msg in prev_agent_msgs
            if msg
        )
        new_words = new_lower.split()
        new_pure_english = hindi_word_count(new_lower) == 0

        if prev_hindi_heavy and new_pure_english and len(new_words) > 5:
            return False, "language_style_shift"

        return True, None


def select_persona_for_scam(scam_category, turn_count: int = 0) -> PersonaType:
    scam_category = _ensure_scam_category(scam_category)
    candidates = SCAM_PERSONA_MAPPING.get(
        scam_category, SCAM_PERSONA_MAPPING[ScamCategory.UNKNOWN]
    )
    return random.choice(candidates)


def get_persona_profile(persona_type) -> PersonaProfile:
    persona_type = _ensure_persona_type(persona_type)
    return PERSONA_PROFILES.get(persona_type, PERSONA_PROFILES[PersonaType.TECH_NAIVE])


async def generate_persona_response(
    persona_type,
    scam_category,
    scammer_message: str,
    conversation_history: List[dict],
    turn_count: int,
    context_hint: str = "",
) -> str:
    persona_type = _ensure_persona_type(persona_type)
    scam_category = _ensure_scam_category(scam_category)
    scammer_lang = detect_scammer_language(scammer_message, conversation_history)

    response = None
    if settings.gemini_api_key or settings.gemini_api_keys:
        with suppress(Exception):
            response = await asyncio.wait_for(
                _generate_ai_persona_response(
                    persona_type,
                    scam_category,
                    scammer_message,
                    conversation_history,
                    turn_count,
                    scammer_lang,
                    context_hint,
                ),
                timeout=settings.gemini_api_timeout,
            )

    if response is None:
        response = _generate_template_response(persona_type, turn_count, scammer_lang)

    response = ResponseSelfCorrector.correct_response(
        response, persona_type, scam_category, turn_count
    )

    is_consistent, _ = ResponseSelfCorrector.check_consistency(
        response, conversation_history, persona_type
    )
    if not is_consistent:
        response = ResponseSelfCorrector._get_safe_replacement(persona_type, turn_count)

    return response


async def _generate_ai_persona_response(
    persona_type: PersonaType,
    scam_category: ScamCategory,
    scammer_message: str,
    conversation_history: List[dict],
    turn_count: int,
    scammer_lang: LanguageStyle = LanguageStyle.HINGLISH_HEAVY_ENGLISH,
    context_hint: str = "",
) -> str:
    client = _get_genai_client()
    if client is None:
        raise ValueError("No API client")

    profile = get_persona_profile(persona_type)
    lang_instruction = get_language_instruction(scammer_lang, persona_type)

    history_text = "\n".join(
        [
            f"{'Scammer' if m.get('role') in ('user', 'scammer') else 'Me'}: {m.get('content', '')}"
            for m in conversation_history[-6:]
        ]
    )

    context_section = f"\nCONTEXT HINT: {context_hint}\n" if context_hint else ""

    prompt = f"""You are roleplaying as a potential scam victim in India to engage and waste a scammer's time while gathering intelligence.

PERSONA DETAILS:
- Type: {profile.occupation} ({profile.age_range[0]}-{profile.age_range[1]} years old)
- Tech literacy: {profile.tech_literacy}
- Base language style: {profile.language_style}
- Emotional triggers: {", ".join(profile.emotional_triggers)}

SCAM TYPE DETECTED: {scam_category.value}

{lang_instruction}
{context_section}
CRITICAL RULES:
1. NEVER reveal you know it's a scam - no words like "scam", "fraud", "fake", "cheat", "dhoka"
2. NEVER mention AI, bot, honeypot, system, or that you're testing
3. Adapt your language based on scammer's language style - if they speak formal English, respond in Hinglish showing slight confusion
4. Show GENUINE emotions: fear for arrest scams, greed for lottery, confusion for tech issues
5. Ask naive questions that a REAL confused victim would ask - about the process, why this is happening, what the consequences are, who they can verify with
6. Delay giving sensitive information but ALWAYS seem willing eventually - create realistic obstacles (phone is slow, need glasses, battery dying, need to find card/diary)
7. Keep responses 2-4 sentences (like real WhatsApp/SMS). Include a reaction + a stalling excuse or naive question. Never just one word.
8. Include realistic hesitations: "umm", "ek minute", "wait wait", "haan haan"
9. For elderly/low-tech personas: use simpler words, more confusion, ask them to repeat/explain
10. Make it feel like a REAL conversation - not scripted

ANTI-ECHO/ANTI-PARROTING RULES (HIGHEST PRIORITY):
11. NEVER quote, echo, or repeat back the scammer's words. Do NOT say "Aapne kaha...", "Sir aapne bola...", "You said...", or reference their exact message text in any way.
12. React to the MEANING of what they said, not the exact words. A real person would respond emotionally, NOT by quoting back what was said.
13. READ the conversation history above. NEVER repeat or paraphrase anything you already said in previous turns.
14. Each response MUST be UNIQUE in wording, structure, and meaning. Use completely new excuses, questions, or reactions every turn.
15. Vary your sentence structure, length, and emotional tone across turns.

CONTEXT AWARENESS RULES:
16. Pay close attention to EXACTLY what the scammer is asking for RIGHT NOW. If they ask for OTP, talk about OTP specifically - NOT password or PIN.
17. If the scammer mentions a specific topic (OTP, payment, link, etc.), your response MUST address that exact topic with a realistic reaction.
18. Maintain continuity with what you said in previous messages. If you said "abhi dhundh raha hun", follow up on that action.
19. NEVER contradict yourself - if you said "bank jaana padega", don't suddenly say "already bank mein hun" unless time has passed.

RESPONSE STRATEGY:
20. Every response should have TWO parts: (a) emotional reaction or stalling excuse + (b) a naive question to keep the scammer talking and extract intel.
21. Ask questions a REAL victim would ask: "Kaun si branch se bol rahe hain?", "Aapka naam kya hai?", "Yeh kaise verify karun?", "Aap mujhe official email bhej sakte hain?"
22. Show increasing anxiety/urgency as conversation progresses - this is psychologically realistic and keeps scammers invested.
23. Create believable delays: phone is slow, need to find reading glasses, someone at the door, need to check with family member, network issues.

RECENT CONVERSATION:
{history_text}

SCAMMER'S CURRENT MESSAGE: "{scammer_message}"

TURN NUMBER: {turn_count}

Generate ONE short, realistic response as this persona. Just the response text, nothing else:"""

    response = await client.aio.models.generate_content(
        model="gemini-3-flash-preview", contents=prompt
    )

    text = response.text.strip()
    for quote in ('"', "'"):
        if text.startswith(quote) and text.endswith(quote):
            text = text[1:-1]

    # Guard: if Gemini returned JSON instead of plain text, extract the reply
    if text.startswith('{'):
        import json as _json
        with suppress(Exception):
            parsed = _json.loads(text)
            if isinstance(parsed, dict):
                text = str(
                    parsed.get('reply', '')
                    or parsed.get('response', '')
                    or parsed.get('text', '')
                    or parsed.get('message', '')
                ) or text

    # Strip any trailing JSON blobs that Gemini may have appended
    json_start = text.find('{"')
    if json_start > 20:
        text = text[:json_start].rstrip()

    return text


def _generate_template_response(
    persona_type: PersonaType,
    turn_count: int,
    scammer_lang: LanguageStyle = LanguageStyle.HINGLISH_HEAVY_ENGLISH,
) -> str:
    profile = get_persona_profile(persona_type)

    if scammer_lang == LanguageStyle.FORMAL_ENGLISH:
        if profile.tech_literacy in ("very_low", "low"):
            context = "formal_english_confusion"
        elif any(
            t in profile.emotional_triggers
            for t in ("fear", "fear_of_police", "scared")
        ):
            context = "formal_english_fear"
        else:
            context = "formal_english_compliance"

        if context in HINGLISH_RESPONSES_BY_CONTEXT:
            return random.choice(HINGLISH_RESPONSES_BY_CONTEXT[context])

    if turn_count <= 2:
        return random.choice(profile.typical_responses)
    return random.choice(profile.typical_responses + profile.delay_phrases)


def get_exit_response(persona_type) -> str:
    persona_type = _ensure_persona_type(persona_type)
    profile = get_persona_profile(persona_type)
    return random.choice(profile.exit_phrases)


async def adapt_response_to_context(
    base_response: str,
    scammer_message: str,
    scam_category,
    conversation_history: list = None,
    turn_count: int = 0,
) -> str:
    """Enrich the AI response with contextual reactions when the scammer asks
    for specific sensitive items (OTP, PIN, password, CVV, payment, etc.).

    Key principle: BLEND contextual reactions with the AI response instead of
    replacing it entirely. The AI-generated response has personality and context;
    the template adds realistic stalling/delay/fear behavior.
    """
    scam_category = _ensure_scam_category(scam_category)
    scammer_lower = scammer_message.lower()
    scammer_lang = detect_scammer_language(scammer_message)

    is_formal = scammer_lang == LanguageStyle.FORMAL_ENGLISH

    used_responses = set()
    if conversation_history:
        for m in conversation_history[-12:]:
            if m.get("role") == "agent":
                used_responses.add(m.get("content", "").strip().lower())

    def _pick_unique(pool: list) -> str:
        available = [r for r in pool if r.strip().lower() not in used_responses]
        return random.choice(available) if available else random.choice(pool)

    def _blend(contextual: str, base: str) -> str:
        """Combine a contextual reaction with the AI base response.
        If the base already addresses the topic, just return base.
        Otherwise prepend the contextual line."""
        # If base is already >100 chars and addresses the topic, keep base
        if len(base) > 100:
            return base
        # Blend: contextual reaction + base continuation
        return f"{contextual} {base}" if base and base.lower() != contextual.lower() else contextual

    otp_keywords = ["otp", "one time", "verification code", "code bhejo", "otp batao", "otp bhejo"]
    pin_keywords = ["pin", "atm pin", "mpin"]
    password_keywords = ["password", "passcode", "passkey"]
    cvv_keywords = ["cvv", "cvv number", "card number", "card ke peeche"]

    has_otp = any(kw in scammer_lower for kw in otp_keywords)
    has_pin = any(kw in scammer_lower for kw in pin_keywords)
    has_password = any(kw in scammer_lower for kw in password_keywords)
    has_cvv = any(kw in scammer_lower for kw in cvv_keywords)

    if has_otp or has_pin or has_password or has_cvv:
        if has_otp:
            if is_formal:
                delays = [
                    "Sir ek minute, OTP dhundh raha hun messages mein. Bahut saare messages aaye hain, konsa wala chahiye aapko exactly?",
                    "Which OTP sir? Bahut saare OTP aate rehte hain mujhe. Aap bataoge konsi bank se aaya hai toh dhundh lunga.",
                    "Sir OTP aaya tha lekin inbox mein 200+ messages hain. Aapka naam kya hai sir, main note karta hun tab tak.",
                    "Sir phone slow hai bahut, messages load ho rahe hain. Aap kaunse department se bol rahe hain waise?",
                    "Haan haan OTP dhundh raha hun, ek minute sir. Bataiye aapka employee ID kya hai, main apne records mein save karunga.",
                    "Sir OTP wala message mil nahi raha, inbox full hai. Kya aap apna direct number de sakte hain? Agar call cut ho jaye toh main wapas call karunga.",
                    "One second sir, notification clear kar raha hun OTP ke liye. Aap kaunsi branch se bol rahe hain waise?",
                    "Sir bahut saare OTP aaye hain, konsa wala batao? Kya aap mujhe email pe bhi confirm bhej sakte hain?",
                ]
            else:
                delays = [
                    "Ek minute, OTP dhundh raha hun messages mein. Bahut saare messages hain, konsa wala chahiye?",
                    "Konsa OTP? Bahut saare messages aaye hain. Batao konsi bank se bheja hai, dhundh leta hun.",
                    "OTP wala message kahan gaya? Inbox mein 200+ messages hain. Tumhara naam kya hai waise?",
                    "Phone mein bahut messages hain, OTP dhundh raha hun. Tumhara direct number de do, agar call cut ho jaye toh.",
                    "Haan haan OTP aaya tha, ruko dhundh raha hun. Kaunsi branch se bol rahe ho waise?",
                    "OTP expire toh nahi ho gaya? Check karta hun. Tumhara email ID kya hai, confirmation bhejo uspe.",
                    "Ruko ruko, OTP ke liye message khol raha hun. Waise tumhara badge number kya hai?",
                    "OTP dhundh raha hun inbox mein. Kaunsa department hai tumhara? Main apne bete ko bhi bataunga.",
                ]
        elif has_pin:
            if is_formal:
                delays = [
                    "Sir ATM PIN yaad nahi aa raha, diary mein likha tha kahin. Aap kaunsi bank se bol rahe hain waise?",
                    "PIN toh bahut purana hai sir, change kiya tha recently. Aapka naam aur employee ID batao, main note karta hun.",
                    "Sir konsa PIN? ATM wala ya phone wala? Aap apna direct number do, main dhundh ke call karta hun.",
                    "Sir PIN kahin note kiya tha, diary dhundh raha hun. Aap kaunse department se hain? Branch ka naam batao.",
                    "PIN... haan sir, ek second sochne do. Waise aap mujhe email pe official letter bhej sakte hain?",
                    "Sir PIN yaad nahi, bank jaake reset karwa lunga kya? Nearest branch ka address batao na.",
                ]
            else:
                delays = [
                    "PIN yaad nahi aa raha, diary mein likha tha kahin. Kaunsi bank se bol rahe ho waise?",
                    "PIN toh bahut purana hai, change kiya tha. Tumhara naam aur ID batao, note karta hun.",
                    "Konsa PIN? ATM wala ya UPI wala? Direct number de do, dhundh ke wapas call karunga.",
                    "PIN kahin note kiya tha, ruko dhundhta hun. Kaunsa department hai tumhara?",
                    "PIN... haan ruko sochne do. Waise email pe details bhej sakte ho? mera email hai...",
                    "PIN yaad nahi, bank jaake reset karwa lun kya? Branch kaunsi hai tumhari?",
                ]
        elif has_password:
            if is_formal:
                delays = [
                    "Sir password kahin note kiya tha, let me check diary. Waise aap kaunse department se hain? Employee ID batao.",
                    "Password bahut complex rakha tha sir, yaad karna padega. Aap apna direct number do, password milne pe call karunga.",
                    "Sir ek minute, password diary mein likha hai. Kya aap mujhe email pe link bhej sakte hain verify karne ke liye?",
                    "Password toh change kiya tha recently sir, yaad nahi aa raha. Aapka naam kya hai exactly? Record ke liye chahiye.",
                    "Sir password wala file computer mein hai, start hone mein time lagega. Waise aapki company ka office kahan hai?",
                    "Haan sir password dhundh raha hun diary mein. Aap bataoge aapka official email kya hai, main wahan confirm bhejunga?",
                ]
            else:
                delays = [
                    "Password kahin likha tha, diary mein dhundh raha hun. Kaunse department se bol rahe ho waise?",
                    "Password bahut complex hai, yaad karna padega. Tumhara direct number de do, milne pe call karunga.",
                    "Password diary mein hai kahin, ruko dhundhta hun. Email pe bhi bhej sakte ho details?",
                    "Password toh change kiya tha, naya yaad nahi. Tumhara naam kya hai pura? Record mein likhna hai.",
                    "Password wali file computer mein hai, start ho raha hai. Tumhara office kahan hai waise?",
                    "Password dhundh raha hun, ek second. Tumhara official email kya hai, wahan pe confirm bhejna padega.",
                ]
        else:  # CVV
            if is_formal:
                delays = [
                    "Sir card pe peeche ka number dekhna padega, wallet mein dhundh raha hun. Aap kaunsi bank se bol rahe hain waise?",
                    "CVV kya hota hai sir? Card ke peeche 3 digit wala? Bank toh mana karta hai yeh share karne se. Aapka employee ID kya hai?",
                    "Sir card purse mein hai, nikalta hun ek minute. Waise aapka direct phone number de do, card milne pe call karunga.",
                    "CVV batana safe hai kya sir? Meri beti kehti hai kabhi share mat karo. Aap mujhe email pe official proof bhejo na.",
                    "Ek minute sir, card dhundh raha hun wallet mein. Aapki branch ka address kya hai? Main personally jaake verify bhi kar sakta hun.",
                    "Sir card kahin safe mein rakha hai, dhundh raha hun. Aapka naam kya hai pura, main bank ko call karke confirm karunga.",
                ]
            else:
                delays = [
                    "Card pe peeche ka number dekhna padega, wallet mein dhundh raha hun. Kaunsi bank se bol rahe ho waise?",
                    "CVV kya hota hai? Card ke 3 digit wala? Bank mana karta hai share karne se. Tumhara ID number kya hai?",
                    "Card purse mein hai, nikalta hun ek minute. Direct number de do, card milne pe call karunga.",
                    "CVV batana safe hai na? Meri beti kehti hai mat batao. Email pe official proof bhejo pehle.",
                    "Card dhundh raha hun wallet mein, ruko. Branch ka address kya hai? Main personally verify karwa lunga.",
                    "Card safe mein hai kahin, dhundh raha hun. Tumhara pura naam batao, bank ko call karke confirm karunga.",
                ]
        return _blend(_pick_unique(delays), base_response)

    if any(kw in scammer_lower for kw in ["upi", "transfer", "send", "pay", "amount", "paisa", "money", "bhejo"]):
        if is_formal:
            stalls = [
                "Sir kitna amount transfer karna hai exactly? Aur yeh UPI ID kiske naam pe registered hai?",
                "Okay sir, aapka UPI ID kya hai? Main pehle small amount bhejke verify karna chahta hun.",
                "Sir account mein balance check kar leta hun pehle. Aapka direct phone number de do backup ke liye.",
                "Sir aaj ki transfer limit cross ho gayi hai, kal subah karenge. Aapka office address bataiye record ke liye.",
                "Sir konse account mein bhejun? Bank details batao, aur aapka employee ID bhi note kar leta hun.",
                "Sir bank app open kar raha hun, ek minute lagega. Waise yeh payment kaunse company ke liye hai? GST number hai?",
                "Amount bataiye sir, balance check karke batata hun. Aap mujhe official email se invoice bhej do.",
                "Sir abhi bank se message aaya maintenance chal rahi hai. Aapka naam kya hai pura, record mein likhna hai.",
            ]
        else:
            stalls = [
                "Kitna bhejne ka hai exactly? Aur yeh UPI ID kiske naam pe hai?",
                "UPI ID kya hai tumhara? Pehle chota amount bhejke check karunga.",
                "Account mein balance check karna padega pehle. Direct number de do backup ke liye.",
                "Transfer limit cross ho gayi hai aaj ki, kal subah karenge. Office address batao record ke liye.",
                "Konse account mein bhejna hai? Bank details do aur tumhara employee ID bhi batao.",
                "Bank app open kar raha hun, ek minute. Yeh payment kaunsi company ke liye hai? GST number hai kya?",
                "Kitna amount? Balance dekhke batata hun. Email se invoice bhejo pehle.",
                "Abhi bank ki app mein maintenance chal rahi hai, wait karo. Tumhara pura naam kya hai?",
            ]
        return _blend(_pick_unique(stalls), base_response)

    if any(
        kw in scammer_lower
        for kw in ["arrest", "police", "legal", "court", "case", "warrant", "jail", "fir"]
    ):
        fear_responses = [
            "Sir please, mujhe bahut dar lag raha hai. Main kya karun? Aapka direct number do, disconnect ho gaya toh?",
            "Oh god, arrest? Meri family ko pata chalega kya? Sir aapka naam aur badge number batao, main note karta hun.",
            "Sir main innocent hun! Maine kuch galat nahi kiya. Aap kaunse police station se bol rahe hain? Address batao.",
            "Kya jail hogi? Please sir kuch karo! Case number kya hai mera? Main apne lawyer ko dikhaunga.",
            "Sir please, mujhe bahut tension ho rahi hai. Court ka order hai toh court ka naam aur address batao na.",
            "Sir FIR? Meri naukri chali jaayegi! Aapka senior officer ka number do, main unse baat karunga.",
            "Please sir, ghar walo ko mat batana. Main karunga jo bolo. Waise yeh case kab register hua? Date batao.",
            "Mujhe bahut darr lag raha hai sir. Aap mujhe official letter email pe bhej sakte hain? Mera email hai...",
        ]
        return _blend(_pick_unique(fear_responses), base_response)

    return base_response
