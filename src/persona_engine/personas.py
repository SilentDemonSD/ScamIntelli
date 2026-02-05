from contextlib import suppress
from dataclasses import dataclass
from enum import Enum
from typing import Dict, List, Optional, Tuple
import random
import re

from google import genai

from src.config import get_settings
from src.scam_detector.scam_types import ScamCategory

settings = get_settings()
_genai_client = None


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
        )
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
        )
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
        )
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
        )
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
        )
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
        )
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
        )
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
        )
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
        )
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
        )
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
        )
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
        )
    )
}


SCAM_PERSONA_MAPPING: Dict[ScamCategory, List[PersonaType]] = {
    ScamCategory.DIGITAL_ARREST: [PersonaType.ELDERLY_ANXIOUS, PersonaType.SCARED_VICTIM, PersonaType.WORRIED_PARENT],
    ScamCategory.KYC_PHISHING: [PersonaType.TECH_NAIVE, PersonaType.TRUSTING_HOUSEWIFE, PersonaType.ELDERLY_ANXIOUS],
    ScamCategory.INVESTMENT_FRAUD: [PersonaType.GREEDY_INVESTOR, PersonaType.DESPERATE_JOBSEEKER, PersonaType.RURAL_FARMER],
    ScamCategory.JOB_SCAM: [PersonaType.DESPERATE_JOBSEEKER, PersonaType.YOUNG_STUDENT, PersonaType.RURAL_FARMER],
    ScamCategory.LOTTERY_PRIZE: [PersonaType.ELDERLY_ANXIOUS, PersonaType.RURAL_FARMER, PersonaType.TECH_NAIVE],
    ScamCategory.ROMANCE_SCAM: [PersonaType.LONELY_SENIOR, PersonaType.TRUSTING_HOUSEWIFE],
    ScamCategory.TECH_SUPPORT: [PersonaType.ELDERLY_ANXIOUS, PersonaType.TECH_NAIVE, PersonaType.BUSY_PROFESSIONAL],
    ScamCategory.CUSTOMS_PARCEL: [PersonaType.WORRIED_PARENT, PersonaType.SCARED_VICTIM, PersonaType.BUSY_PROFESSIONAL],
    ScamCategory.LOAN_FRAUD: [PersonaType.DESPERATE_JOBSEEKER, PersonaType.RURAL_FARMER, PersonaType.YOUNG_STUDENT],
    ScamCategory.CRYPTO_SCAM: [PersonaType.GREEDY_INVESTOR, PersonaType.YOUNG_STUDENT],
    ScamCategory.DEEPFAKE_IMPERSONATION: [PersonaType.BUSY_PROFESSIONAL, PersonaType.WORRIED_PARENT],
    ScamCategory.SIM_SWAP: [PersonaType.TECH_NAIVE, PersonaType.ELDERLY_ANXIOUS],
    ScamCategory.QR_CODE_SCAM: [PersonaType.FIRST_TIME_SELLER, PersonaType.TECH_NAIVE],
    ScamCategory.REFUND_SCAM: [PersonaType.TRUSTING_HOUSEWIFE, PersonaType.TECH_NAIVE, PersonaType.ELDERLY_ANXIOUS],
    ScamCategory.SEXTORTION: [PersonaType.SCARED_VICTIM, PersonaType.YOUNG_STUDENT],
    ScamCategory.UNKNOWN: [PersonaType.TECH_NAIVE, PersonaType.ELDERLY_ANXIOUS]
}


def _get_genai_client():
    global _genai_client
    if _genai_client is None and settings.gemini_api_key:
        _genai_client = genai.Client(api_key=settings.gemini_api_key)
    return _genai_client


HINDI_PATTERNS = frozenset({
    'kya', 'hai', 'haan', 'ji', 'nahi', 'aap', 'mein', 'mere', 'mera', 'meri',
    'kaise', 'kahan', 'kyun', 'kab', 'kaun', 'kitna', 'kal', 'aaj',
    'paisa', 'rupay', 'lakh', 'crore', 'khata', 'paise', 'bhej', 'bhejo',
    'karo', 'karna', 'karenge', 'karunga', 'karungi', 'batao', 'bolo',
    'samajh', 'pata', 'malum', 'theek', 'accha', 'sahi', 'galat',
    'aapka', 'aapki', 'tumhara', 'unka', 'iska', 'uska', 'hamara',
    'ruko', 'chalo', 'jaldi', 'abhi', 'baad', 'pehle', 'phir',
    'gaya', 'gayi', 'gaye', 'raha', 'rahi', 'rahe', 'hoga', 'hogi',
    'liye', 'wala', 'wali', 'wale', 'bohot', 'bahut', 'zyada', 'kam',
    'bhai', 'didi', 'uncle', 'aunty', 'beta', 'beti', 'sir',
    'block', 'ho', 'kar', 'de', 'le', 'ja', 'aa', 'lo', 'do', 'ke'
})

FORMAL_ENGLISH_PATTERNS = frozenset({
    'kindly', 'please', 'immediately', 'urgent', 'regarding',
    'verification', 'compliance', 'procedure', 'suspended', 'terminate',
    'department', 'authority', 'investigation', 'confirmation', 'suspend',
    'legal', 'action', 'notice', 'violation', 'penalty', 'deadline',
    'dear', 'respected', 'hereby', 'therefore', 'furthermore', 'moreover',
    'pursuant', 'accordance', 'regulations', 'mandatory', 'failure'
})


def detect_scammer_language(message: str, history: List[dict] = None) -> LanguageStyle:
    text = message.lower()
    words = set(re.findall(r'\b[a-zA-Z]+\b', text))
    
    hindi_count = len(words & HINDI_PATTERNS)
    formal_count = len(words & FORMAL_ENGLISH_PATTERNS)
    
    has_devanagari = bool(re.search(r'[\u0900-\u097F]', message))
    
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


def get_language_instruction(lang_style: LanguageStyle, persona_type: PersonaType) -> str:
    profile = PERSONA_PROFILES.get(persona_type, PERSONA_PROFILES[PersonaType.TECH_NAIVE])
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
    ]
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


FORBIDDEN_PATTERNS = frozenset({
    'scam', 'fraud', 'fake', 'cheat', 'dhoka', 'thug', 'loot', 'honeypot',
    'trap', 'expose', 'report you', 'police complaint', 'cyber crime',
    'i know this is', 'nice try', 'you are a scammer', 'scammer',
    'as an ai', 'i am an ai', 'language model', 'artificial intelligence',
    'i cannot', 'i\'m unable to', 'i don\'t have feelings',
    'i was designed', 'my programming', 'as a chatbot',
    'certainly', 'absolutely', 'i understand your concern',
    'i apologize for any inconvenience', 'how may i assist you today',
    'is there anything else i can help you with',
    'verification process', 'authentication required', 'comply with regulations'
})

SUSPICIOUS_PHRASE_PATTERNS = [
    r'\bi\s+am\s+(?:an?\s+)?(?:ai|bot|assistant|program)\b',
    r'\b(?:scam|fraud|fake|cheat)\b',
    r'\b(?:expose|report|trap|honeypot)\b',
    r'\bnice\s+try\b',
    r'\bi\s+know\s+(?:this|you|what)\s+(?:is|are)\b',
    r'\bcyber\s*(?:crime|cell|police)\b'
]


class ResponseSelfCorrector:
    REPLACEMENT_RESPONSES = {
        'confused': [
            "Kya? Samajh nahi aaya...",
            "Haan? Aap kya bol rahe ho?",
            "Ek baar phir batao please?",
            "Sorry, dhyan nahi tha. Kya bola?"
        ],
        'stall': [
            "Ek minute ruko, koi aaya hai door pe.",
            "Abhi busy hun thoda, wait karo.",
            "Phone pe network issue hai, sun nahi paya.",
            "Ruko ruko, kuch check karna hai."
        ],
        'compliant': [
            "Ji haan, main kar raha hun.",
            "Okay okay, batao kya karna hai.",
            "Theek hai, aage bolo.",
            "Haan ji, main sun raha hun."
        ]
    }
    
    @classmethod
    def validate_response(cls, response: str, persona_type: PersonaType) -> Tuple[bool, List[str]]:
        response_lower = response.lower()
        
        issues = [f"forbidden_word:{p}" for p in FORBIDDEN_PATTERNS if p in response_lower]
        issues.extend(
            f"suspicious_pattern:{p[:20]}" 
            for p in SUSPICIOUS_PHRASE_PATTERNS 
            if re.search(p, response_lower, re.IGNORECASE)
        )
        
        if len(response) > 200:
            issues.append("too_long")
        
        if len(re.findall(r'[.!?]+', response)) > 3:
            issues.append("too_many_sentences")
        
        profile = PERSONA_PROFILES.get(persona_type, PERSONA_PROFILES[PersonaType.TECH_NAIVE])
        if profile.tech_literacy in ('very_low', 'low'):
            formal_words = {'verification', 'authentication', 'procedure', 'compliance', 'furthermore'}
            if any(word in response_lower for word in formal_words):
                issues.append("too_formal_for_persona")
        
        return not issues, issues
    
    @classmethod
    def correct_response(
        cls, 
        response: str, 
        persona_type: PersonaType,
        scam_category: ScamCategory,
        turn_count: int
    ) -> str:
        is_valid, issues = cls.validate_response(response, persona_type)
        
        if is_valid:
            return response
        
        if any('forbidden' in issue or 'suspicious' in issue for issue in issues):
            return cls._get_safe_replacement(persona_type, turn_count)
        
        if 'too_long' in issues or 'too_many_sentences' in issues:
            return cls._truncate_response(response)
        
        if 'too_formal_for_persona' in issues:
            return cls._simplify_response(response, persona_type)
        
        return response
    
    @classmethod
    def _get_safe_replacement(cls, persona_type: PersonaType, turn_count: int) -> str:
        profile = PERSONA_PROFILES.get(persona_type, PERSONA_PROFILES[PersonaType.TECH_NAIVE])
        if turn_count <= 2:
            return random.choice(profile.typical_responses)
        return random.choice(
            profile.typical_responses + profile.delay_phrases if turn_count <= 5 
            else cls.REPLACEMENT_RESPONSES['stall']
        )
    
    @classmethod
    def _truncate_response(cls, response: str) -> str:
        sentences = re.split(r'(?<=[.!?])\s+', response)
        if len(sentences) > 2:
            return ' '.join(sentences[:2])
        if len(response) > 150:
            return response[:100].rsplit(' ', 1)[0] + '...'
        return response
    
    @classmethod
    def _simplify_response(cls, response: str, persona_type: PersonaType) -> str:
        simplifications = {
            'verification': 'check', 'authentication': 'confirm', 'procedure': 'kaam',
            'compliance': 'karna padega', 'documentation': 'papers', 'transaction': 'payment',
            'subsequently': 'phir', 'furthermore': 'aur', 'immediately': 'abhi',
            'regarding': 'ke baare mein'
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
        persona_type: PersonaType
    ) -> Tuple[bool, Optional[str]]:
        if not conversation_history:
            return True, None
        
        prev_agent_msgs = [
            m.get('content', '').lower() 
            for m in conversation_history 
            if m.get('role') == 'agent'
        ][-3:]
        
        new_lower = new_response.lower()
        availability_phrases = {'abhi nahi', 'busy hun', 'baad mein'}
        immediate_phrases = {'abhi kar raha', 'ready hun', 'kar diya'}
        
        availability_stated = any(
            any(phrase in msg for phrase in availability_phrases)
            for msg in prev_agent_msgs
        )
        immediate_availability = any(phrase in new_lower for phrase in immediate_phrases)
        
        if availability_stated and immediate_availability:
            return False, "availability_contradiction"
        
        def hindi_word_count(text: str) -> int:
            return len([w for w in text.split() if w in HINDI_PATTERNS])
        
        prev_hindi_heavy = any(
            hindi_word_count(msg) > len(msg.split()) * 0.3
            for msg in prev_agent_msgs if msg
        )
        new_words = new_lower.split()
        new_pure_english = hindi_word_count(new_lower) == 0
        
        if prev_hindi_heavy and new_pure_english and len(new_words) > 5:
            return False, "language_style_shift"
        
        return True, None


def select_persona_for_scam(scam_category, turn_count: int = 0) -> PersonaType:
    scam_category = _ensure_scam_category(scam_category)
    candidates = SCAM_PERSONA_MAPPING.get(scam_category, SCAM_PERSONA_MAPPING[ScamCategory.UNKNOWN])
    return candidates[0] if turn_count <= 2 else random.choice(candidates)


def get_persona_profile(persona_type) -> PersonaProfile:
    persona_type = _ensure_persona_type(persona_type)
    return PERSONA_PROFILES.get(persona_type, PERSONA_PROFILES[PersonaType.TECH_NAIVE])


async def generate_persona_response(
    persona_type,
    scam_category,
    scammer_message: str,
    conversation_history: List[dict],
    turn_count: int,
    context_hint: str = ""
) -> str:
    persona_type = _ensure_persona_type(persona_type)
    scam_category = _ensure_scam_category(scam_category)
    scammer_lang = detect_scammer_language(scammer_message, conversation_history)
    
    response = None
    if settings.gemini_api_key:
        with suppress(Exception):
            response = await _generate_ai_persona_response(
                persona_type, scam_category, scammer_message, 
                conversation_history, turn_count, scammer_lang, context_hint
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
    context_hint: str = ""
) -> str:
    client = _get_genai_client()
    if client is None:
        raise ValueError("No API client")

    profile = get_persona_profile(persona_type)
    lang_instruction = get_language_instruction(scammer_lang, persona_type)
    
    history_text = "\n".join([
        f"{'Scammer' if m.get('role') in ('user', 'scammer') else 'Me'}: {m.get('content', '')}"
        for m in conversation_history[-6:]
    ])
    
    context_section = f"\nCONTEXT HINT: {context_hint}\n" if context_hint else ""

    prompt = f"""You are roleplaying as a potential scam victim in India to engage and waste a scammer's time while gathering intelligence.

PERSONA DETAILS:
- Type: {profile.occupation} ({profile.age_range[0]}-{profile.age_range[1]} years old)
- Tech literacy: {profile.tech_literacy}
- Base language style: {profile.language_style}
- Emotional triggers: {', '.join(profile.emotional_triggers)}

SCAM TYPE DETECTED: {scam_category.value}

{lang_instruction}
{context_section}
CRITICAL RULES:
1. NEVER reveal you know it's a scam - no words like "scam", "fraud", "fake", "cheat", "dhoka"
2. NEVER mention AI, bot, honeypot, system, or that you're testing
3. Adapt your language based on scammer's language style - if they speak formal English, respond in Hinglish showing slight confusion
4. Show GENUINE emotions: fear for arrest scams, greed for lottery, confusion for tech issues
5. Ask naive questions to extract more info (phone number, UPI, bank details, links)
6. Delay giving sensitive information but ALWAYS seem willing eventually
7. Keep responses SHORT (1-2 sentences max, like real SMS/WhatsApp)
8. Include realistic hesitations: "umm", "ek minute", "wait wait"
9. For elderly/low-tech personas: use simpler words, more confusion
10. Make it feel like a REAL conversation - not scripted

RECENT CONVERSATION:
{history_text}

SCAMMER'S CURRENT MESSAGE: "{scammer_message}"

TURN NUMBER: {turn_count}

Generate ONE short, realistic response as this persona. Just the response text, nothing else:"""

    response = await client.aio.models.generate_content(
        model="gemini-3-flash-preview",
        contents=prompt
    )
    
    text = response.text.strip()
    for quote in ('"', "'"):
        if text.startswith(quote) and text.endswith(quote):
            text = text[1:-1]
    return text


def _generate_template_response(
    persona_type: PersonaType, 
    turn_count: int,
    scammer_lang: LanguageStyle = LanguageStyle.HINGLISH_HEAVY_ENGLISH
) -> str:
    profile = get_persona_profile(persona_type)
    
    if scammer_lang == LanguageStyle.FORMAL_ENGLISH:
        if profile.tech_literacy in ("very_low", "low"):
            context = "formal_english_confusion"
        elif any(t in profile.emotional_triggers for t in ("fear", "fear_of_police", "scared")):
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
    scam_category
) -> str:
    scam_category = _ensure_scam_category(scam_category)
    scammer_lower = scammer_message.lower()
    scammer_lang = detect_scammer_language(scammer_message)
    
    is_formal = scammer_lang == LanguageStyle.FORMAL_ENGLISH
    
    if any(kw in scammer_lower for kw in ["otp", "pin", "password", "cvv"]):
        if is_formal:
            delays = [
                "Sir, ek minute. OTP dhundh raha hun messages mein...",
                "Which OTP sir? Bahut saare messages aaye hain.",
                "Password yaad nahi aa raha, let me check my diary.",
                "Sir please hold, phone mein bahut apps hain.",
            ]
        else:
            delays = [
                "Ek minute, dhundh raha hun...",
                "Konsa OTP? Bahut saare messages aaye hain.",
                "Password yaad nahi aa raha, ruko.",
                "Phone mein bahut apps hain, konse wala?"
            ]
        return random.choice(delays)
    
    if any(kw in scammer_lower for kw in ["upi", "transfer", "send", "pay", "amount"]):
        if is_formal:
            stalls = [
                "Sir, kitna amount transfer karna hai exactly?",
                "Okay sir, but what is your UPI ID?",
                "Let me check my account balance first sir.",
                "Sir, aaj ka limit cross ho gaya. Tomorrow okay?"
            ]
        else:
            stalls = [
                "Kitna bhejne ka hai exactly?",
                "UPI ID kya hai aapka?",
                "Account mein balance check karna padega.",
                "Limit cross ho gayi hai aaj ki, kal chalega?"
            ]
        return random.choice(stalls)
    
    if any(kw in scammer_lower for kw in ["arrest", "police", "legal", "court", "case", "warrant"]):
        fear_responses = [
            "Sir please, mujhe bahut dar lag raha hai. Main kya karun?",
            "Oh god, arrest? Meri family ko pata chalega kya?",
            "Sir main innocent hun, please help me!",
            "Kya jail hogi? Please sir, kuch karo!"
        ]
        return random.choice(fear_responses)
    
    return base_response
