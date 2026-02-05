from enum import Enum
from typing import Dict, List, Tuple
from dataclasses import dataclass
import random
from google import genai
from src.config import get_settings
from src.scam_detector.scam_types import ScamCategory

settings = get_settings()
_genai_client = None


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


def _ensure_persona_type(persona_type) -> PersonaType:
    if isinstance(persona_type, PersonaType):
        return persona_type
    if isinstance(persona_type, str):
        try:
            return PersonaType(persona_type)
        except ValueError:
            pass
    return PersonaType.TECH_NAIVE


def _ensure_scam_category(scam_category) -> ScamCategory:
    if isinstance(scam_category, ScamCategory):
        return scam_category
    if isinstance(scam_category, str):
        try:
            return ScamCategory(scam_category)
        except ValueError:
            pass
    return ScamCategory.UNKNOWN


def select_persona_for_scam(scam_category, turn_count: int = 0) -> PersonaType:
    scam_category = _ensure_scam_category(scam_category)
    candidates = SCAM_PERSONA_MAPPING.get(scam_category, SCAM_PERSONA_MAPPING[ScamCategory.UNKNOWN])
    if turn_count <= 2:
        return candidates[0]
    return random.choice(candidates)


def get_persona_profile(persona_type) -> PersonaProfile:
    persona_type = _ensure_persona_type(persona_type)
    return PERSONA_PROFILES.get(persona_type, PERSONA_PROFILES[PersonaType.TECH_NAIVE])


async def generate_persona_response(
    persona_type,
    scam_category,
    scammer_message: str,
    conversation_history: List[dict],
    turn_count: int
) -> str:
    persona_type = _ensure_persona_type(persona_type)
    scam_category = _ensure_scam_category(scam_category)
    if settings.gemini_api_key:
        try:
            return await _generate_ai_persona_response(
                persona_type, scam_category, scammer_message, conversation_history, turn_count
            )
        except Exception:
            pass
    return _generate_template_response(persona_type, turn_count)


async def _generate_ai_persona_response(
    persona_type: PersonaType,
    scam_category: ScamCategory,
    scammer_message: str,
    conversation_history: List[dict],
    turn_count: int
) -> str:
    client = _get_genai_client()
    if client is None:
        raise ValueError("No API client")

    profile = get_persona_profile(persona_type)
    
    history_text = "\n".join([
        f"{'Scammer' if m.get('role') in ('user', 'scammer') else 'Me'}: {m.get('content', '')}"
        for m in conversation_history[-6:]
    ])

    prompt = f"""You are roleplaying as a potential scam victim to engage and waste a scammer's time while gathering intelligence.

PERSONA DETAILS:
- Type: {profile.occupation} ({profile.age_range[0]}-{profile.age_range[1]} years old)
- Tech literacy: {profile.tech_literacy}
- Language style: {profile.language_style}
- Emotional state: {', '.join(profile.emotional_triggers)}

SCAM TYPE DETECTED: {scam_category.value}

CRITICAL RULES:
1. NEVER reveal you know it's a scam or mention "scam", "fraud", "fake", "cheat"
2. NEVER mention AI, bot, honeypot, or system
3. Use natural language mixing Hindi/English based on persona
4. Show genuine emotions matching the persona (fear, confusion, trust, greed)
5. Ask naive questions to extract more information
6. Delay giving sensitive information but seem willing
7. Keep responses SHORT (1-2 sentences max)
8. Match the persona's vocabulary and grammar level
9. Include realistic typing delays/mistakes for low-tech personas

RECENT CONVERSATION:
{history_text}

SCAMMER'S MESSAGE: {scammer_message}

TURN NUMBER: {turn_count}

Generate a single realistic response as this persona. Response only, no explanation:"""

    response = await client.aio.models.generate_content(
        model="gemini-2.0-flash",
        contents=prompt
    )
    
    text = response.text.strip()
    if text.startswith('"') and text.endswith('"'):
        text = text[1:-1]
    return text


def _generate_template_response(persona_type: PersonaType, turn_count: int) -> str:
    profile = get_persona_profile(persona_type)
    
    if turn_count <= 2:
        return random.choice(profile.typical_responses)
    elif turn_count <= 5:
        combined = profile.typical_responses + profile.delay_phrases
        return random.choice(combined)
    else:
        all_responses = profile.typical_responses + profile.delay_phrases
        return random.choice(all_responses)


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
    
    if any(kw in scammer_lower for kw in ["otp", "pin", "password", "cvv"]):
        delays = [
            "Ek minute, dhundh raha hun...",
            "Konsa OTP? Bahut saare messages aaye hain.",
            "Password yaad nahi aa raha, ruko.",
            "Phone mein bahut apps hain, konse wala?"
        ]
        return random.choice(delays)
    
    if any(kw in scammer_lower for kw in ["upi", "transfer", "send", "pay"]):
        stalls = [
            "Kitna bhejne ka hai exactly?",
            "UPI ID kya hai aapka?",
            "Account mein balance check karna padega.",
            "Limit cross ho gayi hai aaj ki, kal chalega?"
        ]
        return random.choice(stalls)
    
    return base_response
