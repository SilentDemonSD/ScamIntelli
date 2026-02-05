from enum import Enum
from typing import Dict, Set, List, Tuple
from dataclasses import dataclass


class ScamCategory(str, Enum):
    DIGITAL_ARREST = "digital_arrest"
    KYC_PHISHING = "kyc_phishing"
    INVESTMENT_FRAUD = "investment_fraud"
    JOB_SCAM = "job_scam"
    LOTTERY_PRIZE = "lottery_prize"
    ROMANCE_SCAM = "romance_scam"
    TECH_SUPPORT = "tech_support"
    CUSTOMS_PARCEL = "customs_parcel"
    LOAN_FRAUD = "loan_fraud"
    CRYPTO_SCAM = "crypto_scam"
    DEEPFAKE_IMPERSONATION = "deepfake_impersonation"
    SIM_SWAP = "sim_swap"
    QR_CODE_SCAM = "qr_code_scam"
    REFUND_SCAM = "refund_scam"
    SEXTORTION = "sextortion"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class ScamProfile:
    category: ScamCategory
    severity: int
    typical_tactics: Tuple[str, ...]
    recommended_persona: str
    max_engagement_turns: int


SCAM_CATEGORY_KEYWORDS: Dict[ScamCategory, Set[str]] = {
    ScamCategory.DIGITAL_ARREST: {
        "digital arrest", "cyber police", "cyber cell", "cbi", "ed", "enforcement directorate",
        "narcotics", "money laundering", "hawala", "terror funding", "fir registered",
        "arrest warrant", "virtual court", "video verification", "skype verification",
        "under surveillance", "your aadhaar", "your pan linked", "suspicious transaction",
        "national security", "cyber crime branch", "crime branch", "high court order"
    },
    ScamCategory.KYC_PHISHING: {
        "kyc", "kyc update", "kyc pending", "kyc expired", "verify account", "verify identity",
        "account blocked", "account suspended", "account freeze", "reactivate account",
        "complete verification", "pan verification", "aadhaar link", "bank verification",
        "update details", "re-kyc", "ekyc", "video kyc"
    },
    ScamCategory.INVESTMENT_FRAUD: {
        "guaranteed returns", "daily profit", "weekly returns", "100% profit", "double money",
        "forex trading", "stock tips", "ipo allotment", "pre-ipo", "insider tips",
        "trading platform", "investment opportunity", "high returns", "zero risk",
        "compounding interest", "refer and earn", "mlm", "multi level"
    },
    ScamCategory.JOB_SCAM: {
        "work from home", "part time job", "typing job", "data entry", "easy money",
        "registration fee", "training fee", "job guarantee", "amazon job", "flipkart job",
        "online task", "review job", "like and subscribe", "telegram job", "whatsapp job"
    },
    ScamCategory.LOTTERY_PRIZE: {
        "lottery winner", "prize money", "you have won", "congratulations winner",
        "lucky draw", "jackpot", "claim prize", "processing fee", "tax payment",
        "international lottery", "whatsapp lottery", "google lottery"
    },
    ScamCategory.ROMANCE_SCAM: {
        "gift stuck customs", "send money urgent", "stranded abroad", "military deployment",
        "business partner", "inheritance", "share life together", "marriage proposal",
        "visa fee", "flight ticket", "medical emergency abroad"
    },
    ScamCategory.TECH_SUPPORT: {
        "virus detected", "computer hacked", "microsoft support", "apple support",
        "remote access", "anydesk", "teamviewer", "quick support", "system compromised",
        "firewall breach", "subscription expired", "license renewal"
    },
    ScamCategory.CUSTOMS_PARCEL: {
        "parcel detained", "customs clearance", "import duty", "seized package",
        "dhl courier", "fedex package", "drugs found", "illegal content",
        "pay customs fee", "release shipment", "international courier"
    },
    ScamCategory.LOAN_FRAUD: {
        "instant loan", "pre-approved loan", "loan disbursement", "processing charges",
        "credit score", "loan rejected", "pay to release", "personal loan offer",
        "advance payment", "gst charges", "documentation fee"
    },
    ScamCategory.CRYPTO_SCAM: {
        "bitcoin investment", "crypto trading", "nft opportunity", "token presale",
        "airdrop", "wallet connect", "seed phrase", "private key",
        "mining pool", "staking rewards", "defi yield"
    },
    ScamCategory.DEEPFAKE_IMPERSONATION: {
        "video call verification", "face verification", "live video required",
        "boss calling", "ceo urgent", "family emergency video", "ai generated"
    },
    ScamCategory.SIM_SWAP: {
        "sim upgrade", "4g to 5g", "new sim required", "sim deactivation",
        "port number", "sim blocked", "telecom verification"
    },
    ScamCategory.QR_CODE_SCAM: {
        "scan qr", "scan to receive", "qr payment", "scan for refund",
        "olx payment", "buyer qr", "seller qr"
    },
    ScamCategory.REFUND_SCAM: {
        "refund pending", "excess payment", "refund initiated", "bank refund",
        "cancelled order refund", "insurance refund", "tax refund"
    },
    ScamCategory.SEXTORTION: {
        "private photos", "video leaked", "webcam recorded", "adult website",
        "pay to delete", "reputation damage", "share contacts"
    }
}


SCAM_PROFILES: Dict[ScamCategory, ScamProfile] = {
    ScamCategory.DIGITAL_ARREST: ScamProfile(
        category=ScamCategory.DIGITAL_ARREST,
        severity=10,
        typical_tactics=("authority_impersonation", "fear_inducement", "isolation", "continuous_surveillance"),
        recommended_persona="elderly_anxious",
        max_engagement_turns=12
    ),
    ScamCategory.KYC_PHISHING: ScamProfile(
        category=ScamCategory.KYC_PHISHING,
        severity=7,
        typical_tactics=("urgency", "account_threat", "link_sharing"),
        recommended_persona="tech_naive",
        max_engagement_turns=8
    ),
    ScamCategory.INVESTMENT_FRAUD: ScamProfile(
        category=ScamCategory.INVESTMENT_FRAUD,
        severity=8,
        typical_tactics=("greed_exploitation", "social_proof", "urgency"),
        recommended_persona="greedy_naive",
        max_engagement_turns=10
    ),
    ScamCategory.JOB_SCAM: ScamProfile(
        category=ScamCategory.JOB_SCAM,
        severity=6,
        typical_tactics=("opportunity", "registration_fee", "task_completion"),
        recommended_persona="desperate_jobseeker",
        max_engagement_turns=8
    ),
    ScamCategory.LOTTERY_PRIZE: ScamProfile(
        category=ScamCategory.LOTTERY_PRIZE,
        severity=5,
        typical_tactics=("greed", "processing_fee", "tax_payment"),
        recommended_persona="excited_naive",
        max_engagement_turns=6
    ),
    ScamCategory.ROMANCE_SCAM: ScamProfile(
        category=ScamCategory.ROMANCE_SCAM,
        severity=8,
        typical_tactics=("emotional_manipulation", "emergency", "future_promises"),
        recommended_persona="lonely_trusting",
        max_engagement_turns=15
    ),
    ScamCategory.TECH_SUPPORT: ScamProfile(
        category=ScamCategory.TECH_SUPPORT,
        severity=7,
        typical_tactics=("fear", "remote_access", "urgency"),
        recommended_persona="tech_illiterate",
        max_engagement_turns=8
    ),
    ScamCategory.CUSTOMS_PARCEL: ScamProfile(
        category=ScamCategory.CUSTOMS_PARCEL,
        severity=8,
        typical_tactics=("authority", "fear", "legal_threat"),
        recommended_persona="worried_recipient",
        max_engagement_turns=10
    ),
    ScamCategory.LOAN_FRAUD: ScamProfile(
        category=ScamCategory.LOAN_FRAUD,
        severity=6,
        typical_tactics=("desperation_exploitation", "processing_fee", "urgency"),
        recommended_persona="financially_desperate",
        max_engagement_turns=8
    ),
    ScamCategory.CRYPTO_SCAM: ScamProfile(
        category=ScamCategory.CRYPTO_SCAM,
        severity=7,
        typical_tactics=("fomo", "technical_jargon", "high_returns"),
        recommended_persona="curious_investor",
        max_engagement_turns=8
    ),
    ScamCategory.DEEPFAKE_IMPERSONATION: ScamProfile(
        category=ScamCategory.DEEPFAKE_IMPERSONATION,
        severity=9,
        typical_tactics=("trust_exploitation", "urgency", "authority"),
        recommended_persona="trusting_employee",
        max_engagement_turns=6
    ),
    ScamCategory.SIM_SWAP: ScamProfile(
        category=ScamCategory.SIM_SWAP,
        severity=8,
        typical_tactics=("telecom_impersonation", "upgrade_offer", "urgency"),
        recommended_persona="tech_naive",
        max_engagement_turns=6
    ),
    ScamCategory.QR_CODE_SCAM: ScamProfile(
        category=ScamCategory.QR_CODE_SCAM,
        severity=6,
        typical_tactics=("reversal_trick", "buyer_impersonation", "urgency"),
        recommended_persona="first_time_seller",
        max_engagement_turns=6
    ),
    ScamCategory.REFUND_SCAM: ScamProfile(
        category=ScamCategory.REFUND_SCAM,
        severity=6,
        typical_tactics=("greed", "bank_impersonation", "excess_payment"),
        recommended_persona="expecting_refund",
        max_engagement_turns=8
    ),
    ScamCategory.SEXTORTION: ScamProfile(
        category=ScamCategory.SEXTORTION,
        severity=9,
        typical_tactics=("blackmail", "shame", "urgency"),
        recommended_persona="scared_victim",
        max_engagement_turns=5
    ),
    ScamCategory.UNKNOWN: ScamProfile(
        category=ScamCategory.UNKNOWN,
        severity=5,
        typical_tactics=("generic",),
        recommended_persona="confused_user",
        max_engagement_turns=10
    )
}


def detect_scam_category(message: str, keywords: List[str]) -> Tuple[ScamCategory, float]:
    message_lower = message.lower()
    keywords_lower = {kw.lower() for kw in keywords}
    
    scores: Dict[ScamCategory, float] = {}
    
    for category, category_keywords in SCAM_CATEGORY_KEYWORDS.items():
        match_count = 0
        for kw in category_keywords:
            if kw in message_lower:
                match_count += 2
            elif kw in keywords_lower:
                match_count += 1
        
        if match_count > 0:
            scores[category] = min(match_count / 4, 1.0)
    
    if not scores:
        return ScamCategory.UNKNOWN, 0.0
    
    best_category = max(scores, key=scores.get)
    return best_category, scores[best_category]


def get_scam_profile(category: ScamCategory) -> ScamProfile:
    return SCAM_PROFILES.get(category, SCAM_PROFILES[ScamCategory.UNKNOWN])
