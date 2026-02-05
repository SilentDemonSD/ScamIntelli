from typing import Dict, FrozenSet

URGENCY_KEYWORDS: FrozenSet[str] = frozenset({
    "urgent", "immediately", "right now", "today only", "expire", "last chance",
    "hurry", "quick", "asap", "deadline", "limited time", "act now", "don't delay",
    "time sensitive", "within 24 hours", "within 1 hour", "expires today",
    "final notice", "last warning", "immediate action", "right away"
})

THREAT_KEYWORDS: FrozenSet[str] = frozenset({
    "account blocked", "account suspended", "account will be blocked", "legal action",
    "police complaint", "case filed", "arrest", "fine", "penalty", "blacklisted",
    "suspended", "terminated", "frozen", "disabled", "deactivated", "court order",
    "warrant issued", "fir", "criminal case", "jail", "imprisonment", "prosecution",
    "investigation", "under observation", "surveillance", "cyber crime"
})

PAYMENT_KEYWORDS: FrozenSet[str] = frozenset({
    "upi", "upi id", "send money", "transfer", "payment", "pay now", "google pay",
    "phonepe", "paytm", "bhim", "bank transfer", "neft", "imps", "rtgs",
    "wire transfer", "western union", "money gram", "bitcoin", "crypto", "usdt",
    "pay immediately", "transfer amount", "deposit money"
})

CREDENTIAL_KEYWORDS: FrozenSet[str] = frozenset({
    "otp", "password", "pin", "cvv", "card number", "atm pin", "bank details",
    "account number", "ifsc", "login", "verify", "confirm", "update kyc",
    "kyc update", "pan card", "aadhaar", "passport", "driving license",
    "security code", "mpin", "upi pin", "net banking password", "debit card",
    "credit card", "expiry date", "date of birth"
})

DIGITAL_ARREST_KEYWORDS: FrozenSet[str] = frozenset({
    "digital arrest", "cyber police", "cyber cell", "cbi officer", "cbi calling",
    "enforcement directorate", "ed notice", "narcotics bureau", "ncb",
    "money laundering", "hawala", "terror funding", "pmla", "fema violation",
    "arrest warrant", "video court", "virtual hearing", "skype verification",
    "zoom call court", "under digital arrest", "do not disconnect",
    "stay on video", "your aadhaar linked", "suspicious sim", "multiple sims"
})

INVESTMENT_SCAM_KEYWORDS: FrozenSet[str] = frozenset({
    "guaranteed returns", "100% profit", "double money", "risk free investment",
    "forex signals", "crypto signals", "trading bot", "auto trading",
    "minimum investment", "daily income", "passive income", "compounding",
    "referral bonus", "mlm", "ponzi", "high yield", "exclusive opportunity",
    "limited slots", "vip membership", "premium signals"
})

JOB_SCAM_KEYWORDS: FrozenSet[str] = frozenset({
    "work from home job", "part time income", "typing job", "data entry work",
    "amazon hiring", "flipkart jobs", "google jobs", "easy tasks",
    "registration fee required", "training charges", "refundable deposit",
    "telegram task", "whatsapp group job", "like subscribe earn",
    "review writing job", "product review", "app rating job"
})

CUSTOMS_PARCEL_KEYWORDS: FrozenSet[str] = frozenset({
    "parcel detained", "customs clearance fee", "import duty payment",
    "package seized", "drugs found parcel", "illegal items detected",
    "dhl customs", "fedex customs", "international courier seized",
    "pay duty charges", "parcel release fee", "contraband detected"
})

TECH_SUPPORT_KEYWORDS: FrozenSet[str] = frozenset({
    "virus detected", "computer infected", "malware found", "hacker attack",
    "microsoft calling", "apple support", "windows security", "firewall breach",
    "remote access required", "install anydesk", "download teamviewer",
    "system compromised", "data breach detected", "subscription expired"
})

ROMANCE_SCAM_KEYWORDS: FrozenSet[str] = frozenset({
    "stuck in airport", "gift detained customs", "need money urgent",
    "military contractor", "oil rig worker", "inheritance claim",
    "marry you", "future together", "visa processing fee", "flight ticket money",
    "medical emergency abroad", "business investment together"
})

REFUND_SCAM_KEYWORDS: FrozenSet[str] = frozenset({
    "refund initiated", "excess amount credited", "wrong transfer",
    "refund processing", "return money", "accidental transfer",
    "bank refund pending", "tax refund available", "insurance claim ready"
})

QR_CODE_KEYWORDS: FrozenSet[str] = frozenset({
    "scan qr to receive", "scan for payment", "qr code payment",
    "olx buyer", "scan to get money", "qr for refund"
})

LOAN_SCAM_KEYWORDS: FrozenSet[str] = frozenset({
    "instant loan approved", "pre-approved loan", "loan disbursement",
    "processing fee required", "gst charges loan", "loan release payment",
    "low cibil loan", "no document loan", "5 minute loan"
})

SEXTORTION_KEYWORDS: FrozenSet[str] = frozenset({
    "private video recorded", "webcam hacked", "adult video leak",
    "pay or share", "your contacts list", "reputation destroy",
    "video call recorded", "screenshot taken"
})

INDIA_SPECIFIC_PATTERNS: FrozenSet[str] = frozenset({
    "verify immediately", "kyc pending", "bank suspend", "click link",
    "call this number", "customer care", "toll free", "refund pending",
    "cashback", "lottery winner", "prize money", "rbi notification",
    "income tax", "it department", "sebi registered", "trai", "dot",
    "central government", "state government", "pm scheme", "govt scheme"
})


def get_all_scam_keywords() -> FrozenSet[str]:
    return (
        URGENCY_KEYWORDS | THREAT_KEYWORDS | PAYMENT_KEYWORDS | CREDENTIAL_KEYWORDS |
        DIGITAL_ARREST_KEYWORDS | INVESTMENT_SCAM_KEYWORDS | JOB_SCAM_KEYWORDS |
        CUSTOMS_PARCEL_KEYWORDS | TECH_SUPPORT_KEYWORDS | ROMANCE_SCAM_KEYWORDS |
        REFUND_SCAM_KEYWORDS | QR_CODE_KEYWORDS | LOAN_SCAM_KEYWORDS |
        SEXTORTION_KEYWORDS | INDIA_SPECIFIC_PATTERNS
    )


def get_keyword_categories() -> Dict[str, FrozenSet[str]]:
    return {
        "urgency": URGENCY_KEYWORDS,
        "threat": THREAT_KEYWORDS,
        "payment": PAYMENT_KEYWORDS,
        "credential": CREDENTIAL_KEYWORDS,
        "digital_arrest": DIGITAL_ARREST_KEYWORDS,
        "investment": INVESTMENT_SCAM_KEYWORDS,
        "job_scam": JOB_SCAM_KEYWORDS,
        "customs": CUSTOMS_PARCEL_KEYWORDS,
        "tech_support": TECH_SUPPORT_KEYWORDS,
        "romance": ROMANCE_SCAM_KEYWORDS,
        "refund": REFUND_SCAM_KEYWORDS,
        "qr_code": QR_CODE_KEYWORDS,
        "loan": LOAN_SCAM_KEYWORDS,
        "sextortion": SEXTORTION_KEYWORDS,
        "india_patterns": INDIA_SPECIFIC_PATTERNS
    }


def get_high_severity_keywords() -> FrozenSet[str]:
    return DIGITAL_ARREST_KEYWORDS | SEXTORTION_KEYWORDS | CREDENTIAL_KEYWORDS


def get_category_severity() -> Dict[str, int]:
    return {
        "digital_arrest": 10, "sextortion": 9, "credential": 8, "customs": 8,
        "threat": 7, "investment": 7, "romance": 7, "tech_support": 6,
        "loan": 6, "job_scam": 5, "refund": 5, "qr_code": 5,
        "urgency": 4, "payment": 4, "india_patterns": 3
    }
