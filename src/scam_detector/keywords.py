from typing import Set

URGENCY_KEYWORDS: Set[str] = {
    "urgent",
    "immediately",
    "right now",
    "today only",
    "expire",
    "last chance",
    "hurry",
    "quick",
    "asap",
    "deadline",
    "limited time",
    "act now",
    "don't delay",
    "time sensitive"
}

THREAT_KEYWORDS: Set[str] = {
    "account blocked",
    "account suspended",
    "account will be blocked",
    "legal action",
    "police complaint",
    "case filed",
    "arrest",
    "fine",
    "penalty",
    "blacklisted",
    "suspended",
    "terminated",
    "frozen",
    "disabled"
}

PAYMENT_KEYWORDS: Set[str] = {
    "upi",
    "upi id",
    "send money",
    "transfer",
    "payment",
    "pay now",
    "google pay",
    "phonepe",
    "paytm",
    "bhim",
    "bank transfer",
    "neft",
    "imps",
    "rtgs"
}

CREDENTIAL_KEYWORDS: Set[str] = {
    "otp",
    "password",
    "pin",
    "cvv",
    "card number",
    "atm pin",
    "bank details",
    "account number",
    "ifsc",
    "login",
    "verify",
    "confirm",
    "update kyc",
    "kyc update",
    "pan card",
    "aadhaar"
}

INDIA_SCAM_PATTERNS: Set[str] = {
    "verify immediately",
    "kyc pending",
    "kyc update",
    "bank suspend",
    "click link",
    "call this number",
    "customer care",
    "toll free",
    "refund pending",
    "cashback",
    "lottery winner",
    "prize money",
    "rbi notification",
    "income tax",
    "it department"
}


def get_all_scam_keywords() -> Set[str]:
    return (
        URGENCY_KEYWORDS |
        THREAT_KEYWORDS |
        PAYMENT_KEYWORDS |
        CREDENTIAL_KEYWORDS |
        INDIA_SCAM_PATTERNS
    )


def get_keyword_categories() -> dict:
    return {
        "urgency": URGENCY_KEYWORDS,
        "threat": THREAT_KEYWORDS,
        "payment": PAYMENT_KEYWORDS,
        "credential": CREDENTIAL_KEYWORDS,
        "india_scam": INDIA_SCAM_PATTERNS
    }
