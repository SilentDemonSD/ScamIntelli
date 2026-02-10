import re
from dataclasses import dataclass
from typing import Dict, FrozenSet, List, Optional
from urllib.parse import urlparse

import httpx
from contextlib import suppress


class ThreatType:
    PHISHING_URL = "phishing_url"
    HIDDEN_PHISHING = "hidden_phishing"
    LOOKALIKE_DOMAIN = "lookalike_domain"
    SUSPICIOUS_TLD = "suspicious_tld"
    MALICIOUS_QR_PAYLOAD = "malicious_qr_payload"
    SUSPICIOUS_DOCUMENT = "suspicious_document"


@dataclass(frozen=True)
class URLThreatResult:
    url: str
    threat_score: float
    threat_type: str
    indicators: List[str]
    expanded_url: Optional[str]


@dataclass(frozen=True)
class DocumentThreatResult:
    threats: List[URLThreatResult]
    overall_threat_score: float
    urls_analyzed: int
    phishing_urls_found: int
    suspicious_domains: List[str]
    intel_extracted: Dict[str, List[str]]


SUSPICIOUS_TLDS: FrozenSet[str] = frozenset(
    {".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".buzz",
     ".club", ".icu", ".work", ".click", ".link", ".info", ".online",
     ".site", ".store", ".fun", ".space", ".monster"}
)

URL_SHORTENERS: FrozenSet[str] = frozenset(
    {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
     "buff.ly", "rebrand.ly", "cutt.ly", "shorturl.at", "tiny.cc",
     "rb.gy", "shor.by", "v.gd", "short.io", "bitly.ws"}
)

LEGITIMATE_DOMAINS: Dict[str, FrozenSet[str]] = {
    "banking": frozenset(
        {"sbi.co.in", "onlinesbi.sbi", "hdfcbank.com", "icicibank.com",
         "axisbank.com", "kotak.com", "bankofbaroda.in", "pnbindia.in",
         "unionbankofindia.co.in", "canarabank.com", "rbi.org.in"}
    ),
    "payment": frozenset(
        {"paytm.com", "phonepe.com", "gpay.app", "bhimupi.org.in",
         "npci.org.in", "razorpay.com", "cashfree.com"}
    ),
    "government": frozenset(
        {"gov.in", "nic.in", "india.gov.in", "incometax.gov.in",
         "epfindia.gov.in", "uidai.gov.in", "cybercrime.gov.in"}
    ),
}

LOOKALIKE_TARGETS: Dict[str, FrozenSet[str]] = {
    "sbi": frozenset(
        {"sbi-online.net", "sbi-secure.com", "onlinesbi.org", "sbi-kyc.in",
         "sbi-update.com", "sbionline.xyz", "sbi-verify.com", "sbi-india.com",
         "sbi-alert.com", "sbi-bank.tk"}
    ),
    "hdfc": frozenset(
        {"hdfc-online.com", "hdfcbank-kyc.com", "hdfc-update.in",
         "hdfcbank.org", "hdfc-secure.com", "hdfc-verify.tk"}
    ),
    "icici": frozenset(
        {"icici-online.com", "icicibank-kyc.com", "icici-update.in",
         "icicibank.org", "icici-secure.net"}
    ),
    "paytm": frozenset(
        {"paytm-india.com", "paytm-kyc.com", "paytm-verify.in",
         "paytm-secure.com", "paytm-update.tk", "paytm-link.com"}
    ),
    "phonepe": frozenset(
        {"phonepe-kyc.com", "phonepe-verify.in", "phonepe-update.com",
         "phonepe-secure.net"}
    ),
    "rbi": frozenset(
        {"rbi-india.com", "rbi-gov.in", "rbi-notice.com",
         "rbi-alert.in", "reserve-bank.com"}
    ),
    "income_tax": frozenset(
        {"incometax-refund.com", "incometax-india.com", "it-refund.in",
         "income-tax-notice.com", "tax-refund.xyz"}
    ),
}

PHISHING_PATH_PATTERNS: FrozenSet[str] = frozenset(
    {"login", "verify", "secure", "update", "confirm", "validate",
     "account", "kyc", "otp", "reset", "unlock", "suspend",
     "reactivate", "restore", "claim", "prize", "winner",
     "refund", "cashback", "reward"}
)

HOMOGRAPH_MAP: Dict[str, str] = {
    "\u0430": "a", "\u0435": "e", "\u043e": "o", "\u0440": "p",
    "\u0441": "c", "\u0443": "y", "\u0445": "x", "\u0456": "i",
    "\u0455": "s", "\u0458": "j", "\u04bb": "h", "\u043a": "k",
    "\u043c": "m", "\u043d": "n", "\u0442": "t", "\u0432": "v",
    "\u0077\u0308": "w",
}

URL_PATTERN = re.compile(r'https?://[^\s<>"\'{}|\\^`\[\],]+', re.IGNORECASE)
DOMAIN_PATTERN = re.compile(r'^(?:https?://)?([^/:?#]+)')
IP_URL_PATTERN = re.compile(r'https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}')

URL_SCAM_RESPONSE_TEMPLATES = (
    "Link nahi khul raha... kya aap message mein hi details bata sakte ho?",
    "Sir link open nahi ho raha, aap phone pe bata do na details.",
    "Internet slow hai, link nahi load ho raha. Aap batao kya karna hai.",
    "Yeh link kaam nahi kar raha, koi aur tarika hai kya?",
    "Link mein virus aata hai kya? Mujhe dar lag raha hai click karne mein.",
    "Link pe click kiya toh kuch nahi hua, blank page aa raha hai.",
    "Bhai link se darr lagta hai, seedha bata do kya karna hai.",
    "Net pack khatam ho gaya, link nahi khulega. Aap call pe bata do.",
)


class URLThreatAnalyzer:

    @classmethod
    def extract_urls(cls, message: str) -> List[str]:
        return URL_PATTERN.findall(message)

    @classmethod
    def extract_domain(cls, url: str) -> str:
        with suppress(Exception):
            parsed = urlparse(url)
            return parsed.hostname or ""
        return ""

    @classmethod
    def get_tld(cls, domain: str) -> str:
        parts = domain.rsplit(".", 1)
        return f".{parts[-1]}" if len(parts) > 1 else ""

    @classmethod
    async def analyze_url(cls, url: str) -> URLThreatResult:
        indicators = []
        score = 0.0
        threat_type = ThreatType.PHISHING_URL
        expanded = None

        domain = cls.extract_domain(url)
        if not domain:
            return URLThreatResult(
                url=url, threat_score=0.0, threat_type="",
                indicators=[], expanded_url=None,
            )

        tld = cls.get_tld(domain)
        if tld in SUSPICIOUS_TLDS:
            score += 0.35
            indicators.append(f"suspicious_tld:{tld}")
            threat_type = ThreatType.SUSPICIOUS_TLD

        if cls._is_ip_url(url):
            score += 0.4
            indicators.append("ip_based_url")

        if cls._is_shortener(domain):
            expanded = await cls._expand_url(url)
            if expanded:
                expanded_domain = cls.extract_domain(expanded)
                expanded_tld = cls.get_tld(expanded_domain)
                if expanded_tld in SUSPICIOUS_TLDS:
                    score += 0.4
                    indicators.append(f"shortened_to_suspicious:{expanded_domain}")
                    threat_type = ThreatType.HIDDEN_PHISHING
                lookalike = cls._check_lookalike(expanded_domain)
                if lookalike:
                    score += 0.5
                    indicators.append(f"shortened_lookalike:{lookalike}")
                    threat_type = ThreatType.HIDDEN_PHISHING

        lookalike = cls._check_lookalike(domain)
        if lookalike:
            score += 0.55
            indicators.append(f"lookalike_domain:{lookalike}")
            threat_type = ThreatType.LOOKALIKE_DOMAIN

        homograph = cls._detect_homograph(domain)
        if homograph:
            score += 0.6
            indicators.append(f"homograph_attack:{homograph}")
            threat_type = ThreatType.LOOKALIKE_DOMAIN

        path_score = cls._analyze_path(url)
        if path_score > 0:
            score += path_score
            indicators.append("suspicious_path_keywords")

        if cls._has_excessive_subdomains(domain):
            score += 0.2
            indicators.append("excessive_subdomains")

        if cls._has_misleading_subdomain(domain):
            score += 0.3
            indicators.append("misleading_subdomain")

        return URLThreatResult(
            url=url,
            threat_score=min(score, 1.0),
            threat_type=threat_type if score >= 0.3 else "",
            indicators=indicators,
            expanded_url=expanded,
        )

    @classmethod
    def _is_ip_url(cls, url: str) -> bool:
        return bool(IP_URL_PATTERN.match(url))

    @classmethod
    def _is_shortener(cls, domain: str) -> bool:
        return domain.lower() in URL_SHORTENERS

    @classmethod
    async def _expand_url(cls, url: str) -> Optional[str]:
        with suppress(Exception):
            async with httpx.AsyncClient(
                timeout=5.0, follow_redirects=False, max_redirects=0
            ) as client:
                response = await client.head(url)
                if response.status_code in (301, 302, 303, 307, 308):
                    return response.headers.get("location")
        return None

    @classmethod
    def _check_lookalike(cls, domain: str) -> str:
        domain_lower = domain.lower()
        for brand, fakes in LOOKALIKE_TARGETS.items():
            if domain_lower in fakes:
                return brand
            for fake in fakes:
                if cls._levenshtein_distance(domain_lower, fake) <= 2:
                    return brand
        for category, legit_domains in LEGITIMATE_DOMAINS.items():
            for legit in legit_domains:
                base_legit = legit.split(".")[0]
                if (
                    base_legit in domain_lower
                    and domain_lower not in legit_domains
                    and len(domain_lower) > len(base_legit) + 4
                ):
                    return base_legit
        return ""

    @classmethod
    def _detect_homograph(cls, domain: str) -> str:
        normalized = ""
        has_homograph = False
        for char in domain:
            if char in HOMOGRAPH_MAP:
                normalized += HOMOGRAPH_MAP[char]
                has_homograph = True
            else:
                normalized += char
        return normalized if has_homograph else ""

    @classmethod
    def _analyze_path(cls, url: str) -> float:
        with suppress(Exception):
            parsed = urlparse(url)
            path_lower = parsed.path.lower() + "?" + (parsed.query or "").lower()
            matches = sum(1 for kw in PHISHING_PATH_PATTERNS if kw in path_lower)
            return min(matches * 0.15, 0.4)
        return 0.0

    @classmethod
    def _has_excessive_subdomains(cls, domain: str) -> bool:
        return domain.count(".") > 3

    @classmethod
    def _has_misleading_subdomain(cls, domain: str) -> bool:
        parts = domain.split(".")
        if len(parts) < 3:
            return False
        subdomain = ".".join(parts[:-2]).lower()
        bank_keywords = {"sbi", "hdfc", "icici", "axis", "kotak", "pnb",
                         "rbi", "paytm", "phonepe", "gpay", "upi", "npci",
                         "gov", "police", "court", "income", "tax"}
        return any(kw in subdomain for kw in bank_keywords)

    @classmethod
    def _levenshtein_distance(cls, s1: str, s2: str) -> int:
        if len(s1) < len(s2):
            return cls._levenshtein_distance(s2, s1)
        if len(s2) == 0:
            return len(s1)
        prev_row = list(range(len(s2) + 1))
        for i, c1 in enumerate(s1):
            curr_row = [i + 1]
            for j, c2 in enumerate(s2):
                insertions = prev_row[j + 1] + 1
                deletions = curr_row[j] + 1
                substitutions = prev_row[j] + (c1 != c2)
                curr_row.append(min(insertions, deletions, substitutions))
            prev_row = curr_row
        return prev_row[-1]


class MultiModalScamDetector:

    @classmethod
    async def analyze_message(cls, message: str) -> DocumentThreatResult:
        urls = URLThreatAnalyzer.extract_urls(message)
        threats = []
        suspicious_domains = []
        intel = {"phishing_urls": [], "expanded_urls": [], "suspicious_domains": []}

        for url in urls:
            result = await URLThreatAnalyzer.analyze_url(url)
            if result.threat_score >= 0.3:
                threats.append(result)
                domain = URLThreatAnalyzer.extract_domain(url)
                if domain:
                    suspicious_domains.append(domain)
                    intel["suspicious_domains"].append(domain)
                intel["phishing_urls"].append(url)
                if result.expanded_url:
                    intel["expanded_urls"].append(result.expanded_url)

        overall = max((t.threat_score for t in threats), default=0.0)

        return DocumentThreatResult(
            threats=threats,
            overall_threat_score=overall,
            urls_analyzed=len(urls),
            phishing_urls_found=len(threats),
            suspicious_domains=suspicious_domains,
            intel_extracted=intel,
        )

    @classmethod
    def get_url_avoidance_response(cls) -> str:
        import random
        return random.choice(URL_SCAM_RESPONSE_TEMPLATES)

    @classmethod
    def has_urls(cls, message: str) -> bool:
        return bool(URLThreatAnalyzer.extract_urls(message))
