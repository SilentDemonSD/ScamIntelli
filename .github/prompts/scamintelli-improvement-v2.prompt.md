# ScamIntelli Honeypot API Improvement Prompt - V2.0

## Mission Statement
You WILL transform the ScamIntelli honeypot API from a 75/100 scoring system to a 95+/100 elite-tier scam intelligence platform by addressing critical weaknesses in intelligence extraction, investigative questioning, red flag identification, conversation depth, documentation quality, and error handling.

## Current State Analysis

### Strengths ✅
- Scam detection: 20/20 points (excellent pattern recognition)
- Solid architecture: Hybrid 11-layer detection engine
- Good modular design with clear separation of concerns
- Comprehensive ML ensemble with 5 models

### Critical Weaknesses ❌
- Intelligence extraction: < 35/100 (CRITICAL)
- Question relevance: Minimal investigative probing (CRITICAL)
- Red flag identification: Detected but not actively probed (HIGH)
- Conversation engagement: Basic, lacks depth (HIGH)
- Documentation: Sparse inline comments (MEDIUM)
- Error handling: Too broad, insufficient recovery (MEDIUM)
- Agent notes: Lacks red flag details (MEDIUM)

### Target Score Breakdown (95+/100)
- Scam Detection: 20/20 ✅ (maintain current)
- Intelligence Extraction: 28-30/30 🎯 (must improve from < 10)
- Conversation Quality: 28-30/30 🎯 (must improve from ~15)
- Engagement Quality: 9-10/10 🎯 (maintain/improve)
- Response Structure: 10/10 ✅ (maintain current)

## Requirements

### Phase 1: Critical Intelligence Extraction Overhaul (PRIORITY 1)

#### 1.1 Expand Entity Extraction Coverage
You MUST add extraction support for ALL intelligence types mentioned in submission guidelines:

**MANDATORY: Update [src/intelligence_extractor/extractor.py](src/intelligence_extractor/extractor.py)**

You WILL add new extraction functions for missing entity types:

```python
async def extract_case_ids(message: str) -> List[str]:
    """Extract case/reference/complaint IDs from scammer messages.
    
    Patterns to match:
    - Case ID: CASE12345, CID-789, REF#ABC123
    - Complaint numbers: CMP2024-001, FIR/123/2024
    - Reference codes: REF123456, TRN-ABC-123
    - Investigation IDs: INV-2024-001, INVEST#123
    
    Returns:
        List of normalized case IDs found in message
    """
    # Pattern matching implementation here
    pass

async def extract_policy_numbers(message: str) -> List[str]:
    """Extract insurance/policy numbers from scammer messages.
    
    Patterns to match:
    - Policy numbers: POL123456789, POLICY-2024-ABC
    - Insurance IDs: INS/12345/2024, LIC-123456
    - Claim numbers: CLM-2024-001, CLAIM#123456
    
    Returns:
        List of normalized policy numbers
    """
    pass

async def extract_order_numbers(message: str) -> List[str]:
    """Extract order/transaction/tracking IDs.
    
    Patterns to match:
    - Order IDs: ORD123456, ORDER-2024-ABC
    - Tracking numbers: TRK123456789, AWB-123-456
    - Transaction IDs: TXN20240115123, TRANS#12345
    - Shipment IDs: SHP-2024-001, SHIP#123456
    
    Returns:
        List of normalized order numbers
    """
    pass

async def extract_organization_names(message: str) -> List[str]:
    """Extract company/organization/department names mentioned by scammer.
    
    Patterns to detect:
    - Bank names: SBI, HDFC, ICICI, Axis Bank
    - Government agencies: CBI, ED, Income Tax, Customs
    - Companies: Amazon, Flipkart, PayTM, PhonePe
    - Departments: Fraud Department, KYC Department, Security Team
    
    Returns:
        List of organization names
    """
    pass

async def extract_addresses(message: str) -> List[str]:
    """Extract physical addresses, office locations, or websites.
    
    Patterns:
    - Office addresses with street/city/pin
    - Website URLs (already covered by extract_links, but refine)
    - Branch locations
    
    Returns:
        List of address strings
    """
    pass
```

**MANDATORY: Update [src/models.py](src/models.py) ExtractedIntelligence model:**

```python
@dataclass
class ExtractedIntelligence:
    upi_ids: List[str] = field(default_factory=list)
    phone_numbers: List[str] = field(default_factory=list)
    phishing_links: List[str] = field(default_factory=list)
    bank_accounts: List[str] = field(default_factory=list)
    email_addresses: List[str] = field(default_factory=list)
    suspicious_keywords: List[str] = field(default_factory=list)
    # NEW FIELDS - You MUST add these:
    case_ids: List[str] = field(default_factory=list)
    policy_numbers: List[str] = field(default_factory=list)
    order_numbers: List[str] = field(default_factory=list)
    organization_names: List[str] = field(default_factory=list)
    addresses: List[str] = field(default_factory=list)
    employee_ids: List[str] = field(default_factory=list)  # For impersonation detection
    names_mentioned: List[str] = field(default_factory=list)  # Scammer names/aliases
```

#### 1.2 Comprehensive Extraction Integration
**MANDATORY: Update extract_all_intelligence() function:**

You MUST integrate ALL new extraction functions into the main extraction pipeline with proper error handling:

```python
async def extract_all_intelligence(
    message: str, existing: ExtractedIntelligence
) -> ExtractedIntelligence:
    """Extract ALL intelligence entities from message, merging with existing intel.
    
    Now extracts: UPI IDs, phones, links, banks, emails, keywords, case IDs,
    policy numbers, order numbers, organizations, addresses, employee IDs, names.
    
    Each extraction wrapped in try/except for resilience.
    """
    # Existing extractions (keep all current code)
    emails = []
    upi_ids = []
    # ... (keep existing code)
    
    # NEW EXTRACTIONS - You MUST add these with error handling:
    case_ids: List[str] = []
    try:
        case_ids = await extract_case_ids(message)
    except Exception:
        logger.exception("Case ID extraction failed; continuing with empty list")
    
    policy_numbers: List[str] = []
    try:
        policy_numbers = await extract_policy_numbers(message)
    except Exception:
        logger.exception("Policy number extraction failed; continuing")
    
    # ... (add all new extractions with similar error handling)
    
    return ExtractedIntelligence(
        # Existing fields
        upi_ids=list(set(existing.upi_ids + upi_ids)),
        # ... (keep all existing)
        
        # NEW FIELDS - You MUST add these merges:
        case_ids=list(set(existing.case_ids + case_ids)),
        policy_numbers=list(set(existing.policy_numbers + policy_numbers)),
        order_numbers=list(set(existing.order_numbers + order_numbers)),
        organization_names=list(set(existing.organization_names + org_names)),
        addresses=list(set(existing.addresses + addresses)),
        employee_ids=list(set(existing.employee_ids + emp_ids)),
        names_mentioned=list(set(existing.names_mentioned + names)),
    )
```

### Phase 2: Advanced Investigative Questioning System (PRIORITY 1)

#### 2.1 Investigative Question Framework
**MANDATORY: Create new file [src/agent_controller/question_engine.py](src/agent_controller/question_engine.py):**

```python
"""
Advanced investigative questioning engine for honeypot intelligence extraction.

This module generates contextually-relevant, targeted questions designed to elicit
maximum intelligence from scammers while maintaining persona believability.
"""

from dataclasses import dataclass
from enum import Enum
from typing import Dict, List, Optional, Tuple
import random

from src.models import ExtractedIntelligence, SessionState
from src.scam_detector.scam_types import ScamCategory


class QuestionType(str, Enum):
    """Categories of investigative questions."""
    IDENTITY_VERIFICATION = "identity_verification"  # Who are you? ID? Badge number?
    ORGANIZATION_DETAILS = "organization_details"    # Company name, branch, address?
    CONTACT_VERIFICATION = "contact_verification"    # Callback number, email, website?
    PROCESS_VERIFICATION = "process_verification"    # How does this work? Steps?
    AUTHORITY_CHALLENGE = "authority_challenge"      # How do I verify you're real?
    TIME_STALLING = "time_stalling"                  # Can I do this later? Tomorrow?
    PAYMENT_CLARIFICATION = "payment_clarification"  # Why pay? How much? Refundable?
    TECHNICAL_CONFUSION = "technical_confusion"      # How to do X? Don't understand Y?


@dataclass
class InvestigativeQuestion:
    """Structured investigative question with metadata."""
    question_text: str
    question_type: QuestionType
    target_intelligence: List[str]  # What intel this question aims to extract
    priority: int  # 1-10, higher = more important
    scam_categories: List[ScamCategory]  # Which scam types this applies to
    turn_range: Tuple[int, int]  # (min_turn, max_turn) when to ask
    
    
class QuestionBank:
    """
    Comprehensive bank of investigative questions organized by type and category.
    
    Questions designed to:
    1. Extract maximum intelligence (phone, UPI, organization, address)
    2. Keep scammer engaged and talking
    3. Identify red flags through answers
    4. Maintain persona believability
    """
    
    IDENTITY_QUESTIONS = {
        ScamCategory.DIGITAL_ARREST: [
            InvestigativeQuestion(
                question_text="Sir aapka naam kya hai? Badge number ya ID number bhi batao, main note kar leta hun.",
                question_type=QuestionType.IDENTITY_VERIFICATION,
                target_intelligence=["names_mentioned", "employee_ids"],
                priority=9,
                scam_categories=[ScamCategory.DIGITAL_ARREST],
                turn_range=(2, 6)
            ),
            InvestigativeQuestion(
                question_text="Sir aap kis police station se bol rahe hain? Station ka address bata do.",
                question_type=QuestionType.ORGANIZATION_DETAILS,
                target_intelligence=["organization_names", "addresses"],
                priority=8,
                scam_categories=[ScamCategory.DIGITAL_ARREST],
                turn_range=(3, 7)
            ),
            InvestigativeQuestion(
                question_text="Main aapke senior officer se baat kar sakta hun? Unka direct number de do.",
                question_type=QuestionType.CONTACT_VERIFICATION,
                target_intelligence=["phone_numbers"],
                priority=10,
                scam_categories=[ScamCategory.DIGITAL_ARREST],
                turn_range=(4, 8)
            ),
        ],
        ScamCategory.KYC_PHISHING: [
            InvestigativeQuestion(
                question_text="Sir aap bank ke kis department se call kar rahe hain? Department ka naam batao.",
                question_type=QuestionType.ORGANIZATION_DETAILS,
                target_intelligence=["organization_names"],
                priority=8,
                scam_categories=[ScamCategory.KYC_PHISHING],
                turn_range=(2, 5)
            ),
            InvestigativeQuestion(
                question_text="Aapka employee ID kya hai? Main verification ke liye note kar leta hun.",
                question_type=QuestionType.IDENTITY_VERIFICATION,
                target_intelligence=["employee_ids"],
                priority=7,
                scam_categories=[ScamCategory.KYC_PHISHING],
                turn_range=(3, 6)
            ),
            InvestigativeQuestion(
                question_text="Bank ka official website kya hai? Main online check kar leta hun KYC status.",
                question_type=QuestionType.CONTACT_VERIFICATION,
                target_intelligence=["phishing_links"],
                priority=9,
                scam_categories=[ScamCategory.KYC_PHISHING],
                turn_range=(2, 5)
            ),
        ],
        # ADD ALL OTHER SCAM CATEGORIES: INVESTMENT_FRAUD, JOB_SCAM, etc.
        # You MUST create 8-12 questions per category
    }
    
    GENERAL_INVESTIGATIVE_QUESTIONS = [
        InvestigativeQuestion(
            question_text="Sir, aapka contact number kya hai? Agar call disconnect ho jaye toh main wapas call karunga.",
            question_type=QuestionType.CONTACT_VERIFICATION,
            target_intelligence=["phone_numbers"],
            priority=10,
            scam_categories=[],  # Applies to all
            turn_range=(2, 10)
        ),
        InvestigativeQuestion(
            question_text="Company ka registered office kahan hai? Address batao, main samajh jaunga trustworthy hai.",
            question_type=QuestionType.ORGANIZATION_DETAILS,
            target_intelligence=["addresses", "organization_names"],
            priority=8,
            scam_categories=[],
            turn_range=(3, 8)
        ),
        # ADD 15-20 MORE GENERAL QUESTIONS
    ]
    
    PROBING_FOLLOWUPS = {
        "phone_mentioned": [
            "Sir yeh number WhatsApp pe available hai? Main wahan pe bhi message kar sakta hun.",
            "Yeh aapka direct number hai ya office landline? Aapka personal number de do backup ke liye.",
            "Sir agar urgent ho toh kaunsa number pe call karun - yeh wala ya koi aur?",
        ],
        "upi_mentioned": [
            "Sir yeh UPI ID registered kaunse bank se hai? Main cross-verify kar leta hun.",
            "UPI ID pe payment limit kitni hai? Full amount ek baar mein ho jayega?",
            "Sir yeh UPI aapke naam pe hai ya company ke naam pe registered hai?",
        ],
        "link_mentioned": [
            "Sir yeh link open nahi ho raha. Koi alternate link hai?",
            "Yeh website secure hai na? HTTPS wala? Main check karna chahta hun.",
            "Sir is link ka domain name kya hai? Main apne tech-savvy friend se confirm karunga.",
        ],
        "organization_mentioned": [
            "Sir aapki company ka GST number kya hai? Main verify kar leta hun.",
            "Company ka customer care number kya hai official? Main call karke confirm karunga.",
            "Aapki company ka social media page hai? Facebook ya LinkedIn pe check kar leta hun.",
        ],
    }
    
    @classmethod
    def get_questions_for_category(
        cls, 
        scam_category: ScamCategory, 
        turn_count: int,
        extracted_intel: ExtractedIntelligence,
    ) -> List[InvestigativeQuestion]:
        """
        Get relevant investigative questions for current scam type and turn.
        
        Args:
            scam_category: Detected scam type
            turn_count: Current conversation turn number
            extracted_intel: Already extracted intelligence (to avoid redundant questions)
            
        Returns:
            List of applicable questions, sorted by priority
        """
        applicable = []
        
        # Get category-specific questions
        category_questions = cls.IDENTITY_QUESTIONS.get(scam_category, [])
        for q in category_questions:
            if q.turn_range[0] <= turn_count <= q.turn_range[1]:
                # Check if we still need this intelligence type
                if cls._should_ask_question(q, extracted_intel):
                    applicable.append(q)
        
        # Add general questions
        for q in cls.GENERAL_INVESTIGATIVE_QUESTIONS:
            if q.turn_range[0] <= turn_count <= q.turn_range[1]:
                if cls._should_ask_question(q, extracted_intel):
                    applicable.append(q)
        
        # Sort by priority (descending)
        applicable.sort(key=lambda x: x.priority, reverse=True)
        return applicable
    
    @classmethod
    def _should_ask_question(
        cls, 
        question: InvestigativeQuestion, 
        intel: ExtractedIntelligence
    ) -> bool:
        """Determine if we should ask this question based on already extracted intel."""
        # If question targets phone and we already have 2+ phones, skip
        if "phone_numbers" in question.target_intelligence:
            if len(intel.phone_numbers) >= 2:
                return False
        
        # If question targets UPI and we have 1+ UPI IDs, lower priority but still ask
        if "upi_ids" in question.target_intelligence:
            if len(intel.upi_ids) >= 2:
                return False
        
        # If we have no organization names, prioritize org questions
        if "organization_names" in question.target_intelligence:
            if len(intel.organization_names) == 0:
                return True  # High priority
        
        # Similar logic for other intel types
        return True
    
    @classmethod
    def get_probing_followup(
        cls, 
        entity_type: str, 
        entity_value: str,
        recent_messages: List[Dict]
    ) -> Optional[str]:
        """
        Generate a probing follow-up question when a specific entity is detected.
        
        Args:
            entity_type: "phone_mentioned", "upi_mentioned", etc.
            entity_value: The actual value (phone number, UPI ID, etc.)
            recent_messages: Recent conversation to avoid repeating questions
            
        Returns:
            Follow-up question string or None
        """
        followups = cls.PROBING_FOLLOWUPS.get(entity_type, [])
        if not followups:
            return None
        
        # Filter out questions we've already asked
        recent_agent_msgs = [
            m.get("content", "").lower() 
            for m in recent_messages[-5:] 
            if m.get("role") == "agent"
        ]
        
        available = [
            q for q in followups 
            if not any(fragment in agent_msg for fragment in q.lower().split() for agent_msg in recent_agent_msgs)
        ]
        
        return random.choice(available) if available else None


class IntelligenceExtractionPlanner:
    """
    Strategic planner for intelligence extraction across conversation turns.
    
    Determines:
    1. Which intelligence types are highest priority based on scam category
    2. Optimal turn timing for each question type
    3. When to probe vs when to stall vs when to comply
    """
    
    EXTRACTION_PRIORITY_MAP = {
        ScamCategory.DIGITAL_ARREST: [
            ("phone_numbers", 10),
            ("employee_ids", 9),
            ("organization_names", 9),
            ("addresses", 8),
            ("case_ids", 8),
            ("names_mentioned", 7),
            ("bank_accounts", 6),
        ],
        ScamCategory.KYC_PHISHING: [
            ("phishing_links", 10),
            ("phone_numbers", 9),
            ("organization_names", 8),
            ("employee_ids", 7),
            ("upi_ids", 6),
        ],
        # ADD ALL SCAM CATEGORIES
    }
    
    @classmethod
    def get_extraction_strategy(
        cls,
        scam_category: ScamCategory,
        turn_count: int,
        extracted_intel: ExtractedIntelligence,
    ) -> Dict[str, any]:
        """
        Get strategic extraction plan for current turn.
        
        Returns:
            {
                "primary_target": "phone_numbers",
                "secondary_targets": ["employee_ids", "organization_names"],
                "recommended_question_type": QuestionType.CONTACT_VERIFICATION,
                "urgency_level": "high",  # high/medium/low
            }
        """
        priorities = cls.EXTRACTION_PRIORITY_MAP.get(
            scam_category, 
            [("phone_numbers", 10), ("upi_ids", 9)]
        )
        
        # Find highest priority missing intel
        for intel_type, priority in priorities:
            intel_list = getattr(extracted_intel, intel_type, [])
            if len(intel_list) == 0:
                # This is our primary target
                return {
                    "primary_target": intel_type,
                    "secondary_targets": [t for t, p in priorities[1:3] if t != intel_type],
                    "recommended_question_type": cls._map_intel_to_question_type(intel_type),
                    "urgency_level": "high" if priority >= 9 else "medium",
                }
        
        # If we have basic intel, go for secondary targets
        return {
            "primary_target": priorities[0][0] if priorities else "phone_numbers",
            "secondary_targets": [t for t, p in priorities[1:3]],
            "recommended_question_type": QuestionType.ORGANIZATION_DETAILS,
            "urgency_level": "low",
        }
    
    @classmethod
    def _map_intel_to_question_type(cls, intel_type: str) -> QuestionType:
        """Map intelligence type to appropriate question type."""
        mapping = {
            "phone_numbers": QuestionType.CONTACT_VERIFICATION,
            "upi_ids": QuestionType.PAYMENT_CLARIFICATION,
            "employee_ids": QuestionType.IDENTITY_VERIFICATION,
            "organization_names": QuestionType.ORGANIZATION_DETAILS,
            "addresses": QuestionType.ORGANIZATION_DETAILS,
            "phishing_links": QuestionType.CONTACT_VERIFICATION,
        }
        return mapping.get(intel_type, QuestionType.IDENTITY_VERIFICATION)


# You MUST add comprehensive docstrings to ALL functions
# You MUST add inline comments explaining complex logic
# You MUST add type hints to ALL parameters and returns
```

#### 2.2 Integrate Question Engine into Strategy
**MANDATORY: Update [src/agent_controller/strategy.py](src/agent_controller/strategy.py)**

You MUST replace the existing `_get_intel_extraction_question()` function with the new question engine:

Find this section (around line 540-550 in strategy.py):
```python
        if session.scam_detected and session.engagement_active:
            # Use context-aware probe when confidence is high enough
            probe = make_context_aware_probe(
                session.messages,
                session.extracted_intel,
                confidence=_conf,
            )
            if probe and _conf >= 0.5:
                reply_text = f"{reply_text} {probe}"
            else:
                intel_question = _get_intel_extraction_question(
                    session.turn_count, session.extracted_intel
                )
                if intel_question:
                    reply_text = f"{reply_text} {intel_question}"
```

Replace with:
```python
        if session.scam_detected and session.engagement_active:
            from src.agent_controller.question_engine import (
                QuestionBank, 
                IntelligenceExtractionPlanner
            )
            
            # Get strategic extraction plan
            scam_cat = _ensure_scam_category(session.scam_category)
            extraction_strategy = IntelligenceExtractionPlanner.get_extraction_strategy(
                scam_cat,
                session.turn_count,
                session.extracted_intel
            )
            
            # Get applicable investigative questions
            questions = QuestionBank.get_questions_for_category(
                scam_cat,
                session.turn_count,
                session.extracted_intel
            )
            
            # If we have high-priority questions, append one to response
            if questions and session.turn_count >= 2:
                selected_question = questions[0]  # Highest priority
                reply_text = f"{reply_text} {selected_question.question_text}"
                
                # Log what we're trying to extract
                logger.info(
                    f"Session {session.session_id} turn {session.turn_count}: "
                    f"Asking {selected_question.question_type.value} question "
                    f"targeting {selected_question.target_intelligence}"
                )
            
            # Also add probing follow-ups if recent intel was detected
            if session.turn_count >= 3:
                # Check if scammer just shared something valuable
                last_msg = session.messages[-2] if len(session.messages) >= 2 else None
                if last_msg and last_msg.get("role") in ("user", "scammer"):
                    last_content = last_msg.get("content", "")
                    
                    # Check for new entities in last message
                    if len(session.extracted_intel.phone_numbers) > 0:
                        followup = QuestionBank.get_probing_followup(
                            "phone_mentioned",
                            session.extracted_intel.phone_numbers[-1],
                            session.messages
                        )
                        if followup and len(reply_text.split()) < 40:  # Don't make response too long
                            reply_text = f"{reply_text} {followup}"
```

### Phase 3: Red Flag Identification and Probing (PRIORITY 2)

#### 3.1 Enhanced Red Flag Tracking
**MANDATORY: Create new file [src/agent_controller/red_flag_tracker.py](src/agent_controller/red_flag_tracker.py)**

```python
"""
Red flag detection, tracking, and probing system.

Maintains a running tally of scam indicators and generates targeted
questions to probe suspicious behaviors.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Dict, List, Optional
import logging

from src.models import SessionState

logger = logging.getLogger(__name__)


class RedFlagType(str, Enum):
    """Categories of red flags in scam conversations."""
    URGENCY_PRESSURE = "urgency_pressure"          # "Do it NOW" language
    THREAT_INTIMIDATION = "threat_intimidation"    # Arrest, legal action threats
    CREDENTIAL_REQUEST = "credential_request"      # Asking for OTP, PIN, password
    PAYMENT_DEMAND = "payment_demand"              # Requesting money transfer
    AUTHORITY_CLAIM = "authority_claim"            # Claiming to be police, bank, govt
    VERIFICATION_AVOIDANCE = "verification_avoidance"  # Refusing to provide verification
    PROCESS_IRREGULARITY = "process_irregularity"  # Unusual process (QR to receive money)
    SECRECY_DEMAND = "secrecy_demand"              # "Don't tell anyone"
    PERSONAL_INFO_PROBE = "personal_info_probe"    # Asking too many personal questions
    LINK_PRESSURE = "link_pressure"                # Forcing to click unknown links
    TRUST_BUILDING = "trust_building"              # Fake credentials, false reassurance
    TIME_CONSTRAINT = "time_constraint"            # Limited time offers, expiring deals


@dataclass
class RedFlagInstance:
    """Single occurrence of a red flag."""
    flag_type: RedFlagType
    turn_number: int
    message_content: str  # The specific phrase that triggered flag
    confidence: float  # 0.0 to 1.0
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    
    def to_dict(self) -> Dict:
        """Convert to dictionary for logging/storage."""
        return {
            "flag_type": self.flag_type.value,
            "turn": self.turn_number,
            "content_snippet": self.message_content[:100],
            "confidence": self.confidence,
            "timestamp": self.timestamp.isoformat(),
        }


class RedFlagDetector:
    """
    Detects red flags in scammer messages using keyword analysis and patterns.
    
    Goes beyond basic keyword matching to identify behavioral patterns
    that indicate scam tactics.
    """
    
    RED_FLAG_PATTERNS = {
        RedFlagType.URGENCY_PRESSURE: {
            "keywords": [
                "urgent", "immediately", "right now", "abhi", "turant", "jaldi",
                "fast", "quickly", "hurry", "don't delay", "time is running",
                "avi", "ek minute mein", "2 minutes", "5 minutes",
            ],
            "phrases": [
                "do it now or",
                "you have only",
                "last chance",
                "time running out",
                "before it's too late",
                "aakhri mauka",
            ],
            "confidence_base": 0.8,
        },
        RedFlagType.THREAT_INTIMIDATION: {
            "keywords": [
                "arrest", "police", "jail", "court", "legal action", "fir",
                "warrant", "case", "investigation", "cybercrime", "ed notice",
                "income tax raid", "customs seizure", "blocked", "suspended",
                "frozen account", "criminal case", "chargesheet",
            ],
            "phrases": [
                "arrest warrant issued",
                "police will come",
                "legal notice sent",
                "account will be blocked",
                "you'll go to jail",
                "gir dange andar",
            ],
            "confidence_base": 0.9,
        },
        RedFlagType.CREDENTIAL_REQUEST: {
            "keywords": [
                "otp", "pin", "password", "cvv", "card number", "atm pin",
                "mpin", "passcode", "security code", "verification code",
            ],
            "phrases": [
                "share your otp",
                "send otp",
                "tell me the otp",
                "otp batao",
                "otp bhejo",
                "provide your pin",
                "enter your password",
            ],
            "confidence_base": 0.95,
        },
        # ADD ALL RED FLAG TYPES - You MUST define patterns for all 12 types
    }
    
    @classmethod
    def detect_red_flags(
        cls, 
        message: str, 
        turn_number: int,
        conversation_history: List[Dict] = None
    ) -> List[RedFlagInstance]:
        """
        Analyze message for red flag indicators.
        
        Args:
            message: Scammer's message text
            turn_number: Current turn in conversation
            conversation_history: Previous messages for context
            
        Returns:
            List of detected red flag instances
        """
        detected_flags = []
        message_lower = message.lower()
        
        for flag_type, patterns in cls.RED_FLAG_PATTERNS.items():
            confidence = 0.0
            matched_content = []
            
            # Keyword matching
            keywords = patterns.get("keywords", [])
            matched_keywords = [kw for kw in keywords if kw in message_lower]
            if matched_keywords:
                confidence += len(matched_keywords) * 0.15
                matched_content.extend(matched_keywords)
            
            # Phrase matching (higher weight)
            phrases = patterns.get("phrases", [])
            matched_phrases = [ph for ph in phrases if ph in message_lower]
            if matched_phrases:
                confidence += len(matched_phrases) * 0.3
                matched_content.extend(matched_phrases)
            
            # Apply base confidence
            if confidence > 0:
                confidence = min(confidence, 1.0) * patterns.get("confidence_base", 0.7)
                
                # Create flag instance if confidence threshold met
                if confidence >= 0.3:
                    flag = RedFlagInstance(
                        flag_type=flag_type,
                        turn_number=turn_number,
                        message_content=" | ".join(matched_content),
                        confidence=confidence
                    )
                    detected_flags.append(flag)
                    
                    logger.info(
                        f"Turn {turn_number}: Detected red flag {flag_type.value} "
                        f"with confidence {confidence:.2f}"
                    )
        
        return detected_flags
    
    @classmethod
    def analyze_behavioral_escalation(
        cls, 
        conversation_history: List[Dict]
    ) -> Dict[str, any]:
        """
        Analyze conversation for escalating scam tactics over time.
        
        Returns:
            {
                "escalation_detected": bool,
                "escalation_speed": "slow" | "moderate" | "rapid",
                "pressure_increasing": bool,
                "tactics_changing": bool,
            }
        """
        if len(conversation_history) < 4:
            return {
                "escalation_detected": False,
                "escalation_speed": "none",
                "pressure_increasing": False,
                "tactics_changing": False,
            }
        
        # Analyze urgency keywords over time
        urgency_keywords = ["urgent", "immediate", "now", "jaldi", "turant"]
        
        first_half = conversation_history[:len(conversation_history)//2]
        second_half = conversation_history[len(conversation_history)//2:]
        
        urgency_first = sum(
            1 for msg in first_half 
            if msg.get("role") in ("user", "scammer") 
            and any(kw in msg.get("content", "").lower() for kw in urgency_keywords)
        )
        
        urgency_second = sum(
            1 for msg in second_half
            if msg.get("role") in ("user", "scammer")
            and any(kw in msg.get("content", "").lower() for kw in urgency_keywords)
        )
        
        pressure_increasing = urgency_second > urgency_first
        escalation_detected = pressure_increasing
        
        if urgency_second >= urgency_first * 2:
            escalation_speed = "rapid"
        elif urgency_second > urgency_first:
            escalation_speed = "moderate"
        else:
            escalation_speed = "slow"
        
        return {
            "escalation_detected": escalation_detected,
            "escalation_speed": escalation_speed,
            "pressure_increasing": pressure_increasing,
            "tactics_changing": escalation_detected,  # Simplified for now
        }


class RedFlagProber:
    """
    Generates questions to probe and expose red flags.
    
    When a red flag is detected, this generates follow-up questions
    that challenge the scammer's claims and extract more intelligence.
    """
    
    PROBING_QUESTIONS = {
        RedFlagType.URGENCY_PRESSURE: [
            "Sir itni jaldi kyun hai? Main abhi busy hun, kal kar sakta hun?",
            "Aap bol rahe urgent hai, but normally yeh process kitne din leta hai?",
            "Sir agar main 1 ghante baad karun toh bhi chalega na? Abhi thoda busy hun.",
            "Itni urgent baat hai toh aap personally office kyun nahi aa rahe?",
        ],
        RedFlagType.THREAT_INTIMIDATION: [
            "Sir aap threat de rahe ho, main lawyer se baat kar sakta hun?",
            "Police warrant ke liye court se order aata hai, aapke paas document hai?",
            "Agar legal matter hai toh written notice bhejo pehle, proper process follow karo.",
            "Main thana mein directly jaake FIR check karunga, station ka address do.",
        ],
        RedFlagType.CREDENTIAL_REQUEST: [
            "Sir OTP toh confidential hota hai, bank bhi bolti hai mat share karo. Aap kyun maang rahe ho?",
            "Mujhe pata hai OTP kabhi kisi ko nahi batana chahiye. Aap genuine ho toh alternate method batao.",
            "PIN share karne se account hack ho sakta hai. Koi aur verification process hai?",
        ],
        RedFlagType.AUTHORITY_CLAIM: [
            "Sir aapka employee ID number kya hai? Main bank mein call karke verify karunga.",
            "Police wale toh uniform mein personally aate hain, phone pe kyun bol rahe ho?",
            "Government officer ho toh official email se notice bhejo, proof chahiye.",
            "Aapka officer name aur designation batao, main Google pe department search karunga.",
        ],
        # ADD PROBING QUESTIONS FOR ALL RED FLAG TYPES
    }
    
    @classmethod
    def generate_probing_question(
        cls,
        red_flags: List[RedFlagInstance],
        turn_number: int,
        already_asked: List[str] = None
    ) -> Optional[str]:
        """
        Generate a question that challenges the most serious red flag.
        
        Args:
            red_flags: Detected red flags in recent messages
            turn_number: Current conversation turn
            already_asked: Questions already asked (to avoid repetition)
            
        Returns:
            Probing question string or None
        """
        if not red_flags:
            return None
        
        # Sort by confidence, highest first
        red_flags_sorted = sorted(red_flags, key=lambda f: f.confidence, reverse=True)
        
        already_asked = already_asked or []
        
        # Try each red flag type until we find an unasked question
        for flag in red_flags_sorted:
            questions = cls.PROBING_QUESTIONS.get(flag.flag_type, [])
            
            # Filter out already asked
            available = [
                q for q in questions
                if not any(
                    asked_fragment in q.lower() 
                    for asked_fragment in [a.lower() for a in already_asked]
                )
            ]
            
            if available:
                import random
                return random.choice(available)
        
        return None
    
    @classmethod
    def should_probe_now(
        cls,
        red_flags: List[RedFlagInstance],
        turn_number: int,
        total_red_flags_session: int
    ) -> bool:
        """
        Decide if we should ask a probing question this turn.
        
        Strategy:
        - Probe after 2-3 turns of initial rapport
        - Probe more aggressively if multiple red flags detected
        - Don't probe every turn (maintain believability)
        """
        if turn_number <= 2:
            return False  # Build rapport first
        
        if len(red_flags) >= 2:
            return True  # Multiple flags in one message = probe immediately
        
        if total_red_flags_session >= 5 and turn_number >= 5:
            return True  # Pattern of red flags = challenge them
        
        # Probe 30-40% of the time when red flags present
        import random
        return random.random() < 0.35
```

#### 3.2 Integrate Red Flag Tracker into Strategy
**MANDATORY: Update [src/agent_controller/strategy.py](src/agent_controller/strategy.py)**

Add red flag tracking to the main message processing:

```python
# Add near the imports:
from src.agent_controller.red_flag_tracker import (
    RedFlagDetector,
    RedFlagProber,
    RedFlagInstance
)

# Add to SessionState model in src/models.py:
@dataclass
class SessionState:
    # ... existing fields ...
    
    # NEW FIELD - You MUST add this:
    red_flags_detected: List[Dict] = field(default_factory=list)  # Store all red flags
    
# In _process_message_inner(), after scam detection:
    if is_scam or session.scam_detected:
        # Detect red flags in this message
        detected_flags = RedFlagDetector.detect_red_flags(
            message,
            session.turn_count,
            session.messages
        )
        
        # Store red flags
        for flag in detected_flags:
            session.red_flags_detected.append(flag.to_dict())
            logger.info(
                f"Session {session.session_id}: Red flag {flag.flag_type.value} "
                f"detected with confidence {flag.confidence:.2f}"
            )
        
        # Analyze behavioral escalation
        escalation = RedFlagDetector.analyze_behavioral_escalation(session.messages)
        if escalation["escalation_detected"]:
            logger.warning(
                f"Session {session.session_id}: Escalation detected - "
                f"speed: {escalation['escalation_speed']}, "
                f"pressure increasing: {escalation['pressure_increasing']}"
            )

# Later in response generation section, add probing:
        if session.scam_detected and session.engagement_active:
            # ... existing question generation code ...
            
            # ADD RED FLAG PROBING:
            # Check if we should probe red flags
            recent_flags = [
                RedFlagInstance(**f) for f in session.red_flags_detected[-3:]
            ]
            
            already_asked_questions = [
                m.get("content", "") 
                for m in session.messages 
                if m.get("role") == "agent"
            ]
            
            should_probe = RedFlagProber.should_probe_now(
                recent_flags,
                session.turn_count,
                len(session.red_flags_detected)
            )
            
            if should_probe and session.turn_count >= 3:
                probing_q = RedFlagProber.generate_probing_question(
                    recent_flags,
                    session.turn_count,
                    already_asked_questions
                )
                
                if probing_q:
                    reply_text = f"{reply_text} {probing_q}"
                    logger.info(
                        f"Session {session.session_id} turn {session.turn_count}: "
                        f"Adding red flag probing question"
                    )
```

### Phase 4: Enhanced Agent Notes with Red Flags (PRIORITY 2)

#### 4.1 Update Agent Notes Generation
**MANDATORY: Update [src/agent_controller/agent_state.py](src/agent_controller/agent_state.py)**

Enhance the `generate_agent_notes()` function to include comprehensive red flag details:

```python
async def generate_agent_notes(session: SessionState) -> str:
    """
    Generate comprehensive agent notes for final output submission.
    
    Now includes:
    - Scam type and category
    - Engagement metrics
    - Extracted intelligence summary
    - RED FLAGS IDENTIFIED (NEW)
    - Scammer tactics analysis
    - Risk assessment
    - Behavioral patterns
    
    Args:
        session: Current session state with all conversation data
        
    Returns:
        Detailed notes string for finalOutput.agentNotes field
    """
    notes_parts = []
    intel = session.extracted_intel

    # Scam type
    scam_type = _detect_scam_category(intel.suspicious_keywords)
    if scam_type:
        notes_parts.append(f"Scam Type: {scam_type}")
    
    if session.scam_category:
        notes_parts.append(f"Category: {session.scam_category}")

    # Engagement metrics
    notes_parts.append(f"Engagement: {session.turn_count} exchanges")
    
    # Calculate engagement duration if timestamps available
    if len(session.messages) >= 2:
        try:
            first_ts = datetime.fromisoformat(session.messages[0].get("timestamp"))
            last_ts = datetime.fromisoformat(session.messages[-1].get("timestamp"))
            duration_sec = (last_ts - first_ts).total_seconds()
            notes_parts.append(f"Duration: {int(duration_sec)}s")
        except:
            pass

    # Intelligence summary
    intel_items = []
    if intel.upi_ids:
        intel_items.append(f"UPI: {', '.join(intel.upi_ids[:3])}")
    if intel.bank_accounts:
        intel_items.append(f"Accounts: {', '.join(intel.bank_accounts[:2])}")
    if intel.phone_numbers:
        intel_items.append(f"Phones: {', '.join(intel.phone_numbers[:3])}")
    if intel.phishing_links:
        intel_items.append(f"Links: {len(intel.phishing_links)}")
    if intel.email_addresses:
        intel_items.append(f"Emails: {', '.join(intel.email_addresses[:2])}")
    # NEW INTEL TYPES:
    if intel.case_ids:
        intel_items.append(f"Case IDs: {', '.join(intel.case_ids[:2])}")
    if intel.organization_names:
        intel_items.append(f"Organizations: {', '.join(intel.organization_names[:2])}")
    if intel.employee_ids:
        intel_items.append(f"Employee IDs: {', '.join(intel.employee_ids[:2])}")
    if intel.names_mentioned:
        intel_items.append(f"Names: {', '.join(intel.names_mentioned[:2])}")

    if intel_items:
        notes_parts.append(f"Intel: {'; '.join(intel_items)}")

    # RED FLAGS SECTION (NEW AND CRITICAL)
    if hasattr(session, 'red_flags_detected') and session.red_flags_detected:
        # Group red flags by type
        flag_counts = {}
        for flag_dict in session.red_flags_detected:
            flag_type = flag_dict.get("flag_type", "unknown")
            flag_counts[flag_type] = flag_counts.get(flag_type, 0) + 1
        
        # Create red flags summary
        flag_summary = []
        for flag_type, count in sorted(flag_counts.items(), key=lambda x: x[1], reverse=True):
            # Convert snake_case to Title Case
            flag_display = flag_type.replace("_", " ").title()
            if count > 1:
                flag_summary.append(f"{flag_display} ({count}x)")
            else:
                flag_summary.append(flag_display)
        
        if flag_summary:
            notes_parts.append(f"Red Flags: {', '.join(flag_summary)}")
            
            # Add specific red flag highlights for critical types
            critical_flags = [
                f for f in session.red_flags_detected 
                if f.get("flag_type") in ["credential_request", "threat_intimidation", "payment_demand"]
            ]
            if critical_flags:
                examples = []
                for flag in critical_flags[:2]:  # Top 2 critical flags
                    snippet = flag.get("content_snippet", "")[:50]
                    examples.append(f"'{snippet}'")
                if examples:
                    notes_parts.append(f"Critical Indicators: {'; '.join(examples)}")
    else:
        # If no red flags tracked (shouldn't happen after our changes)
        notes_parts.append("Red Flags: [Not tracked - needs investigation]")

    # Scammer tactics
    if tactics := _analyze_threat_tactics(intel.suspicious_keywords):
        notes_parts.append(f"Tactics: {tactics}")

    # Risk level
    risk_level = _assess_risk_level(intel, session.turn_count)
    notes_parts.append(f"Risk: {risk_level}")

    # Behavioral patterns
    if behavior := _analyze_scammer_behavior(session.messages):
        notes_parts.append(f"Behavior: {behavior}")
    
    # Persona used
    if session.persona_type:
        notes_parts.append(f"Persona: {session.persona_type}")

    return ". ".join(notes_parts)
```

### Phase 5: Comprehensive Documentation (PRIORITY 3)

#### 5.1 Module-Level Documentation Standards
You MUST add comprehensive docstrings to EVERY Python file at the module level:

**Template for module docstrings:**
```python
"""
Module: <module_name>

Purpose:
    <2-3 sentence summary of what this module does>

Key Components:
    - Class/Function 1: <brief description>
    - Class/Function 2: <brief description>
    
Design Patterns:
    <Any patterns used - Factory, Singleton, Strategy, etc.>

Dependencies:
    - Critical: <modules this MUST have>
    - Optional: <modules that enhance functionality>

Usage Example:
    ```python
    from module import Class
    instance = Class()
    result = instance.method()
    ```

Author: ScamIntelli Team
Last Modified: <date>
Version: 2.0
"""
```

**You MUST apply this to ALL modules:**
- [src/agent_controller/strategy.py](src/agent_controller/strategy.py)
- [src/agent_controller/agent_state.py](src/agent_controller/agent_state.py)
- [src/intelligence_extractor/extractor.py](src/intelligence_extractor/extractor.py)
- [src/scam_detector/hybrid_engine.py](src/scam_detector/hybrid_engine.py)
- [src/persona_engine/personas.py](src/persona_engine/personas.py)
- [src/api_gateway/routes.py](src/api_gateway/routes.py)
- ALL other Python files in src/

#### 5.2 Function-Level Documentation
You MUST add comprehensive docstrings to EVERY function using this template:

```python
def function_name(param1: Type1, param2: Type2) -> ReturnType:
    """
    One-line summary of what function does.
    
    Longer description of functionality, algorithm approach,
    and any important implementation details.
    
    Args:
        param1: Description of param1, including valid values/ranges
        param2: Description of param2, including valid values/ranges
        
    Returns:
        Description of return value, including type and possible values
        
    Raises:
        ExceptionType: When this exception is raised
        
    Example:
        >>> result = function_name(val1, val2)
        >>> print(result)
        expected_output
        
    Note:
        Any special considerations, performance implications, or caveats
        
    See Also:
        related_function: What it does differently
    """
    # Implementation
    pass
```

**Apply to ALL functions in**:
- [src/agent_controller/strategy.py](src/agent_controller/strategy.py) - EVERY function
- [src/intelligence_extractor/extractor.py](src/intelligence_extractor/extractor.py) - EVERY function
- [src/agent_controller/agent_state.py](src/agent_controller/agent_state.py) - EVERY function

#### 5.3 Inline Comments for Complex Logic
You MUST add inline comments explaining:
1. Non-obvious algorithms
2. Magic numbers (replace with named constants)
3. Complex conditionals
4. Performance optimizations
5. Workarounds or hacks

**Example of good inline commenting:**
```python
def analyze_escalation(messages: List[Dict]) -> Dict:
    """Detect if scammer is escalating pressure over time."""
    
    # Split conversation into first and second half to measure escalation
    # Rationale: Scammers typically start friendly then increase pressure
    midpoint = len(messages) // 2
    first_half = messages[:midpoint]
    second_half = messages[midpoint:]
    
    # Count urgency keywords in each half
    # Using set for O(1) lookup performance on large keyword lists
    urgency_keywords = {"urgent", "immediate", "now", "jaldi", "turant"}
    
    # Count occurrences in first half
    first_count = sum(
        1 for msg in first_half
        if msg.get("role") == "scammer"  # Only count scammer messages
        and any(kw in msg.get("content", "").lower() for kw in urgency_keywords)
    )
    
    # Count occurrences in second half
    second_count = sum(
        1 for msg in second_half
        if msg.get("role") == "scammer"
        and any(kw in msg.get("content", "").lower() for kw in urgency_keywords)
    )
    
    # Escalation detected if second half has 2x or more urgency indicators
    # Threshold of 2x chosen based on observed scam conversation patterns
    escalation_detected = second_count >= first_count * 2
    
    return {
        "escalation_detected": escalation_detected,
        "urgency_first_half": first_count,
        "urgency_second_half": second_count,
        "escalation_ratio": second_count / max(first_count, 1),  # Prevent division by zero
    }
```

### Phase 6: Robust Error Handling (PRIORITY 3)

#### 6.1 Error Handling Standards
You MUST replace broad exception handlers with specific, actionable error handling:

**BEFORE (BAD - do NOT do this):**
```python
try:
    result = some_operation()
except Exception:
    logger.exception("Something went wrong")
    return None
```

**AFTER (GOOD - do THIS instead):**
```python
try:
    result = some_operation()
except ValueError as e:
    # Specific error: invalid input format
    logger.error(f"Invalid input format in some_operation: {e}")
    # Attempt recovery with default value
    result = get_safe_default()
except ConnectionError as e:
    # Specific error: network issue
    logger.error(f"Connection failed in some_operation: {e}")
    # Retry with exponential backoff or return cached result
    result = retry_with_backoff(some_operation, max_retries=3)
except TimeoutError as e:
    # Specific error: operation took too long
    logger.error(f"Operation timed out: {e}")
    # Return partial result if available
    result = get_partial_result()
except Exception as e:
    # Catch-all for unexpected errors - log with full context
    logger.exception(
        f"Unexpected error in some_operation with params: "
        f"param1={param1}, param2={param2}. Error: {e}"
    )
    # Fail gracefully with safe fallback
    result = get_emergency_fallback()
    # Optionally: alert monitoring system
    send_alert_to_monitoring("Critical error in some_operation", e)
finally:
    # Cleanup resources even if an exception occurred
    cleanup_resources()

return result
```

#### 6.2 Specific Files Requiring Error Handling Updates

**MANDATORY: Update [src/intelligence_extractor/extractor.py](src/intelligence_extractor/extractor.py)**

Replace generic `except Exception` blocks with specific handlers:

```python
async def extract_phone_numbers(message: str) -> List[str]:
    """Extract Indian phone numbers with robust error handling."""
    try:
        matches = _get_pattern("phone").findall(message)
    except re.error as e:
        # Regex compilation or execution failed
        logger.error(f"Regex error in phone extraction: {e}. Pattern may be invalid.")
        return []  # Return empty list, don't crash
    except AttributeError as e:
        # Pattern not found in _PATTERNS dict
        logger.error(f"Phone pattern not initialized: {e}")
        _initialize_patterns()  # Attempt to fix
        matches = []
    except Exception as e:
        logger.exception(f"Unexpected error in phone extraction: {e}")
        return []
    
    phone_numbers = []
    for match in matches:
        try:
            original = match.strip()
            if original and len(original) >= 10:  # Validate minimum length
                if original not in phone_numbers:
                    phone_numbers.append(original)
                
                # Attempt normalization
                normalized = normalize_phone_number(match)
                if normalized and normalized not in phone_numbers:
                    phone_numbers.append(normalized)
        except Exception as e:
            # Don't let one bad match break entire extraction
            logger.warning(f"Failed to process phone match '{match}': {e}")
            continue
    
    return phone_numbers
```

**Apply similar specific error handling to:**
- All extraction functions in [src/intelligence_extractor/extractor.py](src/intelligence_extractor/extractor.py)
- All API routes in [src/api_gateway/routes.py](src/api_gateway/routes.py)
- ML prediction functions in [src/scam_detector/ml_engine.py](src/scam_detector/ml_engine.py)
- Persona generation in [src/persona_engine/personas.py](src/persona_engine/personas.py)

#### 6.3 Error Recovery Strategies
You MUST implement graceful degradation and fallbacks:

```python
async def generate_persona_response(
    persona_type: PersonaType,
    scam_category: ScamCategory,
    message: str,
    conversation_history: List[Dict],
    turn_count: int,
    context_hint: str = ""
) -> str:
    """
    Generate persona-based response with multi-tier fallback strategy.
    
    Fallback chain:
    1. Try AI generation (Gemini API)
    2. If AI fails, use template-based generation
    3. If templates fail, use generic persona response
    4. If all fail, use emergency safe response
    """
    # Tier 1: AI generation (primary)
    try:
        ai_response = await _generate_ai_persona_response(
            persona_type, scam_category, message, 
            conversation_history, turn_count, context_hint
        )
        if ai_response and len(ai_response.strip()) > 10:
            return ai_response
    except httpx.TimeoutException as e:
        logger.warning(f"AI generation timed out after 30s: {e}")
        # Continue to fallback
    except httpx.HTTPStatusError as e:
        logger.error(f"AI API returned error {e.response.status_code}: {e}")
        # Continue to fallback
    except Exception as e:
        logger.exception(f"AI generation failed unexpectedly: {e}")
        # Continue to fallback
    
    # Tier 2: Template-based generation (fallback)
    try:
        template_response = _generate_template_response(
            persona_type, scam_category, message, turn_count
        )
        if template_response:
            logger.info(f"Using template fallback for turn {turn_count}")
            return template_response
    except Exception as e:
        logger.error(f"Template generation failed: {e}")
        # Continue to next fallback
    
    # Tier 3: Generic persona response (emergency fallback)
    try:
        profile = get_persona_profile(persona_type)
        generic_response = random.choice(profile.typical_responses)
        logger.warning(f"Using generic response fallback for turn {turn_count}")
        return generic_response
    except Exception as e:
        logger.error(f"Generic response selection failed: {e}")
        # Continue to final fallback
    
    # Tier 4: Ultimate safe fallback (should never reach here)
    logger.critical(
        f"All response generation methods failed for turn {turn_count}. "
        f"Using emergency fallback."
    )
    return "Ek minute sir, network issue aa raha hai. Main thoda baad baat karta hun."
```

### Phase 7: Final Output Enhancement (PRIORITY 2)

#### 7.1 Comprehensive Final Output Structure
**MANDATORY: Update [src/api_gateway/routes.py](src/api_gateway/routes.py) honeypot_endpoint()**

Ensure final output includes ALL required and optional fields with comprehensive data:

```python
# In honeypot_endpoint, after END_SESSION logic, build finalOutput:

if not session.engagement_active or end_conversation:
    # Generate comprehensive agent notes
    agent_notes = await generate_agent_notes(session)
    
    # Calculate engagement metrics
    engagement_duration = _calculate_engagement_duration(session)
    total_messages = session.turn_count * 2  # Approximate (scammer + agent)
    
    # Count questions asked by agent
    questions_asked = sum(
        1 for msg in session.messages
        if msg.get("role") == "agent"
        and ("?" in msg.get("content", "") or any(
            q in msg.get("content", "").lower() 
            for q in ["kya", "kaise", "kaun", "kahan", "kyun", "what", "how", "who", "where", "why"]
        ))
    )
    
    # Count relevant investigative questions
    investigative_keywords = [
        "employee id", "badge number", "office address", "company name",
        "verification", "website", "email", "superior", "manager",
        "department", "branch"
    ]
    relevant_questions = sum(
        1 for msg in session.messages
        if msg.get("role") == "agent"
        and "?" in msg.get("content", "")
        and any(kw in msg.get("content", "").lower() for kw in investigative_keywords)
    )
    
    # Return comprehensive finalOutput
    return JSONResponse(status_code=200, content={
        "status": "success",
        "reply": "Session ended. Intelligence gathered.",
        
        # REQUIRED FIELDS:
        "sessionId": session.session_id,
        "scamDetected": session.scam_detected,
        "totalMessagesExchanged": total_messages,
        "engagementDurationSeconds": engagement_duration,
        "extractedIntelligence": {
            # Standard intel
            "phoneNumbers": session.extracted_intel.phone_numbers,
            "bankAccounts": session.extracted_intel.bank_accounts,
            "upiIds": session.extracted_intel.upi_ids,
            "phishingLinks": session.extracted_intel.phishing_links,
            "emailAddresses": session.extracted_intel.email_addresses,
            
            # NEW INTEL TYPES - MANDATORY:
            "caseIds": session.extracted_intel.case_ids,
            "policyNumbers": session.extracted_intel.policy_numbers,
            "orderNumbers": session.extracted_intel.order_numbers,
            "organizationNames": session.extracted_intel.organization_names,
            "addresses": session.extracted_intel.addresses,
            "employeeIds": session.extracted_intel.employee_ids,
            "namesMentioned": session.extracted_intel.names_mentioned,
        },
        
        # OPTIONAL BUT IMPORTANT FIELDS:
        "agentNotes": agent_notes,  # NOW includes red flags
        "scamType": session.scam_category or "unknown",
        "confidenceLevel": session.confidence_level,
        
        # ADDITIONAL METRICS (improve conversation quality score):
        "conversationMetrics": {
            "questionsAsked": questions_asked,
            "relevantQuestions": relevant_questions,
            "redFlagsIdentified": len(session.red_flags_detected) if hasattr(session, 'red_flags_detected') else 0,
            "personaType": session.persona_type,
            "turnCount": session.turn_count,
        },
        
        # RED FLAGS DETAIL (demonstrate red flag identification):
        "redFlagsDetail": session.red_flags_detected if hasattr(session, 'red_flags_detected') else []
    })
```

### Phase 8: Testing and Validation (PRIORITY 1)

#### 8.1 Create Comprehensive Test Scenarios
**MANDATORY: Create [tests/test_intelligence_extraction_v2.py](tests/test_intelligence_extraction_v2.py)**

```python
"""
Comprehensive tests for enhanced intelligence extraction.

Tests coverage for all entity types including new additions:
- Case IDs, Policy Numbers, Order Numbers
- Organization Names, Addresses
- Employee IDs, Names Mentioned
"""

import pytest
from src.intelligence_extractor.extractor import (
    extract_case_ids,
    extract_policy_numbers,
    extract_order_numbers,
    extract_organization_names,
    extract_addresses,
    extract_all_intelligence,
)
from src.models import ExtractedIntelligence


@pytest.mark.asyncio
async def test_extract_case_ids():
    """Test case ID extraction from various formats."""
    test_cases = [
        ("Your case ID is CASE12345", ["CASE12345"]),
        ("FIR number FIR/123/2024 has been registered", ["FIR/123/2024"]),
        ("Reference number REF-2024-ABC-789", ["REF-2024-ABC-789"]),
        ("Complaint CMP2024-001 under investigation", ["CMP2024-001"]),
    ]
    
    for message, expected in test_cases:
        result = await extract_case_ids(message)
        for exp_id in expected:
            assert exp_id in result, f"Failed to extract '{exp_id}' from '{message}'"


@pytest.mark.asyncio
async def test_extract_organization_names():
    """Test organization name extraction."""
    test_cases = [
        ("I'm calling from SBI Bank fraud department", ["SBI"]),
        ("This is ICICI customer care", ["ICICI"]),
        ("CBI investigation team here", ["CBI"]),
        ("Income Tax Department notice", ["Income Tax Department"]),
    ]
    
    for message, expected in test_cases:
        result = await extract_organization_names(message)
        assert len(result) >= len(expected), f"Failed to extract orgs from '{message}'"


@pytest.mark.asyncio
async def test_comprehensive_extraction():
    """Test extract_all_intelligence with message containing multiple entity types."""
    message = """
    This is Officer Sharma from CBI, badge ID CBI-12345. 
    Your case number is CASE-2024-789. 
    You must pay 5000 to UPI scammer@paytm.
    Call me back at +91-9876543210 or email cbi.fake@scam.com.
    Visit our office at 123 Fake Street, Delhi-110001.
    """
    
    existing = ExtractedIntelligence()
    result = await extract_all_intelligence(message, existing)
    
    # Verify all entity types extracted
    assert len(result.upi_ids) >= 1, "Failed to extract UPI ID"
    assert len(result.phone_numbers) >= 1, "Failed to extract phone"
    assert len(result.email_addresses) >= 1, "Failed to extract email"
    assert len(result.case_ids) >= 1, "Failed to extract case ID"
    assert len(result.employee_ids) >= 1, "Failed to extract employee ID"
    assert len(result.organization_names) >= 1, "Failed to extract organization"
    assert len(result.names_mentioned) >= 1, "Failed to extract name"
    # assert len(result.addresses) >= 1, "Failed to extract address"  # May be challenging


# ADD 20-30 MORE COMPREHENSIVE TESTS
```

**MANDATORY: Create [tests/test_question_engine.py](tests/test_question_engine.py)**

```python
"""Tests for investigative question engine."""

import pytest
from src.agent_controller.question_engine import (
    QuestionBank,
    IntelligenceExtractionPlanner,
    QuestionType,
)
from src.scam_detector.scam_types import ScamCategory
from src.models import ExtractedIntelligence


def test_question_bank_has_all_categories():
    """Verify question bank has questions for all scam categories."""
    required_categories = [
        ScamCategory.DIGITAL_ARREST,
        ScamCategory.KYC_PHISHING,
        ScamCategory.INVESTMENT_FRAUD,
        ScamCategory.JOB_SCAM,
        # ... ALL categories
    ]
    
    for category in required_categories:
        questions = QuestionBank.IDENTITY_QUESTIONS.get(category, [])
        assert len(questions) >= 5, f"Insufficient questions for {category}"


def test_get_questions_for_category():
    """Test getting relevant questions for specific scam type and turn."""
    intel = ExtractedIntelligence()  # Empty intel
    
    questions = QuestionBank.get_questions_for_category(
        ScamCategory.DIGITAL_ARREST,
        turn_count=3,
        extracted_intel=intel
    )
    
    assert len(questions) > 0, "No questions returned for digital arrest at turn 3"
    assert questions[0].priority >= 7, "Highest priority question should be important"


def test_extraction_planner_prioritizes_missing_intel():
    """Verify planner prioritizes extraction of missing intelligence."""
    intel = ExtractedIntelligence(
        upi_ids=["scammer@paytm"],  # Already have UPI
        phone_numbers=[],  # Missing phones
    )
    
    strategy = IntelligenceExtractionPlanner.get_extraction_strategy(
        ScamCategory.KYC_PHISHING,
        turn_count=4,
        extracted_intel=intel
    )
    
    # Should prioritize phone extraction since it's missing
    assert "phone" in strategy["primary_target"].lower()


# ADD 15-20 MORE TESTS
```

**MANDATORY: Create [tests/test_red_flag_tracker.py](tests/test_red_flag_tracker.py)**

```python
"""Tests for red flag detection and probing."""

import pytest
from src.agent_controller.red_flag_tracker import (
    RedFlagDetector,
    RedFlagProber,
    RedFlagType,
)


def test_detect_urgency_pressure():
    """Test detection of urgency/pressure red flags."""
    messages = [
        "Do it immediately or account will be blocked!",
        "You have only 5 minutes to act!",
        "Abhi karo jaldi!",
    ]
    
    for msg in messages:
        flags = RedFlagDetector.detect_red_flags(msg, turn_number=1)
        assert any(f.flag_type == RedFlagType.URGENCY_PRESSURE for f in flags), \
            f"Failed to detect urgency in: {msg}"


def test_detect_threat_intimidation():
    """Test detection of threat/intimidation red flags."""
    messages = [
        "Arrest warrant has been issued against you",
        "Police will come to your house",
        "Legal action will be taken immediately",
    ]
    
    for msg in messages:
        flags = RedFlagDetector.detect_red_flags(msg, turn_number=1)
        assert any(f.flag_type == RedFlagType.THREAT_INTIMIDATION for f in flags), \
            f"Failed to detect threat in: {msg}"


def test_probing_question_generation():
    """Test that probing questions are generated for detected red flags."""
    flags = RedFlagDetector.detect_red_flags(
        "Share your OTP immediately!",
        turn_number=3
    )
    
    probing_q = RedFlagProber.generate_probing_question(
        flags,
        turn_number=3,
        already_asked=[]
    )
    
    assert probing_q is not None, "No probing question generated"
    assert len(probing_q) > 10, "Probing question too short"


# ADD 15-20 MORE TESTS
```

## Implementation Strategy

### Priority Order (STRICT)
1. **Phase 1**: Intelligence Extraction Overhaul (Days 1-2)
   - Add new extraction functions
   - Update ExtractedIntelligence model
   - Integrate into extract_all_intelligence()
   
2. **Phase 2**: Question Engine (Days 2-3)
   - Create question_engine.py
   - Populate question banks (100+ questions)
   - Integrate into strategy.py
   
3. **Phase 3**: Red Flag System (Days 3-4)
   - Create red_flag_tracker.py
   - Integrate detection into strategy
   - Add probing logic
   
4. **Phase 7**: Final Output Enhancement (Day 4)
   - Update honeypot_endpoint
   - Ensure all fields populated
   
5. **Phase 4**: Agent Notes (Day 4)
   - Update generate_agent_notes()
   - Include red flag details
   
6. **Phase 5**: Documentation (Days 5-6)
   - Add module docstrings
   - Add function docstrings
   - Add inline comments
   
7. **Phase 6**: Error Handling (Days 6-7)
   - Replace broad exception handlers
   - Add specific error recovery
   - Implement fallback chains
   
8. **Phase 8**: Testing (Day 7)
   - Run all test suites
   - Validate against submission guidelines
   - Self-test with evaluation scenarios

### Quality Checklist

Before considering work complete, You MUST verify:

- [ ] All new extraction functions implemented and tested
- [ ] ExtractedIntelligence model includes ALL new fields
- [ ] Question engine has 100+ questions across all scam types
- [ ] Red flag detector identifies ALL 12 red flag types
- [ ] Red flag probing questions generated and integrated
- [ ] Agent notes include comprehensive red flag details
- [ ] Final output includes ALL required + optional fields
- [ ] ALL Python files have module-level docstrings
- [ ] ALL functions have comprehensive docstrings
- [ ] Complex logic has inline comments explaining WHY
- [ ] Error handling is specific, not generic Exception catches
- [ ] Fallback chains exist for critical paths
- [ ] Test coverage >= 80% for new code
- [ ] All tests pass: `pytest tests/ -v --cov=src --cov-report=term`
- [ ] Scam detection maintains 20/20 (don't break existing)
- [ ] Intelligence extraction reaches 28-30/30 target
- [ ] Conversation quality reaches 28-30/30 target
- [ ] Red flags clearly identified in agent notes
- [ ] Questions are relevant and investigative, not generic

### Success Criteria (95+/100 Points)

You WILL achieve:

✅ **Scam Detection: 20/20 points** (maintain current performance)
✅ **Intelligence Extraction: 28-30/30 points** (extract 90%+ of planted data)
✅ **Conversation Quality: 28-30/30 points**
   - Turn Count: 8 points (achieve 8+ turns consistently)
   - Questions Asked: 4 points (5+ questions per conversation)
   - Relevant Questions: 3 points (3+ investigative questions)
   - Red Flag Identification: 8 points (identify 5+ flags per scam)
   - Information Elicitation: 7 points (probe for all intel types)
✅ **Engagement Quality: 9-10/10 points** (maintain/improve)
✅ **Response Structure: 10/10 points** (all required fields present)
✅ **Code Quality: 9-10/10 points** (excellent documentation + error handling)

**TOTAL TARGET: 95-100/100 points**

## Execution Instructions

You WILL execute this prompt by:

1. **Reading and understanding ALL phases** before starting implementation
2. **Following the exact order** specified in Implementation Strategy
3. **Creating backup branches** before making changes: `git checkout -b improvement-v2`
4. **Committing incrementally** after each phase completion
5. **Running tests after each phase** to ensure nothing breaks
6. **Documenting as you go**, not at the end
7. **Validating against submission guidelines** at every step
8. **Self-testing with realistic scam scenarios** before declaring complete

## Continuous Validation

After EVERY major change, You WILL:

1. Run test suite: `pytest tests/ -v --tb=short`
2. Check scam detection still works: Test with known scam messages
3. Verify intelligence extraction: Test with messages containing intel
4. Validate question generation: Ensure questions are relevant
5. Confirm error handling: Intentionally trigger errors, check graceful handling
6. Review agent notes: Ensure comprehensive and clear

## Final Self-Assessment

Before declaring this prompt complete, You MUST answer YES to ALL:

- [ ] Can the system extract ALL 13+ intelligence types from scam messages?
- [ ] Does it ask 5+ investigative questions per conversation?
- [ ] Are 3+ questions specifically targeting identity/organization/verification?
- [ ] Does it identify and track 5+ red flags per scam conversation?
- [ ] Do agent notes explicitly mention red flags identified?
- [ ] Is EVERY Python file fully documented with module + function docstrings?
- [ ] Is error handling specific with graceful fallbacks?
- [ ] Do all tests pass with 80%+ coverage?
- [ ] Would this score 95+/100 based on submission guidelines?

If ANY answer is NO, You MUST continue working until ALL are YES.

## Remember

Your mission is not just to write code, but to create an ELITE honeypot system that:
- **Extracts maximum intelligence** from every scam conversation
- **Asks smart, investigative questions** that expose scammers
- **Identifies and probes red flags** systematically
- **Maintains deep, engaging conversations** that waste scammer time
- **Is thoroughly documented** for maintainability
- **Handles errors gracefully** without crashing
- **Achieves 95+/100 points** in evaluation

You WILL NOT stop until this is accomplished. Failure is not an option.

## Contact for Questions

If ANY part of this prompt is ambiguous or unclear:
1. Document the ambiguity
2. Make a reasonable assumption based on submission guidelines
3. Proceed with implementation
4. Add TODO comment for future clarification

DO NOT let ambiguity block progress. When in doubt, over-deliver.
