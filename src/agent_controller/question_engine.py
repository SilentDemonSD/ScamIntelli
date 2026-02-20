"""
Module: agent_controller.question_engine

Purpose:
    Advanced investigative questioning engine for honeypot intelligence extraction.
    Generates contextually-relevant, targeted questions designed to elicit maximum
    intelligence from scammers while maintaining persona believability.

Key Components:
    - QuestionBank: Comprehensive bank of 100+ investigative questions per category
    - IntelligenceExtractionPlanner: Strategic planner for intel extraction across turns
    - InvestigativeQuestion: Structured question with metadata and priority

Design Patterns:
    - Strategy pattern for per-scam-category question selection
    - Priority queue approach for question ordering

Author: ScamIntelli Team
Last Modified: 2026-02-20
Version: 2.0
"""

import logging
import random
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

from src.models import ExtractedIntelligence
from src.scam_detector.scam_types import ScamCategory

logger = logging.getLogger(__name__)


class QuestionType(str, Enum):
    """Categories of investigative questions."""
    IDENTITY_VERIFICATION = "identity_verification"
    ORGANIZATION_DETAILS = "organization_details"
    CONTACT_VERIFICATION = "contact_verification"
    PROCESS_VERIFICATION = "process_verification"
    AUTHORITY_CHALLENGE = "authority_challenge"
    TIME_STALLING = "time_stalling"
    PAYMENT_CLARIFICATION = "payment_clarification"
    TECHNICAL_CONFUSION = "technical_confusion"
    TECHNICAL_DETAILS = "technical_details"


@dataclass
class InvestigativeQuestion:
    """Structured investigative question with targeting metadata.

    Attributes:
        question_text: The actual question in Hinglish/Hindi/English.
        question_type: Category of the question.
        target_intelligence: Which intel types this question aims to extract.
        priority: 1-10, higher = more important and asked first.
        scam_categories: Which scam types this applies to (empty = all).
        turn_range: (min_turn, max_turn) when to ask this question.
    """
    question_text: str
    question_type: QuestionType
    target_intelligence: List[str] = field(default_factory=list)
    priority: int = 5
    scam_categories: List[ScamCategory] = field(default_factory=list)
    turn_range: Tuple[int, int] = (2, 10)


class QuestionBank:
    """
    Comprehensive bank of investigative questions organized by type and category.

    Questions are designed to:
    1. Extract maximum intelligence (phone, UPI, organization, address, names)
    2. Keep scammer engaged and talking
    3. Identify red flags through contradictions in answers
    4. Maintain persona believability (confused Indian victim)
    """

    # Category-specific investigative questions
    IDENTITY_QUESTIONS: Dict[ScamCategory, List[InvestigativeQuestion]] = {
        ScamCategory.DIGITAL_ARREST: [
            InvestigativeQuestion(
                question_text="Sir aapka naam kya hai? Badge number ya ID number bhi batao, main note kar leta hun.",
                question_type=QuestionType.IDENTITY_VERIFICATION,
                target_intelligence=["names_mentioned", "employee_ids"],
                priority=9,
                scam_categories=[ScamCategory.DIGITAL_ARREST],
                turn_range=(2, 6),
            ),
            InvestigativeQuestion(
                question_text="Sir aap kis police station se bol rahe hain? Station ka address bata do.",
                question_type=QuestionType.ORGANIZATION_DETAILS,
                target_intelligence=["organization_names", "addresses"],
                priority=8,
                scam_categories=[ScamCategory.DIGITAL_ARREST],
                turn_range=(2, 7),
            ),
            InvestigativeQuestion(
                question_text="Main aapke senior officer se baat kar sakta hun? Unka direct number de do.",
                question_type=QuestionType.CONTACT_VERIFICATION,
                target_intelligence=["phone_numbers"],
                priority=10,
                scam_categories=[ScamCategory.DIGITAL_ARREST],
                turn_range=(3, 8),
            ),
            InvestigativeQuestion(
                question_text="Case number kya hai mera? FIR copy bhej do email pe, mera email batata hun.",
                question_type=QuestionType.PROCESS_VERIFICATION,
                target_intelligence=["case_ids", "email_addresses"],
                priority=9,
                scam_categories=[ScamCategory.DIGITAL_ARREST],
                turn_range=(2, 7),
            ),
            InvestigativeQuestion(
                question_text="Sir court ka order hai toh court ka naam aur address batao, main verify karwa lunga.",
                question_type=QuestionType.AUTHORITY_CHALLENGE,
                target_intelligence=["organization_names", "addresses"],
                priority=8,
                scam_categories=[ScamCategory.DIGITAL_ARREST],
                turn_range=(3, 8),
            ),
            InvestigativeQuestion(
                question_text="Sir aap video call pe apna ID card dikhao, main verify karna chahta hun.",
                question_type=QuestionType.IDENTITY_VERIFICATION,
                target_intelligence=["employee_ids"],
                priority=7,
                scam_categories=[ScamCategory.DIGITAL_ARREST],
                turn_range=(4, 9),
            ),
            InvestigativeQuestion(
                question_text="Kaunsa department handle kar raha hai yeh case? Department head ka naam kya hai?",
                question_type=QuestionType.ORGANIZATION_DETAILS,
                target_intelligence=["organization_names", "names_mentioned"],
                priority=8,
                scam_categories=[ScamCategory.DIGITAL_ARREST],
                turn_range=(3, 8),
            ),
            InvestigativeQuestion(
                question_text="Sir complaint number kya hai? Main apne lawyer ko share karunga.",
                question_type=QuestionType.PROCESS_VERIFICATION,
                target_intelligence=["case_ids"],
                priority=9,
                scam_categories=[ScamCategory.DIGITAL_ARREST],
                turn_range=(2, 6),
            ),
        ],
        ScamCategory.KYC_PHISHING: [
            InvestigativeQuestion(
                question_text="Sir aap bank ke kis department se call kar rahe hain? Department ka naam batao.",
                question_type=QuestionType.ORGANIZATION_DETAILS,
                target_intelligence=["organization_names"],
                priority=8,
                scam_categories=[ScamCategory.KYC_PHISHING],
                turn_range=(2, 5),
            ),
            InvestigativeQuestion(
                question_text="Aapka employee ID kya hai? Main verification ke liye note kar leta hun.",
                question_type=QuestionType.IDENTITY_VERIFICATION,
                target_intelligence=["employee_ids"],
                priority=7,
                scam_categories=[ScamCategory.KYC_PHISHING],
                turn_range=(2, 6),
            ),
            InvestigativeQuestion(
                question_text="Bank ka official website kya hai? Main online check kar leta hun KYC status.",
                question_type=QuestionType.CONTACT_VERIFICATION,
                target_intelligence=["phishing_links"],
                priority=9,
                scam_categories=[ScamCategory.KYC_PHISHING],
                turn_range=(2, 5),
            ),
            InvestigativeQuestion(
                question_text="Sir aapka direct phone number do, agar call cut ho jaye toh main wapas call karunga.",
                question_type=QuestionType.CONTACT_VERIFICATION,
                target_intelligence=["phone_numbers"],
                priority=10,
                scam_categories=[ScamCategory.KYC_PHISHING],
                turn_range=(2, 7),
            ),
            InvestigativeQuestion(
                question_text="Kya main branch mein jaake KYC update kar sakta hun? Nearest branch ka address batao.",
                question_type=QuestionType.ORGANIZATION_DETAILS,
                target_intelligence=["addresses", "organization_names"],
                priority=7,
                scam_categories=[ScamCategory.KYC_PHISHING],
                turn_range=(3, 7),
            ),
            InvestigativeQuestion(
                question_text="Mujhe email pe official letter bhejo KYC ke baare mein. Aapka email ID kya hai?",
                question_type=QuestionType.CONTACT_VERIFICATION,
                target_intelligence=["email_addresses"],
                priority=8,
                scam_categories=[ScamCategory.KYC_PHISHING],
                turn_range=(3, 7),
            ),
            InvestigativeQuestion(
                question_text="KYC reference number kya hai? Main bank mein call karke cross-check karunga.",
                question_type=QuestionType.PROCESS_VERIFICATION,
                target_intelligence=["case_ids"],
                priority=8,
                scam_categories=[ScamCategory.KYC_PHISHING],
                turn_range=(2, 6),
            ),
            InvestigativeQuestion(
                question_text="Sir aapke supervisor ka naam aur number do, main double-check karna chahta hun.",
                question_type=QuestionType.IDENTITY_VERIFICATION,
                target_intelligence=["names_mentioned", "phone_numbers"],
                priority=8,
                scam_categories=[ScamCategory.KYC_PHISHING],
                turn_range=(4, 8),
            ),
        ],
        ScamCategory.BANK_FRAUD: [
            InvestigativeQuestion(
                question_text="Sir aap bank ke fraud department se ho? Aapka employee code kya hai?",
                question_type=QuestionType.IDENTITY_VERIFICATION,
                target_intelligence=["employee_ids", "organization_names"],
                priority=9,
                scam_categories=[ScamCategory.BANK_FRAUD],
                turn_range=(2, 6),
            ),
            InvestigativeQuestion(
                question_text="Transaction ID kya hai jo suspicious hai? Main apne statement mein check karunga.",
                question_type=QuestionType.PROCESS_VERIFICATION,
                target_intelligence=["order_numbers", "case_ids"],
                priority=8,
                scam_categories=[ScamCategory.BANK_FRAUD],
                turn_range=(2, 6),
            ),
            InvestigativeQuestion(
                question_text="Sir callback number de do, main 2 minute mein call karunga. Network issue hai.",
                question_type=QuestionType.CONTACT_VERIFICATION,
                target_intelligence=["phone_numbers"],
                priority=10,
                scam_categories=[ScamCategory.BANK_FRAUD],
                turn_range=(2, 7),
            ),
            InvestigativeQuestion(
                question_text="Branch ka address batao, main directly jaake baat karunga personally.",
                question_type=QuestionType.ORGANIZATION_DETAILS,
                target_intelligence=["addresses", "organization_names"],
                priority=7,
                scam_categories=[ScamCategory.BANK_FRAUD],
                turn_range=(3, 8),
            ),
            InvestigativeQuestion(
                question_text="Sir mujhe complaint register karni hai, complaint reference number kya milega?",
                question_type=QuestionType.PROCESS_VERIFICATION,
                target_intelligence=["case_ids"],
                priority=8,
                scam_categories=[ScamCategory.BANK_FRAUD],
                turn_range=(3, 7),
            ),
            InvestigativeQuestion(
                question_text="Kya aap official email se confirmation bhej sakte ho? Email ID kya hai aapka?",
                question_type=QuestionType.CONTACT_VERIFICATION,
                target_intelligence=["email_addresses"],
                priority=8,
                scam_categories=[ScamCategory.BANK_FRAUD],
                turn_range=(3, 8),
            ),
            InvestigativeQuestion(
                question_text="Sir aap kis branch se call kar rahe ho? Branch manager ka naam kya hai?",
                question_type=QuestionType.ORGANIZATION_DETAILS,
                target_intelligence=["organization_names", "names_mentioned"],
                priority=7,
                scam_categories=[ScamCategory.BANK_FRAUD],
                turn_range=(3, 7),
            ),
            InvestigativeQuestion(
                question_text="RBI guidelines ke according toh bank kabhi phone pe details nahi maangta. Kya aap sure ho?",
                question_type=QuestionType.AUTHORITY_CHALLENGE,
                target_intelligence=["organization_names"],
                priority=6,
                scam_categories=[ScamCategory.BANK_FRAUD],
                turn_range=(5, 9),
            ),
        ],
        ScamCategory.UPI_FRAUD: [
            InvestigativeQuestion(
                question_text="Sir payment kisko karna hai? UPI ID bata do, main check karunga.",
                question_type=QuestionType.PAYMENT_CLARIFICATION,
                target_intelligence=["upi_ids"],
                priority=10,
                scam_categories=[ScamCategory.UPI_FRAUD],
                turn_range=(2, 7),
            ),
            InvestigativeQuestion(
                question_text="Aapka contact number kya hai? Agar payment fail ho jaye toh call karunga.",
                question_type=QuestionType.CONTACT_VERIFICATION,
                target_intelligence=["phone_numbers"],
                priority=9,
                scam_categories=[ScamCategory.UPI_FRAUD],
                turn_range=(2, 6),
            ),
            InvestigativeQuestion(
                question_text="Company ka naam kya hai? GST number hai toh batao, main verify karunga.",
                question_type=QuestionType.ORGANIZATION_DETAILS,
                target_intelligence=["organization_names"],
                priority=8,
                scam_categories=[ScamCategory.UPI_FRAUD],
                turn_range=(2, 6),
            ),
            InvestigativeQuestion(
                question_text="Sir payment kitna karna hai exactly? Kisi aur method se bhi ho sakta hai kya?",
                question_type=QuestionType.PAYMENT_CLARIFICATION,
                target_intelligence=["bank_accounts"],
                priority=7,
                scam_categories=[ScamCategory.UPI_FRAUD],
                turn_range=(3, 7),
            ),
            InvestigativeQuestion(
                question_text="Order number ya reference number kya hai? Record ke liye chahiye.",
                question_type=QuestionType.PROCESS_VERIFICATION,
                target_intelligence=["order_numbers", "case_ids"],
                priority=8,
                scam_categories=[ScamCategory.UPI_FRAUD],
                turn_range=(2, 6),
            ),
            InvestigativeQuestion(
                question_text="UPI se nahi ho raha, account number aur IFSC de do bank transfer karunga.",
                question_type=QuestionType.PAYMENT_CLARIFICATION,
                target_intelligence=["bank_accounts"],
                priority=9,
                scam_categories=[ScamCategory.UPI_FRAUD],
                turn_range=(4, 8),
            ),
            InvestigativeQuestion(
                question_text="Website hai aapki? Link dedo, main wahan se check karunga pehle.",
                question_type=QuestionType.CONTACT_VERIFICATION,
                target_intelligence=["phishing_links"],
                priority=7,
                scam_categories=[ScamCategory.UPI_FRAUD],
                turn_range=(3, 7),
            ),
            InvestigativeQuestion(
                question_text="Receipt ya invoice milega kya payment ke baad? Email pe bhej dena.",
                question_type=QuestionType.CONTACT_VERIFICATION,
                target_intelligence=["email_addresses"],
                priority=7,
                scam_categories=[ScamCategory.UPI_FRAUD],
                turn_range=(4, 8),
            ),
        ],
        ScamCategory.INVESTMENT_FRAUD: [
            InvestigativeQuestion(
                question_text="Company ka SEBI registration number kya hai? Main verify karna chahta hun.",
                question_type=QuestionType.AUTHORITY_CHALLENGE,
                target_intelligence=["organization_names", "case_ids"],
                priority=9,
                scam_categories=[ScamCategory.INVESTMENT_FRAUD],
                turn_range=(2, 6),
            ),
            InvestigativeQuestion(
                question_text="Sir aapka direct phone number do, mujhe apne CA se discuss karke callback karna hai.",
                question_type=QuestionType.CONTACT_VERIFICATION,
                target_intelligence=["phone_numbers"],
                priority=10,
                scam_categories=[ScamCategory.INVESTMENT_FRAUD],
                turn_range=(2, 7),
            ),
            InvestigativeQuestion(
                question_text="Company ka office kahan hai? Main visit karna chahunga pehle invest karne se.",
                question_type=QuestionType.ORGANIZATION_DETAILS,
                target_intelligence=["addresses", "organization_names"],
                priority=8,
                scam_categories=[ScamCategory.INVESTMENT_FRAUD],
                turn_range=(3, 7),
            ),
            InvestigativeQuestion(
                question_text="Website ka link bhejo, main dekhunga kya products hain.",
                question_type=QuestionType.CONTACT_VERIFICATION,
                target_intelligence=["phishing_links"],
                priority=8,
                scam_categories=[ScamCategory.INVESTMENT_FRAUD],
                turn_range=(2, 6),
            ),
            InvestigativeQuestion(
                question_text="Payment kahan karna hai? UPI ya bank transfer? Details de do.",
                question_type=QuestionType.PAYMENT_CLARIFICATION,
                target_intelligence=["upi_ids", "bank_accounts"],
                priority=9,
                scam_categories=[ScamCategory.INVESTMENT_FRAUD],
                turn_range=(3, 7),
            ),
            InvestigativeQuestion(
                question_text="Aapka naam kya hai sir? Manager ho ya advisor? Business card bhej do WhatsApp pe.",
                question_type=QuestionType.IDENTITY_VERIFICATION,
                target_intelligence=["names_mentioned", "employee_ids"],
                priority=7,
                scam_categories=[ScamCategory.INVESTMENT_FRAUD],
                turn_range=(2, 5),
            ),
            InvestigativeQuestion(
                question_text="Email pe brochure bhejo, main padh ke decide karunga. Email ID kya hai aapka?",
                question_type=QuestionType.CONTACT_VERIFICATION,
                target_intelligence=["email_addresses"],
                priority=7,
                scam_categories=[ScamCategory.INVESTMENT_FRAUD],
                turn_range=(3, 7),
            ),
            InvestigativeQuestion(
                question_text="Reference number ya policy number milega kya invest karne ke baad?",
                question_type=QuestionType.PROCESS_VERIFICATION,
                target_intelligence=["policy_numbers", "case_ids"],
                priority=7,
                scam_categories=[ScamCategory.INVESTMENT_FRAUD],
                turn_range=(4, 8),
            ),
        ],
        ScamCategory.JOB_SCAM: [
            InvestigativeQuestion(
                question_text="Company ka naam kya hai? LinkedIn pe search karunga.",
                question_type=QuestionType.ORGANIZATION_DETAILS,
                target_intelligence=["organization_names"],
                priority=9,
                scam_categories=[ScamCategory.JOB_SCAM],
                turn_range=(2, 5),
            ),
            InvestigativeQuestion(
                question_text="HR ka direct number de do, main call karke confirm karunga.",
                question_type=QuestionType.CONTACT_VERIFICATION,
                target_intelligence=["phone_numbers", "names_mentioned"],
                priority=10,
                scam_categories=[ScamCategory.JOB_SCAM],
                turn_range=(2, 6),
            ),
            InvestigativeQuestion(
                question_text="Office address kahan hai? Interview ke liye jaana padega kya?",
                question_type=QuestionType.ORGANIZATION_DETAILS,
                target_intelligence=["addresses"],
                priority=8,
                scam_categories=[ScamCategory.JOB_SCAM],
                turn_range=(2, 6),
            ),
            InvestigativeQuestion(
                question_text="Job offer letter email pe bhejo, main check karunga. Company email ID kya hai?",
                question_type=QuestionType.CONTACT_VERIFICATION,
                target_intelligence=["email_addresses"],
                priority=8,
                scam_categories=[ScamCategory.JOB_SCAM],
                turn_range=(3, 7),
            ),
            InvestigativeQuestion(
                question_text="Registration fee kyun hai? Payment UPI pe karna hai ya bank transfer?",
                question_type=QuestionType.PAYMENT_CLARIFICATION,
                target_intelligence=["upi_ids", "bank_accounts"],
                priority=9,
                scam_categories=[ScamCategory.JOB_SCAM],
                turn_range=(3, 7),
            ),
            InvestigativeQuestion(
                question_text="Website ka link do company ka, main Glassdoor pe bhi reviews check karunga.",
                question_type=QuestionType.CONTACT_VERIFICATION,
                target_intelligence=["phishing_links"],
                priority=7,
                scam_categories=[ScamCategory.JOB_SCAM],
                turn_range=(2, 6),
            ),
            InvestigativeQuestion(
                question_text="Job reference number kya hai? Main apne friend ko bhi share karunga.",
                question_type=QuestionType.PROCESS_VERIFICATION,
                target_intelligence=["case_ids", "order_numbers"],
                priority=7,
                scam_categories=[ScamCategory.JOB_SCAM],
                turn_range=(3, 7),
            ),
            InvestigativeQuestion(
                question_text="Aapka naam kya hai sir? LinkedIn pe connect karun?",
                question_type=QuestionType.IDENTITY_VERIFICATION,
                target_intelligence=["names_mentioned"],
                priority=7,
                scam_categories=[ScamCategory.JOB_SCAM],
                turn_range=(2, 5),
            ),
        ],
        ScamCategory.LOTTERY_PRIZE: [
            InvestigativeQuestion(
                question_text="Company ka naam kya hai? Official website ka link do.",
                question_type=QuestionType.ORGANIZATION_DETAILS,
                target_intelligence=["organization_names", "phishing_links"],
                priority=9,
                scam_categories=[ScamCategory.LOTTERY_PRIZE],
                turn_range=(2, 6),
            ),
            InvestigativeQuestion(
                question_text="Prize claim karne ke liye kahan contact karna hai? Phone number do.",
                question_type=QuestionType.CONTACT_VERIFICATION,
                target_intelligence=["phone_numbers"],
                priority=10,
                scam_categories=[ScamCategory.LOTTERY_PRIZE],
                turn_range=(2, 6),
            ),
            InvestigativeQuestion(
                question_text="Lottery ticket number kya hai mera? Reference number batao.",
                question_type=QuestionType.PROCESS_VERIFICATION,
                target_intelligence=["case_ids", "order_numbers"],
                priority=8,
                scam_categories=[ScamCategory.LOTTERY_PRIZE],
                turn_range=(2, 6),
            ),
            InvestigativeQuestion(
                question_text="Processing fee kahan bhejni hai? Bank account ya UPI?",
                question_type=QuestionType.PAYMENT_CLARIFICATION,
                target_intelligence=["upi_ids", "bank_accounts"],
                priority=9,
                scam_categories=[ScamCategory.LOTTERY_PRIZE],
                turn_range=(3, 7),
            ),
            InvestigativeQuestion(
                question_text="Email pe official letter bhejo. Aapka email kya hai?",
                question_type=QuestionType.CONTACT_VERIFICATION,
                target_intelligence=["email_addresses"],
                priority=7,
                scam_categories=[ScamCategory.LOTTERY_PRIZE],
                turn_range=(3, 7),
            ),
            InvestigativeQuestion(
                question_text="Office kahan hai aapka? Main direct visit karke prize le sakta hun kya?",
                question_type=QuestionType.ORGANIZATION_DETAILS,
                target_intelligence=["addresses"],
                priority=7,
                scam_categories=[ScamCategory.LOTTERY_PRIZE],
                turn_range=(3, 8),
            ),
            InvestigativeQuestion(
                question_text="Aap agent ho ya company se directly? Aapka naam aur ID number batao.",
                question_type=QuestionType.IDENTITY_VERIFICATION,
                target_intelligence=["names_mentioned", "employee_ids"],
                priority=8,
                scam_categories=[ScamCategory.LOTTERY_PRIZE],
                turn_range=(2, 6),
            ),
            InvestigativeQuestion(
                question_text="Kya kal kar sakta hun? Abhi paise nahi hain, kal subah bhejunga.",
                question_type=QuestionType.TIME_STALLING,
                target_intelligence=[],
                priority=5,
                scam_categories=[ScamCategory.LOTTERY_PRIZE],
                turn_range=(5, 9),
            ),
        ],
        ScamCategory.CUSTOMS_PARCEL: [
            InvestigativeQuestion(
                question_text="Parcel ka tracking number kya hai? Main India Post pe check karunga.",
                question_type=QuestionType.PROCESS_VERIFICATION,
                target_intelligence=["order_numbers"],
                priority=9,
                scam_categories=[ScamCategory.CUSTOMS_PARCEL],
                turn_range=(2, 6),
            ),
            InvestigativeQuestion(
                question_text="Customs office ka address kahan hai? Main personally jaaunga.",
                question_type=QuestionType.ORGANIZATION_DETAILS,
                target_intelligence=["addresses", "organization_names"],
                priority=8,
                scam_categories=[ScamCategory.CUSTOMS_PARCEL],
                turn_range=(3, 7),
            ),
            InvestigativeQuestion(
                question_text="Officer ka naam aur badge number de do for verification.",
                question_type=QuestionType.IDENTITY_VERIFICATION,
                target_intelligence=["names_mentioned", "employee_ids"],
                priority=9,
                scam_categories=[ScamCategory.CUSTOMS_PARCEL],
                turn_range=(2, 6),
            ),
            InvestigativeQuestion(
                question_text="Fine kahan pay karna hai? UPI ID ya bank account batao.",
                question_type=QuestionType.PAYMENT_CLARIFICATION,
                target_intelligence=["upi_ids", "bank_accounts"],
                priority=9,
                scam_categories=[ScamCategory.CUSTOMS_PARCEL],
                turn_range=(3, 7),
            ),
            InvestigativeQuestion(
                question_text="Case reference number kya hai? Main lawyer ko dikhaunga.",
                question_type=QuestionType.PROCESS_VERIFICATION,
                target_intelligence=["case_ids"],
                priority=8,
                scam_categories=[ScamCategory.CUSTOMS_PARCEL],
                turn_range=(2, 6),
            ),
            InvestigativeQuestion(
                question_text="Email pe seizure notice bhejo, official email kya hai aapka?",
                question_type=QuestionType.CONTACT_VERIFICATION,
                target_intelligence=["email_addresses"],
                priority=7,
                scam_categories=[ScamCategory.CUSTOMS_PARCEL],
                turn_range=(3, 7),
            ),
            InvestigativeQuestion(
                question_text="Sir callback number dedo, main apne bete se discuss karke call karta hun.",
                question_type=QuestionType.CONTACT_VERIFICATION,
                target_intelligence=["phone_numbers"],
                priority=10,
                scam_categories=[ScamCategory.CUSTOMS_PARCEL],
                turn_range=(2, 7),
            ),
            InvestigativeQuestion(
                question_text="Parcel sender ka naam kya hai? Main usse baat karke confirm karna chahta hun.",
                question_type=QuestionType.IDENTITY_VERIFICATION,
                target_intelligence=["names_mentioned"],
                priority=7,
                scam_categories=[ScamCategory.CUSTOMS_PARCEL],
                turn_range=(3, 7),
            ),
        ],
        ScamCategory.PHISHING: [
            InvestigativeQuestion(
                question_text="Website ka link phir se bhejo, pehle wala open nahi hua.",
                question_type=QuestionType.CONTACT_VERIFICATION,
                target_intelligence=["phishing_links"],
                priority=10,
                scam_categories=[ScamCategory.PHISHING],
                turn_range=(2, 7),
            ),
            InvestigativeQuestion(
                question_text="Aapki company ka naam kya hai? Customer care ka phone number do.",
                question_type=QuestionType.ORGANIZATION_DETAILS,
                target_intelligence=["organization_names", "phone_numbers"],
                priority=9,
                scam_categories=[ScamCategory.PHISHING],
                turn_range=(2, 6),
            ),
            InvestigativeQuestion(
                question_text="Email pe details bhejo, mera email hai... aapka official email kya hai?",
                question_type=QuestionType.CONTACT_VERIFICATION,
                target_intelligence=["email_addresses"],
                priority=8,
                scam_categories=[ScamCategory.PHISHING],
                turn_range=(3, 7),
            ),
            InvestigativeQuestion(
                question_text="Offer ka reference number kya hai? Main friend ko bhi bataunga.",
                question_type=QuestionType.PROCESS_VERIFICATION,
                target_intelligence=["case_ids", "order_numbers"],
                priority=7,
                scam_categories=[ScamCategory.PHISHING],
                turn_range=(2, 6),
            ),
            InvestigativeQuestion(
                question_text="Payment kaise karna hai? UPI ya card? Details do.",
                question_type=QuestionType.PAYMENT_CLARIFICATION,
                target_intelligence=["upi_ids", "bank_accounts"],
                priority=8,
                scam_categories=[ScamCategory.PHISHING],
                turn_range=(3, 7),
            ),
            InvestigativeQuestion(
                question_text="Aap agent ho ya company se? Aapka naam aur designation batao.",
                question_type=QuestionType.IDENTITY_VERIFICATION,
                target_intelligence=["names_mentioned", "employee_ids"],
                priority=7,
                scam_categories=[ScamCategory.PHISHING],
                turn_range=(2, 6),
            ),
            InvestigativeQuestion(
                question_text="Office address kya hai? Kya main personally visit karke claim kar sakta hun?",
                question_type=QuestionType.ORGANIZATION_DETAILS,
                target_intelligence=["addresses"],
                priority=7,
                scam_categories=[ScamCategory.PHISHING],
                turn_range=(3, 8),
            ),
            InvestigativeQuestion(
                question_text="Kal kar sakta hun kya? Abhi mere paas time nahi hai properly check karne ka.",
                question_type=QuestionType.TIME_STALLING,
                target_intelligence=[],
                priority=5,
                scam_categories=[ScamCategory.PHISHING],
                turn_range=(4, 9),
            ),
        ],
        ScamCategory.ROMANCE_SCAM: [
            InvestigativeQuestion(
                question_text="Aapka full name kya hai? Instagram ya Facebook pe dhundhun?",
                question_type=QuestionType.IDENTITY_VERIFICATION,
                target_intelligence=["names_mentioned"],
                priority=9,
                scam_categories=[ScamCategory.ROMANCE_SCAM],
                turn_range=(2, 8),
            ),
            InvestigativeQuestion(
                question_text="Yeh payment kahan bhejni hai? Account number de do.",
                question_type=QuestionType.PAYMENT_CLARIFICATION,
                target_intelligence=["bank_accounts", "upi_ids"],
                priority=9,
                scam_categories=[ScamCategory.ROMANCE_SCAM],
                turn_range=(3, 8),
            ),
            InvestigativeQuestion(
                question_text="Aap kahan rehte ho? City aur area batao, main visit karunga.",
                question_type=QuestionType.ORGANIZATION_DETAILS,
                target_intelligence=["addresses"],
                priority=8,
                scam_categories=[ScamCategory.ROMANCE_SCAM],
                turn_range=(3, 8),
            ),
            InvestigativeQuestion(
                question_text="Aapka phone number do, main WhatsApp pe message karunga.",
                question_type=QuestionType.CONTACT_VERIFICATION,
                target_intelligence=["phone_numbers"],
                priority=10,
                scam_categories=[ScamCategory.ROMANCE_SCAM],
                turn_range=(2, 7),
            ),
            InvestigativeQuestion(
                question_text="Email ID do, main photos send karunga.",
                question_type=QuestionType.CONTACT_VERIFICATION,
                target_intelligence=["email_addresses"],
                priority=7,
                scam_categories=[ScamCategory.ROMANCE_SCAM],
                turn_range=(3, 7),
            ),
            InvestigativeQuestion(
                question_text="Kahan kaam karte ho? Company ka website hai?",
                question_type=QuestionType.ORGANIZATION_DETAILS,
                target_intelligence=["organization_names", "phishing_links"],
                priority=7,
                scam_categories=[ScamCategory.ROMANCE_SCAM],
                turn_range=(3, 8),
            ),
        ],
        ScamCategory.TECH_SUPPORT: [
            InvestigativeQuestion(
                question_text="Aap konsi company se ho? Official website batao verification ke liye.",
                question_type=QuestionType.ORGANIZATION_DETAILS,
                target_intelligence=["organization_names", "phishing_links"],
                priority=9,
                scam_categories=[ScamCategory.TECH_SUPPORT],
                turn_range=(2, 5),
            ),
            InvestigativeQuestion(
                question_text="Ticket number kya hai? Main records mein check karunga.",
                question_type=QuestionType.PROCESS_VERIFICATION,
                target_intelligence=["case_ids"],
                priority=8,
                scam_categories=[ScamCategory.TECH_SUPPORT],
                turn_range=(2, 6),
            ),
            InvestigativeQuestion(
                question_text="Aapka employee ID aur naam batao, main HR se verify karunga.",
                question_type=QuestionType.IDENTITY_VERIFICATION,
                target_intelligence=["employee_ids", "names_mentioned"],
                priority=8,
                scam_categories=[ScamCategory.TECH_SUPPORT],
                turn_range=(2, 6),
            ),
            InvestigativeQuestion(
                question_text="Direct phone number do apna, agar disconnect ho jaye toh.",
                question_type=QuestionType.CONTACT_VERIFICATION,
                target_intelligence=["phone_numbers"],
                priority=10,
                scam_categories=[ScamCategory.TECH_SUPPORT],
                turn_range=(2, 7),
            ),
            InvestigativeQuestion(
                question_text="Fix karne ka charge kitna hai? UPI pe ya card se?",
                question_type=QuestionType.PAYMENT_CLARIFICATION,
                target_intelligence=["upi_ids"],
                priority=8,
                scam_categories=[ScamCategory.TECH_SUPPORT],
                turn_range=(3, 7),
            ),
            InvestigativeQuestion(
                question_text="Email pe invoice bhejo. Aapka official email kya hai?",
                question_type=QuestionType.CONTACT_VERIFICATION,
                target_intelligence=["email_addresses"],
                priority=7,
                scam_categories=[ScamCategory.TECH_SUPPORT],
                turn_range=(3, 7),
            ),
        ],
        ScamCategory.LOAN_FRAUD: [
            InvestigativeQuestion(
                question_text="Company ka RBI registration number kya hai? Main check karunga.",
                question_type=QuestionType.AUTHORITY_CHALLENGE,
                target_intelligence=["organization_names", "case_ids"],
                priority=9,
                scam_categories=[ScamCategory.LOAN_FRAUD],
                turn_range=(2, 6),
            ),
            InvestigativeQuestion(
                question_text="Processing fee kahan pay karni hai? UPI ID ya account number?",
                question_type=QuestionType.PAYMENT_CLARIFICATION,
                target_intelligence=["upi_ids", "bank_accounts"],
                priority=10,
                scam_categories=[ScamCategory.LOAN_FRAUD],
                turn_range=(2, 6),
            ),
            InvestigativeQuestion(
                question_text="Office kahan hai? Main visit karke documents sign karunga.",
                question_type=QuestionType.ORGANIZATION_DETAILS,
                target_intelligence=["addresses", "organization_names"],
                priority=8,
                scam_categories=[ScamCategory.LOAN_FRAUD],
                turn_range=(3, 7),
            ),
            InvestigativeQuestion(
                question_text="Aapka direct phone number do. Agar koi issue aaye toh call karunga.",
                question_type=QuestionType.CONTACT_VERIFICATION,
                target_intelligence=["phone_numbers"],
                priority=9,
                scam_categories=[ScamCategory.LOAN_FRAUD],
                turn_range=(2, 7),
            ),
            InvestigativeQuestion(
                question_text="Loan application reference number kya hai? Main track karunga.",
                question_type=QuestionType.PROCESS_VERIFICATION,
                target_intelligence=["case_ids", "order_numbers"],
                priority=8,
                scam_categories=[ScamCategory.LOAN_FRAUD],
                turn_range=(2, 6),
            ),
            InvestigativeQuestion(
                question_text="Email pe loan agreement bhejo. Company ka email kya hai?",
                question_type=QuestionType.CONTACT_VERIFICATION,
                target_intelligence=["email_addresses"],
                priority=7,
                scam_categories=[ScamCategory.LOAN_FRAUD],
                turn_range=(3, 7),
            ),
        ],
        ScamCategory.REFUND_SCAM: [
            InvestigativeQuestion(
                question_text="Refund ka reference number kya hai? Main bank statement mein check karunga.",
                question_type=QuestionType.PROCESS_VERIFICATION,
                target_intelligence=["case_ids", "order_numbers"],
                priority=9,
                scam_categories=[ScamCategory.REFUND_SCAM],
                turn_range=(2, 6),
            ),
            InvestigativeQuestion(
                question_text="Aap kis company se bol rahe ho? Official customer care number kya hai?",
                question_type=QuestionType.ORGANIZATION_DETAILS,
                target_intelligence=["organization_names", "phone_numbers"],
                priority=9,
                scam_categories=[ScamCategory.REFUND_SCAM],
                turn_range=(2, 6),
            ),
            InvestigativeQuestion(
                question_text="Refund kaise milega? UPI pe ya bank account mein? Details do.",
                question_type=QuestionType.PAYMENT_CLARIFICATION,
                target_intelligence=["upi_ids", "bank_accounts"],
                priority=8,
                scam_categories=[ScamCategory.REFUND_SCAM],
                turn_range=(3, 7),
            ),
            InvestigativeQuestion(
                question_text="Aapka employee ID aur department batao, main verify karunga.",
                question_type=QuestionType.IDENTITY_VERIFICATION,
                target_intelligence=["employee_ids", "names_mentioned"],
                priority=8,
                scam_categories=[ScamCategory.REFUND_SCAM],
                turn_range=(2, 6),
            ),
            InvestigativeQuestion(
                question_text="Email pe refund confirmation bhejo. Aapka email kya hai?",
                question_type=QuestionType.CONTACT_VERIFICATION,
                target_intelligence=["email_addresses"],
                priority=7,
                scam_categories=[ScamCategory.REFUND_SCAM],
                turn_range=(3, 7),
            ),
            InvestigativeQuestion(
                question_text="Office ka address kya hai? Main personally jaaunga agar online nahi hota.",
                question_type=QuestionType.ORGANIZATION_DETAILS,
                target_intelligence=["addresses"],
                priority=6,
                scam_categories=[ScamCategory.REFUND_SCAM],
                turn_range=(4, 8),
            ),
        ],
        ScamCategory.CRYPTO_SCAM: [
            InvestigativeQuestion(
                question_text="Sir kaunsa crypto exchange use karna hai? Platform ka naam batao.",
                question_type=QuestionType.ORGANIZATION_DETAILS,
                target_intelligence=["organization_names"],
                priority=9,
                scam_categories=[ScamCategory.CRYPTO_SCAM],
                turn_range=(2, 6),
            ),
            InvestigativeQuestion(
                question_text="Wallet address kaha pe bhejun? Aur aapka contact number de do confirmation ke liye.",
                question_type=QuestionType.CONTACT_VERIFICATION,
                target_intelligence=["phone_numbers"],
                priority=9,
                scam_categories=[ScamCategory.CRYPTO_SCAM],
                turn_range=(2, 7),
            ),
            InvestigativeQuestion(
                question_text="Minimum investment kitna hai? Payment kahan karna padega - UPI ya bank transfer?",
                question_type=QuestionType.PAYMENT_CLARIFICATION,
                target_intelligence=["upi_ids", "bank_accounts"],
                priority=8,
                scam_categories=[ScamCategory.CRYPTO_SCAM],
                turn_range=(3, 7),
            ),
            InvestigativeQuestion(
                question_text="Aapka referral link ya registration website kya hai?",
                question_type=QuestionType.TECHNICAL_DETAILS,
                target_intelligence=["phishing_links"],
                priority=8,
                scam_categories=[ScamCategory.CRYPTO_SCAM],
                turn_range=(2, 8),
            ),
            InvestigativeQuestion(
                question_text="Aap kaun ho bhai? Manager ya agent? Apna employee ID dena.",
                question_type=QuestionType.IDENTITY_VERIFICATION,
                target_intelligence=["employee_ids", "names_mentioned"],
                priority=7,
                scam_categories=[ScamCategory.CRYPTO_SCAM],
                turn_range=(3, 7),
            ),
            InvestigativeQuestion(
                question_text="Office kahan hai aapka? Main personally aake sign up karunga.",
                question_type=QuestionType.ORGANIZATION_DETAILS,
                target_intelligence=["addresses"],
                priority=6,
                scam_categories=[ScamCategory.CRYPTO_SCAM],
                turn_range=(4, 8),
            ),
        ],
        ScamCategory.SEXTORTION: [
            InvestigativeQuestion(
                question_text="Bhai kaun ho tum? Naam batao apna, police mein complaint karunga.",
                question_type=QuestionType.IDENTITY_VERIFICATION,
                target_intelligence=["names_mentioned"],
                priority=9,
                scam_categories=[ScamCategory.SEXTORTION],
                turn_range=(2, 6),
            ),
            InvestigativeQuestion(
                question_text="Paise kahan bhejne hai? UPI ID ya bank account number do.",
                question_type=QuestionType.PAYMENT_CLARIFICATION,
                target_intelligence=["upi_ids", "bank_accounts"],
                priority=9,
                scam_categories=[ScamCategory.SEXTORTION],
                turn_range=(2, 7),
            ),
            InvestigativeQuestion(
                question_text="Tum kahan se call kar rahe ho? Number kya hai tumhara?",
                question_type=QuestionType.CONTACT_VERIFICATION,
                target_intelligence=["phone_numbers"],
                priority=8,
                scam_categories=[ScamCategory.SEXTORTION],
                turn_range=(2, 6),
            ),
            InvestigativeQuestion(
                question_text="Email pe bhejo proof, mera lawyer dekhega. Tumhara email kya hai?",
                question_type=QuestionType.CONTACT_VERIFICATION,
                target_intelligence=["email_addresses"],
                priority=7,
                scam_categories=[ScamCategory.SEXTORTION],
                turn_range=(3, 7),
            ),
            InvestigativeQuestion(
                question_text="Kaunsi website se yeh sab hua? Link do toh main dekhunga.",
                question_type=QuestionType.TECHNICAL_DETAILS,
                target_intelligence=["phishing_links"],
                priority=7,
                scam_categories=[ScamCategory.SEXTORTION],
                turn_range=(3, 8),
            ),
        ],
        ScamCategory.QR_CODE_SCAM: [
            InvestigativeQuestion(
                question_text="Bhai pehle apna phone number de do, QR scan karne mein dikkat aa rahi hai.",
                question_type=QuestionType.CONTACT_VERIFICATION,
                target_intelligence=["phone_numbers"],
                priority=9,
                scam_categories=[ScamCategory.QR_CODE_SCAM],
                turn_range=(2, 6),
            ),
            InvestigativeQuestion(
                question_text="QR se payment nahi ho raha. UPI ID do direct transfer kar deta hun.",
                question_type=QuestionType.PAYMENT_CLARIFICATION,
                target_intelligence=["upi_ids"],
                priority=9,
                scam_categories=[ScamCategory.QR_CODE_SCAM],
                turn_range=(2, 7),
            ),
            InvestigativeQuestion(
                question_text="Tumhara naam kya hai? OLX pe profile name alag dikh raha hai.",
                question_type=QuestionType.IDENTITY_VERIFICATION,
                target_intelligence=["names_mentioned"],
                priority=8,
                scam_categories=[ScamCategory.QR_CODE_SCAM],
                turn_range=(2, 6),
            ),
            InvestigativeQuestion(
                question_text="Bank account number do, NEFT se kar deta hun. QR kaam nahi kar raha.",
                question_type=QuestionType.PAYMENT_CLARIFICATION,
                target_intelligence=["bank_accounts"],
                priority=8,
                scam_categories=[ScamCategory.QR_CODE_SCAM],
                turn_range=(3, 7),
            ),
            InvestigativeQuestion(
                question_text="Email pe invoice bhej do bhai, record ke liye chahiye.",
                question_type=QuestionType.CONTACT_VERIFICATION,
                target_intelligence=["email_addresses"],
                priority=6,
                scam_categories=[ScamCategory.QR_CODE_SCAM],
                turn_range=(3, 8),
            ),
        ],
        ScamCategory.SIM_SWAP: [
            InvestigativeQuestion(
                question_text="Aap kaunse telecom company se bol rahe ho? Employee ID kya hai?",
                question_type=QuestionType.IDENTITY_VERIFICATION,
                target_intelligence=["organization_names", "employee_ids"],
                priority=9,
                scam_categories=[ScamCategory.SIM_SWAP],
                turn_range=(2, 6),
            ),
            InvestigativeQuestion(
                question_text="Customer care number kya hai? Main verify karunga pehle.",
                question_type=QuestionType.CONTACT_VERIFICATION,
                target_intelligence=["phone_numbers"],
                priority=9,
                scam_categories=[ScamCategory.SIM_SWAP],
                turn_range=(2, 7),
            ),
            InvestigativeQuestion(
                question_text="Near store kahan hai? Main personally jaaunga SIM lene. Address do.",
                question_type=QuestionType.ORGANIZATION_DETAILS,
                target_intelligence=["addresses"],
                priority=8,
                scam_categories=[ScamCategory.SIM_SWAP],
                turn_range=(3, 7),
            ),
            InvestigativeQuestion(
                question_text="Email pe confirmation bhejo upgrade ki. Aapka official email kya hai?",
                question_type=QuestionType.CONTACT_VERIFICATION,
                target_intelligence=["email_addresses"],
                priority=7,
                scam_categories=[ScamCategory.SIM_SWAP],
                turn_range=(3, 7),
            ),
            InvestigativeQuestion(
                question_text="Reference number kya hai is request ka? Main note kar leta hun.",
                question_type=QuestionType.PROCESS_VERIFICATION,
                target_intelligence=["case_ids"],
                priority=7,
                scam_categories=[ScamCategory.SIM_SWAP],
                turn_range=(3, 8),
            ),
        ],
        ScamCategory.DEEPFAKE_IMPERSONATION: [
            InvestigativeQuestion(
                question_text="Sir aap kaun bol rahe ho? Full name aur designation batao.",
                question_type=QuestionType.IDENTITY_VERIFICATION,
                target_intelligence=["names_mentioned", "employee_ids"],
                priority=9,
                scam_categories=[ScamCategory.DEEPFAKE_IMPERSONATION],
                turn_range=(2, 6),
            ),
            InvestigativeQuestion(
                question_text="Aapka direct number kya hai? Main call back karunga verify karne ke liye.",
                question_type=QuestionType.CONTACT_VERIFICATION,
                target_intelligence=["phone_numbers"],
                priority=9,
                scam_categories=[ScamCategory.DEEPFAKE_IMPERSONATION],
                turn_range=(2, 7),
            ),
            InvestigativeQuestion(
                question_text="Kaunsi company se hai yeh request? Official email se verify karo.",
                question_type=QuestionType.ORGANIZATION_DETAILS,
                target_intelligence=["organization_names", "email_addresses"],
                priority=8,
                scam_categories=[ScamCategory.DEEPFAKE_IMPERSONATION],
                turn_range=(2, 7),
            ),
            InvestigativeQuestion(
                question_text="Payment kahan karna hai? Bank details ya UPI ID bhejo.",
                question_type=QuestionType.PAYMENT_CLARIFICATION,
                target_intelligence=["bank_accounts", "upi_ids"],
                priority=8,
                scam_categories=[ScamCategory.DEEPFAKE_IMPERSONATION],
                turn_range=(3, 7),
            ),
            InvestigativeQuestion(
                question_text="Office ka address bata do, main courier kar dunga documents.",
                question_type=QuestionType.ORGANIZATION_DETAILS,
                target_intelligence=["addresses"],
                priority=6,
                scam_categories=[ScamCategory.DEEPFAKE_IMPERSONATION],
                turn_range=(4, 8),
            ),
        ],
    }

    # General questions applicable to ALL scam types
    GENERAL_INVESTIGATIVE_QUESTIONS: List[InvestigativeQuestion] = [
        InvestigativeQuestion(
            question_text="Sir, aapka contact number kya hai? Agar call disconnect ho jaye toh main wapas call karunga.",
            question_type=QuestionType.CONTACT_VERIFICATION,
            target_intelligence=["phone_numbers"],
            priority=10,
            turn_range=(2, 10),
        ),
        InvestigativeQuestion(
            question_text="Company ka registered office kahan hai? Address batao, main samajh jaunga trustworthy hai.",
            question_type=QuestionType.ORGANIZATION_DETAILS,
            target_intelligence=["addresses", "organization_names"],
            priority=8,
            turn_range=(3, 8),
        ),
        InvestigativeQuestion(
            question_text="Aapka email ID kya hai? Main email pe bhi confirm karna chahta hun.",
            question_type=QuestionType.CONTACT_VERIFICATION,
            target_intelligence=["email_addresses"],
            priority=7,
            turn_range=(3, 9),
        ),
        InvestigativeQuestion(
            question_text="Sir aapka full name kya hai? Record ke liye chahiye.",
            question_type=QuestionType.IDENTITY_VERIFICATION,
            target_intelligence=["names_mentioned"],
            priority=7,
            turn_range=(2, 7),
        ),
        InvestigativeQuestion(
            question_text="Reference number ya case ID kya hai? Main note kar leta hun.",
            question_type=QuestionType.PROCESS_VERIFICATION,
            target_intelligence=["case_ids"],
            priority=8,
            turn_range=(2, 8),
        ),
        InvestigativeQuestion(
            question_text="Aap kaunse department se ho? Department head ka naam kya hai?",
            question_type=QuestionType.ORGANIZATION_DETAILS,
            target_intelligence=["organization_names", "names_mentioned"],
            priority=7,
            turn_range=(3, 8),
        ),
        InvestigativeQuestion(
            question_text="Payment kaise karna hai? UPI ID ya bank account details do.",
            question_type=QuestionType.PAYMENT_CLARIFICATION,
            target_intelligence=["upi_ids", "bank_accounts"],
            priority=9,
            turn_range=(3, 9),
        ),
        InvestigativeQuestion(
            question_text="Website hai aapki? Link do, main check karunga pehle.",
            question_type=QuestionType.CONTACT_VERIFICATION,
            target_intelligence=["phishing_links"],
            priority=7,
            turn_range=(2, 8),
        ),
        InvestigativeQuestion(
            question_text="Employee ID ya badge number de do, main verify karwa lunga.",
            question_type=QuestionType.IDENTITY_VERIFICATION,
            target_intelligence=["employee_ids"],
            priority=8,
            turn_range=(3, 8),
        ),
        InvestigativeQuestion(
            question_text="Yeh toh main pehli baar sun raha hun. Kya aap step by step samjha sakte ho?",
            question_type=QuestionType.PROCESS_VERIFICATION,
            target_intelligence=[],
            priority=5,
            turn_range=(2, 6),
        ),
        InvestigativeQuestion(
            question_text="Agar main abhi nahi kar paaya toh kal kar sakta hun kya?",
            question_type=QuestionType.TIME_STALLING,
            target_intelligence=[],
            priority=4,
            turn_range=(4, 9),
        ),
        InvestigativeQuestion(
            question_text="Sir thoda confusing hai, kya aap apni official email se details bhej sakte ho?",
            question_type=QuestionType.CONTACT_VERIFICATION,
            target_intelligence=["email_addresses"],
            priority=7,
            turn_range=(3, 8),
        ),
        InvestigativeQuestion(
            question_text="Aap officer ho toh apna ID number aur department ka phone number batao.",
            question_type=QuestionType.AUTHORITY_CHALLENGE,
            target_intelligence=["employee_ids", "phone_numbers"],
            priority=8,
            turn_range=(3, 8),
        ),
        InvestigativeQuestion(
            question_text="Main apne bete ko puchh ke batata hun. Aapke number pe call karunga 10 minute mein.",
            question_type=QuestionType.TIME_STALLING,
            target_intelligence=["phone_numbers"],
            priority=6,
            turn_range=(4, 9),
        ),
        InvestigativeQuestion(
            question_text="Sir WhatsApp pe apna official ID card bhej do, main trust karunga tab.",
            question_type=QuestionType.IDENTITY_VERIFICATION,
            target_intelligence=["employee_ids"],
            priority=7,
            turn_range=(3, 8),
        ),
    ]

    # Probing follow-ups when a specific entity type is detected in conversation
    PROBING_FOLLOWUPS: Dict[str, List[str]] = {
        "phone_mentioned": [
            "Sir yeh number WhatsApp pe available hai? Main wahan pe bhi message kar sakta hun.",
            "Yeh aapka direct number hai ya office landline? Personal number de do backup ke liye.",
            "Sir agar urgent ho toh kaunsa number pe call karun - yeh wala ya koi aur?",
        ],
        "upi_mentioned": [
            "Sir yeh UPI ID registered kaunse bank se hai? Main cross-verify kar leta hun.",
            "UPI pe payment limit kitni hai? Full amount ek baar mein ho jayega?",
            "Sir yeh UPI aapke naam pe hai ya company ke naam pe registered hai?",
        ],
        "link_mentioned": [
            "Sir yeh link open nahi ho raha. Koi alternate link hai?",
            "Yeh website secure hai na? HTTPS wala? Main check karna chahta hun.",
            "Sir is link ka domain name kya hai? Main tech-savvy friend se confirm karunga.",
        ],
        "organization_mentioned": [
            "Sir aapki company ka GST number kya hai? Main verify kar leta hun.",
            "Company ka customer care number kya hai official? Main call karke confirm karunga.",
            "Aapki company ka social media page hai? Facebook ya LinkedIn pe check kar leta hun.",
        ],
        "email_mentioned": [
            "Sir yeh email ID personal hai ya company ka official email?",
            "Main is email pe reply karunga, aap check kar lena.",
            "Kya yeh email ID company ke domain se hai? Official lagni chahiye.",
        ],
        "case_mentioned": [
            "Sir yeh case number court ka hai ya police ka? Main verify karunga.",
            "Case ki copy mil sakti hai mujhe? Email pe bhej do.",
            "Yeh case kab register hua? Date batao, main check karunga records.",
        ],
    }

    @classmethod
    def get_questions_for_category(
        cls,
        scam_category: ScamCategory,
        turn_count: int,
        extracted_intel: ExtractedIntelligence,
    ) -> List[InvestigativeQuestion]:
        """Get relevant investigative questions for current scam type and turn.

        Combines category-specific and general questions, filters by turn range
        and intel already collected, then sorts by priority.

        Args:
            scam_category: Detected scam type for category-specific questions.
            turn_count: Current conversation turn number.
            extracted_intel: Already extracted intel (to avoid redundant questions).

        Returns:
            List of applicable questions, sorted by priority (descending).
        """
        applicable: List[InvestigativeQuestion] = []

        # Get category-specific questions
        category_questions = cls.IDENTITY_QUESTIONS.get(scam_category, [])
        for q in category_questions:
            if q.turn_range[0] <= turn_count <= q.turn_range[1]:
                if cls._should_ask_question(q, extracted_intel):
                    applicable.append(q)

        # Add general questions that apply to all scam types
        for q in cls.GENERAL_INVESTIGATIVE_QUESTIONS:
            if q.turn_range[0] <= turn_count <= q.turn_range[1]:
                if cls._should_ask_question(q, extracted_intel):
                    applicable.append(q)

        # Sort by priority (descending) so most important questions come first
        applicable.sort(key=lambda x: x.priority, reverse=True)
        return applicable

    @classmethod
    def _should_ask_question(
        cls,
        question: InvestigativeQuestion,
        intel: ExtractedIntelligence,
    ) -> bool:
        """Determine if we should ask this question based on already extracted intel.

        Skips questions whose target intel has already been sufficiently extracted,
        but keeps questions that target still-missing entities.

        Args:
            question: The candidate question.
            intel: Already extracted intelligence.

        Returns:
            True if this question is still relevant and should be asked.
        """
        # If question targets phone and we already have 2+ phones, skip
        if "phone_numbers" in question.target_intelligence and len(intel.phone_numbers) >= 2:
            return False
        if "upi_ids" in question.target_intelligence and len(intel.upi_ids) >= 2:
            return False
        if "email_addresses" in question.target_intelligence and len(intel.email_addresses) >= 2:
            return False
        if "bank_accounts" in question.target_intelligence and len(intel.bank_accounts) >= 2:
            return False
        # Prioritize questions targeting empty intel categories
        for target in question.target_intelligence:
            if len(getattr(intel, target, [])) == 0:
                return True
        # If all targets already have data, lower priority but still ask sometimes
        return len(question.target_intelligence) == 0 or random.random() < 0.3

    @classmethod
    def get_probing_followup(
        cls,
        entity_type: str,
        entity_value: str,
        recent_messages: List[Dict],
    ) -> Optional[str]:
        """Generate a probing follow-up question when a specific entity is detected.

        Args:
            entity_type: Key like "phone_mentioned", "upi_mentioned", etc.
            entity_value: The actual value (phone number, UPI ID, etc.).
            recent_messages: Recent conversation to avoid repeating questions.

        Returns:
            Follow-up question string or None if no suitable question found.
        """
        followups = cls.PROBING_FOLLOWUPS.get(entity_type, [])
        if not followups:
            return None

        # Filter out questions similar to what we've already asked
        recent_agent_msgs = [
            m.get("content", "").lower()
            for m in recent_messages[-5:]
            if m.get("role") == "agent"
        ]

        available = []
        for q in followups:
            q_words = set(q.lower().split()[:5])
            if not any(
                len(q_words & set(am.split()[:8])) >= 3
                for am in recent_agent_msgs
                if am
            ):
                available.append(q)

        return random.choice(available) if available else None


class IntelligenceExtractionPlanner:
    """Strategic planner for intelligence extraction across conversation turns.

    Determines:
    1. Which intelligence types are highest priority based on scam category
    2. Optimal turn timing for each question type
    3. When to probe vs stall vs comply
    """

    EXTRACTION_PRIORITY_MAP: Dict[ScamCategory, List[Tuple[str, int]]] = {
        ScamCategory.DIGITAL_ARREST: [
            ("phone_numbers", 10), ("employee_ids", 9), ("organization_names", 9),
            ("addresses", 8), ("case_ids", 8), ("names_mentioned", 7),
            ("bank_accounts", 6), ("email_addresses", 6),
        ],
        ScamCategory.KYC_PHISHING: [
            ("phishing_links", 10), ("phone_numbers", 9), ("organization_names", 8),
            ("employee_ids", 7), ("upi_ids", 6), ("email_addresses", 6),
        ],
        ScamCategory.BANK_FRAUD: [
            ("phone_numbers", 10), ("bank_accounts", 9), ("employee_ids", 8),
            ("organization_names", 8), ("case_ids", 7), ("email_addresses", 6),
        ],
        ScamCategory.UPI_FRAUD: [
            ("upi_ids", 10), ("phone_numbers", 9), ("organization_names", 8),
            ("order_numbers", 7), ("bank_accounts", 7), ("email_addresses", 6),
        ],
        ScamCategory.PHISHING: [
            ("phishing_links", 10), ("phone_numbers", 9), ("email_addresses", 8),
            ("organization_names", 8), ("order_numbers", 7), ("names_mentioned", 6),
        ],
        ScamCategory.INVESTMENT_FRAUD: [
            ("upi_ids", 10), ("bank_accounts", 9), ("phone_numbers", 9),
            ("organization_names", 8), ("phishing_links", 7), ("email_addresses", 7),
        ],
        ScamCategory.JOB_SCAM: [
            ("phone_numbers", 10), ("organization_names", 9), ("upi_ids", 8),
            ("email_addresses", 8), ("phishing_links", 7), ("addresses", 7),
        ],
        ScamCategory.LOTTERY_PRIZE: [
            ("phone_numbers", 10), ("upi_ids", 9), ("bank_accounts", 9),
            ("organization_names", 8), ("email_addresses", 7), ("case_ids", 7),
        ],
        ScamCategory.CUSTOMS_PARCEL: [
            ("phone_numbers", 10), ("order_numbers", 9), ("bank_accounts", 9),
            ("employee_ids", 8), ("organization_names", 8), ("case_ids", 7),
        ],
        ScamCategory.ROMANCE_SCAM: [
            ("phone_numbers", 10), ("bank_accounts", 9), ("names_mentioned", 9),
            ("addresses", 8), ("email_addresses", 7), ("phishing_links", 7),
        ],
        ScamCategory.TECH_SUPPORT: [
            ("phone_numbers", 10), ("organization_names", 9), ("phishing_links", 8),
            ("employee_ids", 8), ("case_ids", 7), ("email_addresses", 7),
        ],
        ScamCategory.LOAN_FRAUD: [
            ("upi_ids", 10), ("bank_accounts", 9), ("phone_numbers", 9),
            ("organization_names", 8), ("case_ids", 7), ("email_addresses", 7),
        ],
        ScamCategory.REFUND_SCAM: [
            ("phone_numbers", 10), ("organization_names", 9), ("upi_ids", 8),
            ("case_ids", 8), ("bank_accounts", 7), ("email_addresses", 7),
        ],
        ScamCategory.CRYPTO_SCAM: [
            ("phone_numbers", 10), ("organization_names", 9), ("upi_ids", 8),
            ("phishing_links", 8), ("bank_accounts", 7), ("email_addresses", 7),
        ],
        ScamCategory.SEXTORTION: [
            ("phone_numbers", 10), ("upi_ids", 9), ("bank_accounts", 9),
            ("email_addresses", 8), ("names_mentioned", 7), ("phishing_links", 7),
        ],
        ScamCategory.QR_CODE_SCAM: [
            ("upi_ids", 10), ("phone_numbers", 9), ("bank_accounts", 9),
            ("names_mentioned", 7), ("email_addresses", 6),
        ],
        ScamCategory.SIM_SWAP: [
            ("phone_numbers", 10), ("organization_names", 9), ("employee_ids", 8),
            ("email_addresses", 7), ("case_ids", 7), ("addresses", 6),
        ],
        ScamCategory.DEEPFAKE_IMPERSONATION: [
            ("phone_numbers", 10), ("names_mentioned", 9), ("organization_names", 9),
            ("email_addresses", 8), ("bank_accounts", 7), ("employee_ids", 7),
        ],
    }

    DEFAULT_PRIORITIES: List[Tuple[str, int]] = [
        ("phone_numbers", 10), ("upi_ids", 9), ("organization_names", 8),
        ("phishing_links", 7), ("bank_accounts", 7), ("email_addresses", 6),
    ]

    @classmethod
    def get_extraction_strategy(
        cls,
        scam_category: ScamCategory,
        turn_count: int,
        extracted_intel: ExtractedIntelligence,
    ) -> Dict[str, Any]:
        """Get strategic extraction plan for current turn.

        Identifies highest-priority missing intel and recommends question approach.

        Args:
            scam_category: Detected scam type.
            turn_count: Current conversation turn.
            extracted_intel: Already extracted intelligence.

        Returns:
            Dict with primary_target, secondary_targets, recommended_question_type,
            and urgency_level.
        """
        priorities = cls.EXTRACTION_PRIORITY_MAP.get(
            scam_category, cls.DEFAULT_PRIORITIES
        )

        # Find highest priority missing intel
        for intel_type, priority in priorities:
            intel_list = getattr(extracted_intel, intel_type, [])
            if len(intel_list) == 0:
                secondary = [
                    t for t, p in priorities[1:4] if t != intel_type
                ]
                return {
                    "primary_target": intel_type,
                    "secondary_targets": secondary,
                    "recommended_question_type": cls._map_intel_to_question_type(intel_type),
                    "urgency_level": "high" if priority >= 9 else "medium",
                }

        # If we have at least some of everything, still suggest deepening
        return {
            "primary_target": priorities[0][0] if priorities else "phone_numbers",
            "secondary_targets": [t for t, _ in priorities[1:3]],
            "recommended_question_type": QuestionType.ORGANIZATION_DETAILS,
            "urgency_level": "low",
        }

    @classmethod
    def _map_intel_to_question_type(cls, intel_type: str) -> QuestionType:
        """Map intelligence type to the most appropriate question type.

        Args:
            intel_type: Intelligence field name (e.g. 'phone_numbers').

        Returns:
            Matching QuestionType enum value.
        """
        mapping = {
            "phone_numbers": QuestionType.CONTACT_VERIFICATION,
            "upi_ids": QuestionType.PAYMENT_CLARIFICATION,
            "employee_ids": QuestionType.IDENTITY_VERIFICATION,
            "organization_names": QuestionType.ORGANIZATION_DETAILS,
            "addresses": QuestionType.ORGANIZATION_DETAILS,
            "phishing_links": QuestionType.CONTACT_VERIFICATION,
            "bank_accounts": QuestionType.PAYMENT_CLARIFICATION,
            "email_addresses": QuestionType.CONTACT_VERIFICATION,
            "case_ids": QuestionType.PROCESS_VERIFICATION,
            "order_numbers": QuestionType.PROCESS_VERIFICATION,
            "names_mentioned": QuestionType.IDENTITY_VERIFICATION,
        }
        return mapping.get(intel_type, QuestionType.IDENTITY_VERIFICATION)
