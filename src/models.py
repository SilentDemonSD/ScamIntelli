from pydantic import BaseModel, Field
from typing import List
from enum import Enum
from datetime import datetime, timezone


class PersonaStyle(str, Enum):
    ANXIOUS = "anxious"
    CONFUSED = "confused"
    COOPERATIVE = "cooperative"


class MessageRequest(BaseModel):
    session_id: str = Field(..., min_length=1)
    message: str = Field(..., min_length=1)


class AgentReply(BaseModel):
    status: str
    reply: str
    session_id: str
    scam_detected: bool
    engagement_active: bool


class ExtractedIntelligence(BaseModel):
    bank_accounts: List[str] = Field(default_factory=list)
    upi_ids: List[str] = Field(default_factory=list)
    phishing_links: List[str] = Field(default_factory=list)
    phone_numbers: List[str] = Field(default_factory=list)
    suspicious_keywords: List[str] = Field(default_factory=list)


class SessionState(BaseModel):
    session_id: str
    persona_style: PersonaStyle = PersonaStyle.CONFUSED
    extracted_intel: ExtractedIntelligence = Field(default_factory=ExtractedIntelligence)
    turn_count: int = 0
    confidence_level: float = 0.5
    scam_detected: bool = False
    engagement_active: bool = True
    messages: List[dict] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    last_updated: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class GuviCallbackPayload(BaseModel):
    sessionId: str
    scamDetected: bool
    totalMessagesExchanged: int
    extractedIntelligence: dict
    agentNotes: str


class ScamScore(BaseModel):
    keyword_score: float = 0.0
    intent_score: float = 0.0
    pattern_score: float = 0.0
    total_score: float = 0.0
    is_scam: bool = False


class SessionResponse(BaseModel):
    session_id: str
    scam_detected: bool
    engagement_active: bool
    turn_count: int
    extracted_intelligence: ExtractedIntelligence


class EndSessionResponse(BaseModel):
    status: str
    session_id: str
    callback_sent: bool
    total_messages: int
    extracted_intelligence: ExtractedIntelligence


class HealthResponse(BaseModel):
    status: str
    timestamp: datetime


class ErrorResponse(BaseModel):
    status: str = "error"
    detail: str
