from pydantic import BaseModel, Field, ConfigDict
from typing import List, Optional, Union, Any
from enum import Enum
from datetime import datetime, timezone


class PersonaStyle(str, Enum):
    ANXIOUS = "anxious"
    CONFUSED = "confused"
    COOPERATIVE = "cooperative"


class MessageRequest(BaseModel):
    session_id: str = Field(..., min_length=1)
    message: str = Field(..., min_length=1)


class MessageContent(BaseModel):
    model_config = ConfigDict(extra='ignore')
    sender: str = Field(..., description="Sender: 'scammer' or 'user'")
    text: str = Field(..., description="Message content")
    timestamp: Optional[Union[int, str]] = Field(default=None)


class ConversationMessage(BaseModel):
    model_config = ConfigDict(extra='ignore')
    sender: str = Field(...)
    text: str = Field(...)
    timestamp: Optional[Union[int, str]] = Field(default=None)


class Metadata(BaseModel):
    model_config = ConfigDict(extra='ignore')
    channel: str = Field(default="SMS")
    language: str = Field(default="English")
    locale: str = Field(default="IN")


class HoneypotRequest(BaseModel):
    model_config = ConfigDict(extra='ignore')
    sessionId: str = Field(...)
    message: Union[MessageContent, dict, Any] = Field(...)
    conversationHistory: List[Union[ConversationMessage, dict]] = Field(default_factory=list)
    metadata: Optional[Union[Metadata, dict, Any]] = Field(default=None)


class EngagementMetrics(BaseModel):
    engagementDurationSeconds: int = Field(default=0)
    totalMessagesExchanged: int = Field(default=0)


class HoneypotSimpleResponse(BaseModel):
    status: str = Field(default="success")
    reply: str = Field(...)


class HoneypotResponse(BaseModel):
    status: str = Field(default="success")
    scamDetected: bool = Field(...)
    agentResponse: Optional[str] = Field(default=None)
    engagementMetrics: EngagementMetrics = Field(default_factory=EngagementMetrics)
    extractedIntelligence: "GuviExtractedIntelligence" = Field(default_factory=lambda: GuviExtractedIntelligence())
    agentNotes: Optional[str] = Field(default=None)
    sessionId: str = Field(...)
    conversationComplete: bool = Field(default=False)


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


class GuviExtractedIntelligence(BaseModel):
    bankAccounts: List[str] = Field(default_factory=list)
    upiIds: List[str] = Field(default_factory=list)
    phishingLinks: List[str] = Field(default_factory=list)
    phoneNumbers: List[str] = Field(default_factory=list)
    suspiciousKeywords: List[str] = Field(default_factory=list)


class SessionState(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True)
    
    session_id: str
    persona_style: PersonaStyle = PersonaStyle.CONFUSED
    persona_type: Optional[Any] = Field(default=None)
    scam_category: Optional[Any] = Field(default=None)
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
    extractedIntelligence: GuviExtractedIntelligence
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
