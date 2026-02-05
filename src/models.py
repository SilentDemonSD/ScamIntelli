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


# ========== GUVI Hackathon Format Models ==========

class MessageContent(BaseModel):
    """Incoming message structure per GUVI hackathon spec."""
    model_config = ConfigDict(extra='ignore')
    sender: str = Field(..., description="Sender: 'scammer' or 'user'")
    text: str = Field(..., description="Message content")
    timestamp: Optional[Union[int, str]] = Field(default=None, description="Epoch ms or ISO-8601 timestamp")


class ConversationMessage(BaseModel):
    """A single message in the conversation history (hackathon format)."""
    model_config = ConfigDict(extra='ignore')
    sender: str = Field(..., description="Sender: 'scammer' or 'user'")
    text: str = Field(..., description="Message content")
    timestamp: Optional[Union[int, str]] = Field(default=None, description="Epoch ms or ISO timestamp")


class Metadata(BaseModel):
    """Request metadata."""
    model_config = ConfigDict(extra='ignore')
    channel: str = Field(default="SMS", description="Channel: SMS, WhatsApp, Email, Chat")
    language: str = Field(default="English", description="Language name")
    locale: str = Field(default="IN", description="Locale/region code")


class HoneypotRequest(BaseModel):
    """Incoming honeypot API request - GUVI Hackathon format."""
    model_config = ConfigDict(extra='ignore')
    sessionId: str = Field(..., description="Unique session identifier")
    message: Union[MessageContent, dict, Any] = Field(..., description="Incoming message object")
    conversationHistory: List[Union[ConversationMessage, dict]] = Field(
        default_factory=list, 
        description="Previous messages in conversation"
    )
    metadata: Optional[Union[Metadata, dict, Any]] = Field(default=None, description="Request metadata")


class EngagementMetrics(BaseModel):
    """Metrics about the honeypot engagement - Hackathon format."""
    engagementDurationSeconds: int = Field(default=0, description="Total engagement duration")
    totalMessagesExchanged: int = Field(default=0, description="Total message count")


class HoneypotSimpleResponse(BaseModel):
    """Simple honeypot API response - GUVI expects this format."""
    status: str = Field(default="success", description="Response status")
    reply: str = Field(..., description="AI agent reply to scammer")


class HoneypotResponse(BaseModel):
    """Full honeypot API response - for detailed tracking."""
    status: str = Field(default="success", description="Response status")
    scamDetected: bool = Field(..., description="Whether scam was detected")
    agentResponse: Optional[str] = Field(default=None, description="AI agent response to scammer")
    engagementMetrics: EngagementMetrics = Field(
        default_factory=EngagementMetrics, 
        description="Engagement statistics"
    )
    extractedIntelligence: "GuviExtractedIntelligence" = Field(
        default_factory=lambda: GuviExtractedIntelligence(),
        description="Extracted intelligence data"
    )
    agentNotes: Optional[str] = Field(default=None, description="Summary notes from agent")
    sessionId: str = Field(..., description="Session identifier")
    conversationComplete: bool = Field(default=False, description="Whether conversation is complete")


# ========== End GUVI Format Models ==========


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
    """Intelligence model with camelCase for GUVI callback (hackathon format)."""
    bankAccounts: List[str] = Field(default_factory=list)
    upiIds: List[str] = Field(default_factory=list)
    phishingLinks: List[str] = Field(default_factory=list)
    phoneNumbers: List[str] = Field(default_factory=list)
    suspiciousKeywords: List[str] = Field(default_factory=list)


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
    """Payload for GUVI hackathon evaluation endpoint."""
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
