import random
from google import genai
from src.models import PersonaStyle, SessionState
from src.config import get_settings

settings = get_settings()

# Initialize Gemini client (will be created lazily)
_genai_client = None


def _get_genai_client():
    global _genai_client
    if _genai_client is None and settings.gemini_api_key:
        _genai_client = genai.Client(api_key=settings.gemini_api_key)
    return _genai_client

PERSONA_RESPONSES = {
    PersonaStyle.ANXIOUS: [
        "Oh no, what is happening? I got very scared reading this.",
        "Please don't block my account, I need it for my salary.",
        "What should I do? I am very worried now.",
        "Is this really from the bank? I am getting nervous.",
        "My heart is beating fast, please tell me what to do.",
    ],
    PersonaStyle.CONFUSED: [
        "I don't understand all this, can you explain simply?",
        "What is KYC? I never heard of this before.",
        "Why will my account be blocked? I didn't do anything wrong.",
        "I don't use net banking much, what app should I open?",
        "Is this happening today only? I am confused.",
    ],
    PersonaStyle.COOPERATIVE: [
        "Okay okay, I will do whatever you say.",
        "Tell me step by step, I will follow.",
        "Should I give you my details? Which ones?",
        "I trust you, please help me fix this.",
        "What information do you need from me?",
    ]
}

CLARIFICATION_RESPONSES = [
    "But which app should I use? I have many apps.",
    "What is UPI ID? Is it same as phone number?",
    "Should I call my bank also? What is the number?",
    "I am at work, can I do this later?",
    "My son handles all this, should I ask him?",
]

DELAY_RESPONSES = [
    "Wait, let me check my phone.",
    "One minute, I am trying to find the app.",
    "Hold on, I need to remember my password.",
    "Let me ask my family member, they know these things.",
    "I am in a meeting, can you wait 5 minutes?",
]


async def generate_persona_response(
    session: SessionState,
    scammer_message: str,
    use_ai: bool = True
) -> str:
    if use_ai and settings.gemini_api_key:
        try:
            return await _generate_ai_response(session, scammer_message)
        except Exception:
            pass
    
    return await _generate_template_response(session)


async def _generate_ai_response(session: SessionState, scammer_message: str) -> str:
    client = _get_genai_client()
    if client is None:
        raise ValueError("Gemini API key not configured")
    
    conversation_history = "\n".join([
        f"{'Scammer' if msg.get('role') == 'scammer' else 'Me'}: {msg.get('content', '')}"
        for msg in session.messages[-5:]
    ])
    
    prompt = f"""You are pretending to be a confused, naive Indian user who received a scam message. 
Your persona style is: {session.persona_style.value}

RULES:
1. Never reveal you know it's a scam
2. Act confused, anxious, or overly cooperative based on persona
3. Ask naive questions to keep the scammer talking
4. Use simple English with occasional Hindi words (like "haan", "kya", "accha")
5. Show partial trust but delay giving real information
6. Keep responses short (1-2 sentences)
7. Never mention RBI, fraud, scam, or police

Recent conversation:
{conversation_history}

Latest scammer message: {scammer_message}

Generate a believable response as the confused victim:"""

    response = await client.aio.models.generate_content(
        model="gemini-2.0-flash",
        contents=prompt
    )
    return response.text.strip()


async def _generate_template_response(session: SessionState) -> str:
    turn = session.turn_count
    
    if turn <= 2:
        responses = PERSONA_RESPONSES.get(session.persona_style, PERSONA_RESPONSES[PersonaStyle.CONFUSED])
    elif turn <= 5:
        responses = CLARIFICATION_RESPONSES
    else:
        responses = DELAY_RESPONSES + PERSONA_RESPONSES.get(session.persona_style, [])
    
    return random.choice(responses)


async def get_exit_response() -> str:
    exit_responses = [
        "I think I need to call my bank directly, thank you.",
        "My son is telling me not to share anything, sorry.",
        "I will visit my bank branch tomorrow, bye.",
        "I don't think I should share this on phone.",
        "Let me talk to my family first, I will call back.",
    ]
    return random.choice(exit_responses)


async def select_persona_style(message_count: int, scam_intensity: float) -> PersonaStyle:
    if message_count <= 3:
        return PersonaStyle.CONFUSED
    elif scam_intensity > 0.8:
        return PersonaStyle.ANXIOUS
    else:
        return PersonaStyle.COOPERATIVE
