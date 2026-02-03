# ScamIntelli - Scam Honeypot Agent

A stateful, agentic honeypot API that detects scam intent, impersonates a realistic user persona, autonomously engages scammers, extracts structured intelligence, and reports results to the evaluation system.

## Features

- **Scam Detection**: Hybrid scoring using keywords, intent classification, and pattern matching
- **Persona Engine**: Generates realistic Indian user responses using Gemini AI
- **Intelligence Extraction**: Extracts UPI IDs, phone numbers, phishing links, and suspicious keywords
- **Multi-turn Engagement**: Maintains conversation state for authentic scammer interaction
- **GUVI Callback**: Submits structured intelligence reports upon session completion

## Tech Stack

- Python 3.11+
- FastAPI
- Pydantic v2
- Google Gemini AI
- Redis (optional, in-memory fallback available)

## Installation

```bash
pip install -r requirements.txt
cp .env.example .env
```

## Configuration

Edit `.env` with your credentials:

- `API_KEY`: Your API key for endpoint authentication
- `GEMINI_API_KEY`: Google Gemini API key
- `GUVI_CALLBACK_URL`: Callback endpoint for intelligence submission
- `REDIS_URL`: Redis connection URL (optional)
- `USE_REDIS`: Set to `true` to use Redis, `false` for in-memory storage

## Running the Server

```bash
uvicorn src.api_gateway.app:app --host 0.0.0.0 --port 8000 --reload
```

## Docker

```bash
docker-compose -f docker/docker-compose.yml up --build
```

## API Endpoints

### POST /api/v1/message
Process incoming message and return agent response.

**Headers:**
- `X-API-Key`: Your API key

**Request Body:**
```json
{
  "session_id": "unique-session-id",
  "message": "Your account will be blocked. Send UPI details immediately."
}
```

**Response:**
```json
{
  "status": "success",
  "reply": "Why will my account be blocked? I didn't get any message from bank.",
  "session_id": "unique-session-id",
  "scam_detected": true,
  "engagement_active": true
}
```

### GET /api/v1/session/{session_id}
Get session state and extracted intelligence.

### DELETE /api/v1/session/{session_id}
End session and trigger GUVI callback.

## Project Structure

```
scam-honeypot/
├── src/
│   ├── api_gateway/
│   ├── session_manager/
│   ├── scam_detector/
│   ├── agent_controller/
│   ├── persona_engine/
│   ├── intelligence_extractor/
│   ├── callback_worker/
│   └── utils/
├── tests/
├── docker/
└── requirements.txt
```

## License

MIT License
