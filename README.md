<div align="center">

# ScamIntelli

### AI-Powered Scam Honeypot Agent

An autonomous, multi-layered honeypot system that detects scam intent in real-time, impersonates believable Indian user personas, engages scammers across extended conversations, and extracts actionable intelligence — powered by a 10-layer hybrid detection engine with ML capabilities.

[![Python 3.11+](https://img.shields.io/badge/Python-3.11+-blue.svg)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.100+-green.svg)](https://fastapi.tiangolo.com)
[![Tests](https://img.shields.io/badge/Tests-218%20Passing-brightgreen.svg)]()
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

</div>

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────┐
│                        API Gateway (FastAPI)                        │
│  /message  /honeypot  /session  /health  /summary  /stats  /logs   │
├─────────────────────────────────────────────────────────────────────┤
│                         Security Layer                              │
│  ┌─────────────────┐  ┌──────────────────┐  ┌──────────────────┐   │
│  │  Tamper-Proof    │  │  Jailbreak Guard │  │  Rate Limiter    │   │
│  │  Middleware      │  │  (5 Attack Types)│  │  Anti-Fingerprint│   │
│  └────────┬────────┘  └────────┬─────────┘  └────────┬─────────┘   │
├───────────┴────────────────────┴──────────────────────┴─────────────┤
│                    Agent Controller (Strategy)                       │
│  ┌──────────────────────────────────────────────────────────────┐   │
│  │  ConversationContextTracker  │  EngagementStrategy (16 cats) │   │
│  └──────────────────────────────────────────────────────────────┘   │
├─────────────────────────────────────────────────────────────────────┤
│              10-Layer Hybrid Scam Detection Engine                   │
│  ┌──────────┬──────────┬──────────┬──────────┬──────────────────┐   │
│  │ Keyword  │  Intent  │ Pattern  │ Emotion  │  Behavioral      │   │
│  │  (0.12)  │  (0.25)  │  (0.12)  │  (0.08)  │   (0.08)        │   │
│  ├──────────┼──────────┼──────────┼──────────┼──────────────────┤   │
│  │URL Threat│Multilang │Multi-Vec │ML Model  │Learned Patterns  │   │
│  │  (0.08)  │  (0.04)  │  (0.05)  │  (0.12)  │   (0.06)        │   │
│  └──────────┴──────────┴──────────┴──────────┴──────────────────┘   │
├─────────────────────────────────────────────────────────────────────┤
│                        Persona Engine                               │
│  ┌────────────────┐  ┌──────────────┐  ┌────────────────────────┐  │
│  │ 12 Persona     │  │  Emotional   │  │  Age-Adaptive Engine   │  │
│  │ Types + Gemini │  │  Intelligence│  │  (Senior/Mid/Young)    │  │
│  ├────────────────┤  ├──────────────┤  ├────────────────────────┤  │
│  │ ResponseSelf   │  │  Typing      │  │  Language-Adaptive     │  │
│  │ Corrector      │  │  Simulator   │  │  (6 Language Styles)   │  │
│  └────────────────┘  └──────────────┘  └────────────────────────┘  │
├─────────────────────────────────────────────────────────────────────┤
│  ┌──────────────────┐  ┌──────────────────┐  ┌─────────────────┐   │
│  │  Intelligence    │  │  Session Manager │  │  GUVI Callback  │   │
│  │  Extractor       │  │  (Redis/Memory)  │  │  Worker (HTTP/2)│   │
│  └──────────────────┘  └──────────────────┘  └─────────────────┘   │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Key Features

### 1. 10-Layer Hybrid Scam Detection Engine

Weighted multi-signal scoring system combining 10 independent detection layers:

| Layer | Weight | Description |
|-------|--------|-------------|
| **Keyword Scoring** | 0.12 | 250+ bilingual keywords across 15 categories with severity weighting |
| **Intent Classification** | 0.25 | 5-signal intent scoring (digital arrest, threats, urgency, credentials, payment) |
| **Pattern Matching** | 0.12 | URL detection, UPI handles, phone numbers, action phrases, video call requests |
| **Emotional Analysis** | 0.08 | 9 emotional states + 8 manipulation pattern detection |
| **Behavioral Escalation** | 0.08 | Threat density tracking, urgency progression, credential pressure analysis |
| **URL Threat Analysis** | 0.08 | Phishing URLs, lookalike domains, homograph attacks, URL shortener expansion |
| **Multilingual Detection** | 0.04 | 11 Indian languages, Unicode script detection, code-switching analysis |
| **Multi-Vector Attack** | 0.05 | Detects combined attack vectors (URL + credentials + threats + social engineering) |
| **ML Model (LightGBM)** | 0.12 | 25-feature ML model with heuristic fallback when model unavailable |
| **Learned Patterns** | 0.06 | Adaptive n-gram patterns learned from previous scam conversations |

Hard indicator detection and multi-vector boosting provide additional confidence overrides.

### 2. 12 Persona Types

Each persona has unique personality traits, language preferences, response templates, delay phrases, and exit strategies:

| Persona | Description | Target Scams |
|---------|-------------|-------------|
| `ELDERLY_ANXIOUS` | Scared senior, easily confused by technology | Digital arrest, KYC phishing |
| `TECH_NAIVE` | Non-technical user, slow to understand | Tech support, refund scams |
| `DESPERATE_JOBSEEKER` | Unemployed, eager for opportunities | Job scams, investment fraud |
| `GREEDY_INVESTOR` | Interested in quick returns | Investment fraud, crypto scams |
| `WORRIED_PARENT` | Concerned about family and children | Sextortion, digital arrest |
| `RURAL_FARMER` | Limited tech/banking exposure | Loan fraud, lottery scams |
| `YOUNG_STUDENT` | College student, low balance | Job scams, QR code scams |
| `BUSY_PROFESSIONAL` | Always in meetings, limited attention | SIM swap, refund scams |
| `LONELY_SENIOR` | Isolated, craves conversation | Romance scams, lottery |
| `FIRST_TIME_SELLER` | New to online marketplaces | QR code scams, refund scams |
| `SCARED_VICTIM` | Already anxious about previous scams | Digital arrest, customs |
| `TRUSTING_HOUSEWIFE` | Trusting, handles household finances | KYC phishing, loan fraud |

### 3. 16 Scam Categories

Each category has severity ratings (5–10), tactical descriptions, recommended personas, and engagement turn limits:

| Category | Severity | Max Turns |
|----------|----------|-----------|
| Digital Arrest | 10 | 12 |
| KYC Phishing | 8 | 8 |
| Investment Fraud | 8 | 10 |
| Job Scam | 7 | 10 |
| Lottery/Prize | 6 | 6 |
| Romance Scam | 7 | 15 |
| Tech Support | 7 | 8 |
| Customs/Parcel | 8 | 10 |
| Loan Fraud | 7 | 8 |
| Crypto Scam | 8 | 10 |
| Deepfake Impersonation | 9 | 12 |
| SIM Swap | 9 | 8 |
| QR Code Scam | 7 | 6 |
| Refund Scam | 7 | 8 |
| Sextortion | 9 | 5 |
| Unknown | 5 | 8 |

### 4. ML-Powered Adaptive Detection

LightGBM-based machine learning engine with 25 extracted features:

- **Text Features** — Message length, word count, average word length, uppercase ratio
- **Entity Detection** — URLs, phone numbers, emails, UPI IDs
- **Keyword Density** — Urgency, threat, credential, and payment keyword counts
- **Structural Analysis** — Currency symbols, number counts, special character ratio
- **Language Features** — Hindi word ratio, consecutive caps, sentiment negativity
- **Information Theory** — Message entropy, repeated character ratio
- **Session Context** — Turn count, escalation score, multi-vector count

Graceful fallback to weighted heuristic scoring when LightGBM/NumPy are unavailable. Training samples are automatically persisted for future model improvement.

### 5. Emotional Intelligence Engine

Detects 9 emotional states and 8 manipulation patterns in scammer messages:

**Emotional States**: Fear, Greed, Urgency, Trust, Confusion, Anger, Sadness, Excitement, Neutral

**Manipulation Patterns**: Fear Escalation, Urgency Pressure, Greed Exploitation, Authority Intimidation, Emotional Blackmail, Trust Building, Isolation Tactics, Shame Inducement

Includes 40+ emoji sentiment analysis, per-session escalation tracking, and persona emotion mirroring.

### 6. Multilingual Detection (11 Languages)

Unicode script detection for Devanagari, Bengali, Tamil, Telugu, Kannada, Malayalam, Gujarati, and Gurmukhi. Romanized Hindi detection with 58 Hindi + 28 Hinglish scam keywords. Regional keyword sets for Tamil, Bengali, and Telugu. Optional Sarvam AI translation integration. Code-switching analysis (inter-sentential, intra-sentential, tag-switching).

### 7. Age-Adaptive Persona Engine

3 demographic profiles (Senior 55+, Middle-Aged 35–55, Young Adult 18–35):

- **Typing Speed** — 15/40/55 WPM respectively
- **Typo Generation** — Adjacent key errors, character swaps, doubles, skips
- **Senior Artifacts** — Random caps, double spaces, long corrections
- **Young Adult Patterns** — Abbreviations (16 pairs), slang (12 items), skeptical phrases
- **Intel Extraction** — Age-appropriate information gathering strategies

### 8. URL & Document Threat Analysis

- **Phishing Detection** — 20 suspicious TLDs, IP-based URLs, path keyword analysis
- **Lookalike Domains** — 7 major brand targets (SBI, HDFC, ICICI, Paytm, PhonePe, RBI, Income Tax) with 35+ fake domain patterns
- **Homograph Attacks** — 17 Cyrillic-to-Latin character mappings
- **URL Shortener Expansion** — 16 shortener domains with async HTTP redirect following
- **Misleading Subdomains** — Detection of legitimate brand names used as subdomains

### 9. Meta-Scam Detection

Detects when scammers attempt to identify the honeypot:

- **38 honeypot probe patterns** (bilingual) — "Are you a bot?", "Kya tum AI ho?"
- **25 reverse psychology patterns** — "I know this is a scam"
- **16 capability probe patterns** — "What model are you using?"
- **Timing analysis** — rapid requests, uniform intervals
- **Message hash deduplication** — repeated message detection
- **Counter-responses** — in-character deflection per probe type

### 10. Security Layer

**Tamper-Proof Middleware** — Request fingerprinting, bot UA detection (13 patterns), suspicious header analysis (8 patterns), request timing analysis (>30/min, <0.5s intervals)

**Jailbreak Guard** — 5 attack vector protection:
- Prompt injection (27 bilingual patterns)
- Persona hijacking (17 patterns)
- Prompt leaking (18 patterns)
- Encoding attacks (7 regex: base64, eval/exec, hex/unicode escapes)
- Token overflow (500 word threshold)

**Anti-Fingerprinting** — Response jitter, randomized error messages, internal state masking, response humanization with fillers and typos

### 11. Human Typing Simulator

WPM-based delay calculation per age group. 4 typo generation strategies (swap, adjacent key, double, skip). Age-specific correction formats. Thinking pauses and error correction delays.

### 12. Intelligence Extraction

Automatically extracts from scammer messages:
- **UPI IDs** — Email filtering and normalization
- **Phone Numbers** — +91 normalization and 6–9 first digit validation
- **Phishing Links** — Excluding 25 trusted domains
- **Bank Accounts** — 16-digit cards, 9–18 digit accounts with banking context verification
- **Suspicious Keywords** — Matching against 250+ keyword corpus

---

## Tech Stack

| Component | Technology |
|-----------|------------|
| Framework | FastAPI + Pydantic v2 |
| Language | Python 3.11+ |
| LLM | Google Gemini (gemini-3-flash-preview) |
| ML Engine | LightGBM + NumPy |
| HTTP Client | httpx (HTTP/2) |
| Session Storage | Redis (optional) / In-Memory |
| Validation | Pydantic Settings + Custom Validators |
| Testing | pytest + pytest-asyncio |
| Deployment | Docker + Koyeb |

---

## API Endpoints

All endpoints are prefixed with `/api/v1` and require `X-API-Key` header authentication (except `/health`).

### POST `/api/v1/message`

Process an incoming scammer message and return the agent's persona response.

```json
// Request
{
  "session_id": "unique-session-id",
  "message": "Your account will be blocked. Send UPI details immediately."
}

// Response
{
  "status": "success",
  "reply": "Kya hua? Mera account block ho jaayega? Bank se koi message nahi aaya...",
  "session_id": "unique-session-id",
  "scam_detected": true,
  "engagement_active": true
}
```

### POST `/api/v1/honeypot`

GUVI-compatible honeypot endpoint with structured request/response format.

```json
// Request
{
  "sessionId": "session-123",
  "message": { "sender": "scammer", "text": "Send OTP now!" },
  "conversationHistory": [],
  "metadata": { "channel": "SMS", "language": "English", "locale": "IN" }
}

// Response
{
  "status": "success",
  "reply": "OTP? Ek minute, phone mein message dhundh raha hun..."
}
```

### GET `/api/v1/session/{session_id}`

Retrieve session state including scam detection status and extracted intelligence.

### DELETE `/api/v1/session/{session_id}`

End session, trigger GUVI callback if scam was detected, and clean up.

### GET `/api/v1/health`

Health check endpoint (no authentication required).

### GET `/api/v1/summary/{session_id}`

Get engagement summary with conversation analysis.

### GET `/api/v1/stats`

Aggregated system statistics: total sessions, scam detections, intelligence gathered, ML model info, per-session breakdown.

### GET `/api/v1/logs`

Real-time application log buffer (last 500 entries). Supports query parameters:
- `limit` — int, max 500
- `level` — INFO, WARNING, ERROR
- `source` — filter by logger name

---

## Project Structure

```
ScamIntelli/
├── src/
│   ├── config.py                          # Settings (Pydantic)
│   ├── models.py                          # Request/response models
│   ├── api_gateway/
│   │   ├── app.py                         # FastAPI app, lifespan, rate limiter
│   │   └── routes.py                      # 8 API route handlers
│   ├── agent_controller/
│   │   ├── agent_state.py                 # Agent state definitions
│   │   └── strategy.py                    # EngagementStrategy, ContextTracker
│   ├── scam_detector/
│   │   ├── classifier.py                  # Core 3-signal scam scoring
│   │   ├── keywords.py                    # 250+ keywords, 15 categories
│   │   ├── scam_types.py                  # 16 ScamCategory definitions
│   │   ├── hybrid_engine.py               # 10-layer detection orchestrator
│   │   ├── ml_engine.py                   # LightGBM ML + feature extraction
│   │   ├── meta_detector.py               # Anti-probe detection
│   │   ├── multilingual_detector.py       # 11-language detection
│   │   └── url_document_detector.py       # URL threat + phishing analysis
│   ├── persona_engine/
│   │   ├── personas.py                    # 12 personas, Gemini, self-correction
│   │   ├── persona_generator.py           # Simplified persona fallback
│   │   ├── emotional_intelligence.py      # Emotion + manipulation analysis
│   │   ├── age_adaptive.py                # Age-group adaptation
│   │   └── typing_simulator.py            # WPM delays + typo generation
│   ├── security/
│   │   ├── tamper_proof.py                # Request fingerprinting
│   │   └── jailbreak_guard.py             # LLM jailbreak prevention
│   ├── intelligence_extractor/
│   │   └── extractor.py                   # UPI, phone, bank, link extraction
│   ├── callback_worker/
│   │   └── guvi_callback.py               # HTTP/2 callback with retry
│   ├── session_manager/
│   │   └── session_store.py               # Redis + in-memory storage
│   └── utils/
│       ├── logging.py                     # Structured logging + LogBuffer
│       └── validation.py                  # Input sanitization
├── tests/
│   ├── test_agent.py                      # Core agent tests
│   ├── test_detector.py                   # Scam detector tests
│   ├── test_extractor.py                  # Intelligence extraction tests
│   ├── test_callback.py                   # GUVI callback tests
│   ├── test_new_features.py               # Feature v1 tests (36)
│   ├── test_new_features_v2.py            # Feature v2 tests (73)
│   └── test_api_comprehensive.py          # API + ML + pipeline tests (73)
├── docker/
│   ├── Dockerfile                         # Python 3.11-slim image
│   └── docker-compose.yml                 # API + Redis orchestration
├── requirements.txt
├── pytest.ini
└── LICENSE
```

---

## Installation

### Prerequisites

- Python 3.11+
- Google Gemini API key
- Redis (optional)

### Setup

```bash
git clone https://github.com/SilentDemonSD/ScamIntelli.git
cd ScamIntelli
python -m venv .venv
.venv/Scripts/activate      # Windows
source .venv/bin/activate   # Linux/macOS
pip install -r requirements.txt
cp .env.example .env
```

### Environment Variables

```env
API_KEY=your-api-key
GEMINI_API_KEY=your-gemini-api-key
GUVI_CALLBACK_URL=https://callback-endpoint.com
REDIS_URL=redis://localhost:6379
USE_REDIS=false
LOG_LEVEL=INFO
SESSION_TIMEOUT_SECONDS=3600
MAX_ENGAGEMENT_TURNS=15
SCAM_THRESHOLD=0.7
ENABLE_TAMPER_PROTECTION=true
MAX_CONCURRENT_SESSIONS=1000
RATE_LIMIT_PER_MINUTE=60
```

### Run

```bash
uvicorn src.api_gateway.app:app --host 0.0.0.0 --port 8000 --reload
```

### Docker

```bash
docker-compose -f docker/docker-compose.yml up --build
```

### Tests

```bash
pytest tests/ -v --tb=short
```

```
218 passed in ~60s
```

---

## Deployment

Deployed on **Koyeb**: `https://possible-crane-primegenz-8819088f.koyeb.app/`

Health check: `GET /api/v1/health`

---

## License

MIT License
