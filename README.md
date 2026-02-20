# ScamIntelli — AI-Powered Honeypot Scam Detection API

An intelligent honeypot system that detects, engages, and extracts intelligence from scam conversations in real-time. Built with a hybrid 11-layer scam detection engine, persona-driven engagement, and graph-based fraud network analysis.

## Description

ScamIntelli acts as an AI-powered honeypot that simulates a vulnerable victim to scammers while:

1. **Detecting scams** using an 11-layer hybrid scoring engine combining a 5-model ML ensemble (LightGBM, XGBoost, Random Forest, Gradient Boosting, Logistic Regression), keyword analysis, behavioral patterns, and Google Gemini LLM verification.
2. **Extracting intelligence** — phone numbers, bank accounts, UPI IDs, phishing links, email addresses, case IDs, policy numbers, order numbers, and more — from scam conversations using regex pattern matching and NLP across 13 intelligence categories.
3. **Engaging scammers** with adaptive persona-based responses (confused elderly, gullible student, busy professional) in English and Hinglish, powered by a question engine (19 scam categories × investigative questions) and a red flag tracker (12 behavioral indicators) to maximize engagement duration, message count, and intelligence extraction.
4. **Mapping fraud networks** via Neo4j graph database to identify connected scam operations, kingpins, and fraud rings.

## Approach

### How We Detect Scams

Messages pass through the **Hybrid 11-Layer Detection Engine**:

1. **Keyword Scoring** — 200+ weighted scam keywords across 16 categories (urgency, threat, payment, credential, digital arrest, investment, etc.).
2. **Hard Indicator Patterns** — Regex-based instant detection of UPI IDs, bank references, OTP requests. Hard indicators trigger scam detection with a 0.70 confidence floor.
3. **ML Ensemble** — 5-model soft voting ensemble (LightGBM, XGBoost, Random Forest, Gradient Boosting, Logistic Regression) trained on 3,390 samples achieving 97.64% accuracy and F1=0.978.
4. **TF-IDF Similarity** — Cosine similarity against the training corpus.
5. **URL/Document Detection** — Suspicious URL patterns and document-based phishing detection.
6. **Urgency Language** — Time pressure phrases, CAPS usage, exclamation frequency.
7. **Multilingual Translation** — Sarvam AI API translates Hindi, Bengali, Tamil, Telugu messages to English for re-detection.
8. **Gemini LLM Cross-Verification** — Google Gemini analyzes the full conversation for structured scam assessment.
9. **Cumulative Session Scoring** — Aggregates detection signals across all turns for persistent scam tracking.
10. **Online Pattern Learning** — Live pattern updates from confirmed scams stored in `learned_patterns.json`.
11. **Meta-Detection** — Ensemble of all layer scores for final weighted confidence computation.

Scores are weighted and combined into a final confidence score (threshold: 0.4). The detection engine runs authentically on every message — no hardcoded responses.

### How We Extract Intelligence

Regex-based extractors run on every message and accumulate intelligence across all conversation turns:

| Category | Method | Example |
|----------|--------|---------|
| Phone Numbers | Indian +91 format regex | `+91-9876543210` |
| Bank Accounts | 8-18 digit pattern matching | `1234567890123456` |
| UPI IDs | @provider pattern matching | `user@paytm`, `user@ybl` |
| Phishing Links | URL pattern detection | `http://fake-bank.com/verify` |
| Email Addresses | Standard email regex | `scammer@example.com` |
| Case IDs | Reference/case number patterns | `CBI-2025-001234` |
| Policy Numbers | Insurance policy patterns | `POL-123456789` |
| Order Numbers | Order ID patterns | `ORD-2025-5678` |
| Organization Names | NLP entity extraction | `SBI Fraud Department` |
| Addresses | Location pattern matching | `123 MG Road, Mumbai` |
| Employee IDs | ID pattern extraction | `EMP-SBI-12345` |
| Names Mentioned | Name entity extraction | `Inspector Rajesh Kumar` |
| Suspicious Keywords | Scam vocabulary detection | `OTP`, `verify`, `blocked` |

Both original and normalized formats are preserved for maximum match coverage.

### How We Maintain Engagement

1. **Persona Selection** — Dynamically selects from persona profiles (confused elderly, gullible student, busy professional) based on scam type severity.
2. **Question Engine** — 19 scam-category-specific question banks with 9 question types (identity verification, organization details, contact verification, process verification, authority challenge, time stalling, payment clarification, technical confusion, technical details). Probing follow-ups fire automatically when specific intel types (phone, UPI, link, email) are detected.
3. **Red Flag Tracker** — Detects 12 behavioral indicators (urgency escalation, threat patterns, authority impersonation, etc.) and generates targeted probing questions based on detected flags.
4. **Age-Adaptive Language** — Adjusts vocabulary, sentence length, and formality based on persona age profile.
5. **Emotional Intelligence** — Calibrates fear, confusion, and trust in responses to appear as a genuine victim.
6. **Typing Delay Simulation** — WPM-based realistic typing delays for natural conversation pacing.
7. **Gemini LLM Responses** — Context-aware response generation using Google Gemini with multi-key rotation and full conversation history.

## Tech Stack

| Component | Technology |
|-----------|------------|
| Language | Python 3.12 |
| Framework | FastAPI + Uvicorn (async) |
| WSGI Server | Gunicorn (4 workers, UvicornWorker) |
| LLM | Google Gemini (multi-key rotation) |
| ML Models | LightGBM, XGBoost, Random Forest, Gradient Boosting, Logistic Regression (5-model ensemble) |
| ML Libraries | scikit-learn, LightGBM, XGBoost |
| Session Store | Redis 7 (Alpine) |
| Graph Database | Neo4j 5 Community |
| Translation | Sarvam AI API (multilingual) |
| Reverse Proxy | Nginx 1.27 (Alpine, TLS/HTTP2) |
| Containerization | Docker Compose (5 services) |
| Testing | pytest + pytest-asyncio (455 tests) |

### Key Libraries

- `fastapi` — async REST API framework
- `pydantic` / `pydantic-settings` — request validation and configuration
- `httpx` — async HTTP client (Gemini & Sarvam API calls)
- `redis` — session storage and distributed locking
- `neo4j` — graph database driver
- `google-genai` — Google Gemini generative AI
- `scikit-learn` — ML pipeline, TF-IDF vectorization, model ensembling
- `lightgbm` / `xgboost` — gradient boosting classifiers
- `networkx` — in-memory graph analysis for fraud ring detection
- `joblib` — model serialization

## Setup Instructions

### Prerequisites

- Python 3.12+
- Docker & Docker Compose
- Google Gemini API key(s)
- Sarvam AI API key (for multilingual support)

### 1. Clone the Repository

```bash
git clone https://github.com/SilentDemonSD/ScamIntelli.git
cd ScamIntelli
```

### 2. Install Dependencies

```bash
pip install -r requirements.txt
```

### 3. Set Environment Variables

Copy the example environment file and fill in your keys:

```bash
cp .env.example .env
```

Edit `.env` with your values:

```env
API_KEY=your_api_key
GEMINI_API_KEY=your_gemini_api_key
GEMINI_API_KEYS=key1,key2,key3
SARVAM_API_KEY=your_sarvam_api_key
GUVI_CALLBACK_URL=your_callback_url
REDIS_URL=redis://localhost:6379
USE_REDIS=true
NEO4J_ENABLED=true
NEO4J_URI=bolt://localhost:7687
NEO4J_USER=neo4j
NEO4J_PASSWORD=your_neo4j_password
```

### 4. Run with Docker Compose (Recommended)

```bash
cd docker
docker compose up -d --build
```

This starts 5 services:
- **nginx** — reverse proxy with TLS termination (ports 80/443)
- **api** — FastAPI application (4 Gunicorn workers)
- **worker** — background task queue processor
- **redis** — session storage and caching
- **neo4j** — fraud network graph database

### 5. Run Locally (Development)

```bash
uvicorn src.api_gateway.app:app --host 0.0.0.0 --port 8000 --reload
```

### 6. Run Tests

```bash
python -m pytest tests/ -q --tb=short
```

All 455 tests should pass.

## API Endpoint

| Property | Value |
|----------|-------|
| **URL** | `https://scamintelli.mysterysd.in/api/v1/honeypot` |
| **Method** | `POST` |
| **Authentication** | `x-api-key` header |
| **Content-Type** | `application/json` |

### Request Format

```json
{
  "sessionId": "unique-session-uuid",
  "message": {
    "sender": "scammer",
    "text": "URGENT: Your SBI account has been compromised...",
    "timestamp": "2025-01-01T00:00:00Z"
  },
  "conversationHistory": [],
  "metadata": {
    "channel": "SMS",
    "language": "English",
    "locale": "IN"
  }
}
```

### Response Format

```json
{
  "reply": "Oh no! Which account? I have so many...",
  "status": "success",
  "scamDetected": true,
  "scamType": "bank_fraud",
  "confidence": 0.92,
  "extractedIntelligence": {
    "phoneNumbers": ["+91-9876543210"],
    "bankAccounts": ["1234567890123456"],
    "upiIds": ["scammer@fakebank"],
    "phishingLinks": [],
    "emailAddresses": [],
    "suspiciousKeywords": ["urgent", "compromised", "OTP"],
    "caseIds": [],
    "policyNumbers": [],
    "orderNumbers": [],
    "organizationNames": ["SBI"],
    "addresses": [],
    "employeeIds": [],
    "namesMentioned": []
  },
  "engagementMetrics": {
    "totalMessagesExchanged": 6,
    "engagementDurationSeconds": 120
  },
  "agentNotes": "Bank fraud detected with high confidence. Scammer requesting OTP and account details. Red flags: urgency pressure, credential request, authority impersonation."
}
```

### Callback Payload (Final Output)

After each turn, the system dispatches a callback with the full session analysis:

```json
{
  "sessionId": "abc123-session-id",
  "scamDetected": true,
  "scamType": "bank_fraud",
  "totalMessagesExchanged": 18,
  "engagementDurationSeconds": 240,
  "confidenceLevel": 0.92,
  "extractedIntelligence": {
    "phoneNumbers": ["+91-9876543210"],
    "bankAccounts": ["1234567890123456"],
    "upiIds": ["scammer.fraud@fakebank"],
    "phishingLinks": [],
    "emailAddresses": [],
    "suspiciousKeywords": ["urgent", "OTP", "blocked"],
    "caseIds": [],
    "policyNumbers": [],
    "orderNumbers": [],
    "organizationNames": ["SBI Fraud Department"],
    "addresses": [],
    "employeeIds": [],
    "namesMentioned": []
  },
  "engagementMetrics": {
    "engagementDurationSeconds": 240,
    "totalMessagesExchanged": 18
  },
  "agentNotes": "Scammer claimed to be from SBI fraud department. Detected red flags: urgency escalation, OTP request, account freeze threat."
}
```

### Other Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/v1/health` | GET | Health check |
| `/api/v1/health/ready` | GET | Readiness check (Redis, Neo4j, ML model) |
| `/api/v1/detect` | POST | Standalone scam detection (no engagement) |
| `/api/v1/message` | POST | Alternative message endpoint |
| `/api/v1/session/{id}` | GET | Get session details |
| `/api/v1/session/{id}/end` | POST | End session and get final report |
| `/api/v1/stats` | GET | System statistics |

## ML Model Performance

| Metric | Value |
|--------|-------|
| Accuracy | 97.64% |
| Precision | 98.64% |
| Recall | 97.05% |
| F1 Score | 0.9784 |
| Cross-Validation Mean | 96.72% |
| Training Samples | 3,390 |
| Features | 545 |
| Training Time | 7.19s |

### Per-Model Accuracy (Ensemble)

| Model | Accuracy |
|-------|----------|
| Logistic Regression | 99.41% |
| XGBoost | 94.25% |
| LightGBM | 97.05% |
| Random Forest | 93.07% |
| Gradient Boosting | 95.87% |

## Supported Scam Types (19 Categories)

| Scam Type | Description |
|-----------|-------------|
| `bank_fraud` | Fake bank alerts requesting account/OTP |
| `upi_fraud` | UPI payment scams and fake refunds |
| `phishing` | Malicious links and credential harvesting |
| `kyc_phishing` | Fake KYC verification requiring personal data |
| `digital_arrest` | Fake law enforcement threats and PMLA claims |
| `investment_fraud` | Fake crypto/stock/forex investment schemes |
| `lottery_prize` | Fake prize/lottery/lucky draw notifications |
| `tech_support` | Fake technical support and remote access scams |
| `job_scam` | Fake employment offers and work-from-home scams |
| `romance_scam` | Romance-based social engineering and gift scams |
| `customs_parcel` | Fake customs/parcel detention fee scams |
| `loan_fraud` | Fake instant loan and processing fee scams |
| `crypto_scam` | Cryptocurrency fraud and wallet scams |
| `deepfake_impersonation` | AI-generated impersonation attacks |
| `sim_swap` | SIM card swap and mobile takeover scams |
| `qr_code_scam` | Malicious QR code payment scams |
| `refund_scam` | Fake refund and excess credit scams |
| `sextortion` | Blackmail with fake private video/webcam threats |

## Architecture Overview

```
┌─────────────┐     ┌──────────────┐     ┌──────────────────┐
│   Scammer    │────▶│  Nginx (TLS) │────▶│  FastAPI (4 wkr) │
└─────────────┘     └──────────────┘     └─────────┬────────┘
                                                   │
          ┌────────────────┬───────────────────────┤
          │                │                       │
    ┌─────▼──────┐  ┌─────▼──────┐        ┌──────▼────────┐
    │   Redis 7   │  │ Question   │        │ Hybrid Engine  │
    │  (sessions) │  │ Engine +   │        │  (11-layer)    │
    └─────────────┘  │ Red Flag   │        └──────┬────────┘
                     │ Tracker    │               │
                     └────────────┘   ┌───────────┼───────────┐
                                      │           │           │
                                ┌─────▼───┐ ┌────▼────┐ ┌───▼──────┐
                                │ML Ensemble│ │ Gemini │ │ Keyword  │
                                │(5 models)│ │ LLM API│ │ Patterns │
                                └──────────┘ └────────┘ └──────────┘
                                                              │
                                              ┌───────────────┤
                                              │               │
                                        ┌─────▼──────┐ ┌─────▼──────┐
                                        │  Neo4j 5   │ │ Callback   │
                                        │(fraud graph)│ │ (per turn) │
                                        └────────────┘ └────────────┘
```

See [docs/architecture.md](docs/architecture.md) for detailed architecture documentation.

## Project Structure

```
ScamIntelli/
├── README.md
├── requirements.txt
├── pytest.ini
├── .env.example
├── src/
│   ├── config.py                          # Pydantic settings
│   ├── models.py                          # Request/response models
│   ├── api_gateway/
│   │   ├── app.py                         # FastAPI application
│   │   └── routes.py                      # All API endpoints
│   ├── agent_controller/
│   │   ├── agent_state.py                 # Agent state management
│   │   ├── strategy.py                    # Engagement strategy pipeline
│   │   ├── question_engine.py             # Investigative question bank (19 categories)
│   │   └── red_flag_tracker.py            # Behavioral red flag detection (12 types)
│   ├── scam_detector/
│   │   ├── hybrid_engine.py               # 11-layer detection engine
│   │   ├── ml_engine.py                   # ML model inference
│   │   ├── classifier.py                  # Rule-based classification
│   │   ├── keywords.py                    # Scam keyword patterns (16 categories)
│   │   ├── scam_types.py                  # 19 scam category profiles
│   │   ├── multilingual_detector.py       # Sarvam API translation
│   │   ├── url_document_detector.py       # URL/document analysis
│   │   ├── train_model.py                 # Model training script
│   │   └── training_pipeline.py           # Online learning pipeline
│   ├── intelligence_extractor/
│   │   ├── extractor.py                   # 13-category intelligence extraction
│   │   ├── network_analyzer.py            # Fraud network analysis
│   │   └── behavioral_fingerprint.py      # Scammer fingerprinting
│   ├── persona_engine/
│   │   ├── personas.py                    # Persona profiles & Gemini
│   │   ├── persona_generator.py           # Dynamic persona selection
│   │   ├── emotional_intelligence.py      # Emotional response tuning
│   │   ├── age_adaptive.py                # Age-based language adaptation
│   │   └── typing_simulator.py            # Realistic typing delays
│   ├── session_manager/
│   │   ├── session_store.py               # Redis session management
│   │   └── distributed_lock.py            # Redis distributed locking
│   ├── graph/
│   │   ├── graph_backend.py               # In-memory graph backend
│   │   └── neo4j_backend.py               # Neo4j graph operations
│   ├── resilience/
│   │   ├── circuit_breaker.py             # Circuit breaker pattern
│   │   └── backpressure.py                # Backpressure controller
│   ├── security/
│   │   ├── jailbreak_guard.py             # Jailbreak detection
│   │   └── tamper_proof.py                # Response integrity
│   ├── callback_worker/
│   │   └── guvi_callback.py               # Callback integration (every turn)
│   ├── task_queue/
│   │   ├── broker.py                      # Redis stream task broker
│   │   └── workers.py                     # Background task workers
│   └── utils/
│       ├── logging.py                     # Structured logging
│       └── validation.py                  # Input sanitization
├── models/
│   ├── ensemble_detector.joblib           # Trained ensemble model
│   ├── tfidf_vectorizer.joblib            # TF-IDF vectorizer
│   ├── feature_scaler.joblib              # Feature scaler
│   ├── learned_patterns.json              # Online-learned patterns
│   ├── training_data.jsonl                # Training dataset (3,390 samples)
│   └── training_metrics.json              # Model performance metrics
├── tests/                                 # 455 tests across 19 test files
│   ├── test_scam_scenarios.py             # End-to-end scenario tests
│   ├── test_extraction_unit.py            # Intelligence extraction unit tests
│   ├── test_detector.py                   # Detection engine tests
│   ├── test_agent.py                      # Agent controller tests
│   ├── test_question_engine.py            # Question engine tests
│   ├── test_red_flag_tracker.py           # Red flag tracker tests
│   └── ...                                # 13 more test modules
├── docker/
│   ├── Dockerfile
│   ├── docker-compose.yml                 # 5-service orchestration
│   ├── gunicorn.conf.py                   # Gunicorn configuration
│   ├── nginx/                             # Nginx reverse proxy config
│   └── k8s/                               # Kubernetes manifests
└── docs/
    └── architecture.md                    # Detailed architecture documentation
```

## License

This project is licensed under the terms specified in the [LICENSE](LICENSE) file.
