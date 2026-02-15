# ScamIntelli — AI-Powered Honeypot Scam Detection API

An intelligent honeypot system that detects, engages, and extracts intelligence from scam conversations in real-time. Built with a hybrid 11-layer scam detection engine, persona-driven engagement, and graph-based fraud network analysis.

## Description

ScamIntelli acts as an AI-powered honeypot that simulates a vulnerable victim to scammers while:

1. **Detecting scams** using an 11-layer hybrid scoring engine combining a 5-model ML ensemble (LightGBM, XGBoost, Random Forest, Gradient Boosting, Logistic Regression), keyword analysis, behavioral patterns, and Google Gemini LLM verification.
2. **Extracting intelligence** — phone numbers, bank accounts, UPI IDs, phishing links, and email addresses — from scam conversations using regex pattern matching and NLP.
3. **Engaging scammers** with adaptive persona-based responses (confused elderly, gullible student, busy professional) in English and Hinglish to maximize engagement duration and message count.
4. **Mapping fraud networks** via Neo4j graph database to identify connected scam operations, kingpins, and fraud rings.

### Approach & Strategy

- **Detection**: Messages pass through keyword scoring, hard-indicator pattern matching (UPI/bank/OTP), ML ensemble prediction (97.6% accuracy, F1=0.978), TF-IDF vectorization, URL/document analysis, multilingual translation (Sarvam API for Hindi, Bengali, Tamil, Telugu), and Gemini LLM cross-verification. Scores are weighted and combined for final scam probability.
- **Engagement**: Once a scam is detected, the system selects a persona profile and generates context-aware responses that appear genuine to the scammer, using age-adaptive language, emotional intelligence, and realistic typing delays.
- **Intelligence Extraction**: Regex-based extractors capture phone numbers (Indian format with +91), UPI IDs, bank account numbers, phishing URLs, and email addresses. Both original and normalized formats are preserved for maximum match coverage.
- **Graph Intelligence**: Neo4j stores entities and their relationships, enabling fraud ring detection via community analysis and kingpin identification through centrality metrics.

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
| Testing | pytest + pytest-asyncio (377 tests) |

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

All 377 tests should pass.

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
  "status": "engaged",
  "scamDetected": true,
  "scamType": "bank_fraud",
  "confidence": 0.92,
  "extractedIntelligence": {
    "phoneNumbers": ["+91-9876543210"],
    "bankAccounts": ["1234567890123456"],
    "upiIds": ["scammer@fakebank"],
    "phishingLinks": [],
    "emailAddresses": []
  },
  "engagementMetrics": {
    "totalMessagesExchanged": 6,
    "engagementDurationSeconds": 120
  },
  "agentNotes": "Bank fraud detected with high confidence. Scammer requesting OTP and account details."
}
```

### Other Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/v1/health` | GET | Health check |
| `/api/v1/health/ready` | GET | Readiness check (Redis, Neo4j, ML model) |
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

## Supported Scam Types

| Scam Type | Description |
|-----------|-------------|
| `bank_fraud` | Fake bank alerts requesting account/OTP |
| `upi_fraud` | UPI payment scams and fake refunds |
| `phishing` | Malicious links and credential harvesting |
| `digital_arrest` | Fake law enforcement threats |
| `investment_fraud` | Fake crypto/stock schemes |
| `lottery_scam` | Fake prize/lottery notifications |
| `tech_support` | Fake technical support scams |
| `job_scam` | Fake employment offers |
| `insurance_fraud` | Fake insurance claims |
| `identity_theft` | Social engineering for personal data |

## Architecture Overview

```
┌─────────────┐     ┌──────────────┐     ┌──────────────────┐
│   Scammer    │────▶│  Nginx (TLS) │────▶│  FastAPI (4 wkr) │
└─────────────┘     └──────────────┘     └─────────┬────────┘
                                                   │
                    ┌──────────────────────────────┤
                    │                              │
              ┌─────▼──────┐              ┌───────▼────────┐
              │   Redis 7   │              │  Hybrid Engine  │
              │  (sessions) │              │  (11-layer)     │
              └─────────────┘              └───────┬────────┘
                                                   │
                    ┌──────────────┬───────────────┤
                    │              │               │
              ┌─────▼──────┐ ┌────▼─────┐  ┌─────▼──────┐
              │  ML Ensemble│ │ Gemini   │  │  Keyword   │
              │  (5 models) │ │ LLM API  │  │  Patterns  │
              └─────────────┘ └──────────┘  └────────────┘
                                                   │
                                            ┌──────▼───────┐
                                            │   Neo4j 5    │
                                            │ (fraud graph)│
                                            └──────────────┘
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
│   │   └── strategy.py                    # Engagement strategy
│   ├── scam_detector/
│   │   ├── hybrid_engine.py               # 11-layer detection engine
│   │   ├── ml_engine.py                   # ML model inference
│   │   ├── classifier.py                  # Rule-based classification
│   │   ├── keywords.py                    # Scam keyword patterns
│   │   ├── multilingual_detector.py       # Sarvam API translation
│   │   ├── url_document_detector.py       # URL/document analysis
│   │   ├── train_model.py                 # Model training script
│   │   └── training_pipeline.py           # Online learning pipeline
│   ├── intelligence_extractor/
│   │   ├── extractor.py                   # Phone/UPI/bank extraction
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
│   │   └── guvi_callback.py               # GUVI callback integration
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
│   ├── training_data.jsonl                # Training dataset
│   └── training_metrics.json              # Model performance metrics
├── tests/                                 # 377 tests
│   ├── test_scam_scenarios.py             # 73 end-to-end scenario tests
│   ├── test_extraction_unit.py            # 35 extraction unit tests
│   ├── test_detector.py                   # Detection engine tests
│   ├── test_agent.py                      # Agent controller tests
│   └── ...
├── docker/
│   ├── Dockerfile
│   ├── docker-compose.yml                 # 5-service orchestration
│   ├── gunicorn.conf.py                   # Gunicorn configuration
│   ├── nginx/                             # Nginx reverse proxy config
│   └── k8s/                               # Kubernetes manifests
└── docs/
    └── architecture/                      # Architecture Decision Records
```

## Self-Testing

Use the Python self-test script from the submission guidelines to validate your deployment:

```python
import requests
import uuid
from datetime import datetime

ENDPOINT_URL = "https://scamintelli.mysterysd.in/api/v1/honeypot"
API_KEY = "your-api-key"

test_scenario = {
    "scenarioId": "bank_fraud",
    "name": "Bank Fraud Detection",
    "scamType": "bank_fraud",
    "initialMessage": (
        "URGENT: Your SBI account has been compromised. "
        "Your account will be blocked in 2 hours. "
        "Share your account number and OTP immediately "
        "to verify your identity."
    ),
    "metadata": {"channel": "SMS", "language": "English", "locale": "IN"},
    "maxTurns": 10,
    "fakeData": {
        "bankAccount": "1234567890123456",
        "upiId": "scammer.fraud@fakebank",
        "phoneNumber": "+91-9876543210",
    },
}


def test_honeypot_api():
    session_id = str(uuid.uuid4())
    conversation_history = []
    headers = {"Content-Type": "application/json", "x-api-key": API_KEY}

    for turn in range(1, test_scenario["maxTurns"] + 1):
        if turn == 1:
            scammer_message = test_scenario["initialMessage"]
        else:
            scammer_message = input("Enter scammer message (or 'quit'): ")
            if scammer_message.lower() == "quit":
                break

        message = {
            "sender": "scammer",
            "text": scammer_message,
            "timestamp": datetime.utcnow().isoformat() + "Z",
        }

        request_body = {
            "sessionId": session_id,
            "message": message,
            "conversationHistory": conversation_history,
            "metadata": test_scenario["metadata"],
        }

        response = requests.post(
            ENDPOINT_URL, headers=headers, json=request_body, timeout=30
        )
        response_data = response.json()
        honeypot_reply = (
            response_data.get("reply")
            or response_data.get("message")
            or response_data.get("text")
        )

        print(f"Turn {turn} | Honeypot: {honeypot_reply}")
        conversation_history.append(message)
        conversation_history.append(
            {
                "sender": "user",
                "text": honeypot_reply,
                "timestamp": datetime.utcnow().isoformat() + "Z",
            }
        )


if __name__ == "__main__":
    test_honeypot_api()
```

## License

This project is licensed under the terms specified in the [LICENSE](LICENSE) file.
