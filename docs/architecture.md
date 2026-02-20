# ScamIntelli — System Architecture

A comprehensive guide to the ScamIntelli system architecture, from high-level overview to component-level implementation details.

---

## Table of Contents

1. [System Overview](#system-overview)
2. [Request Flow](#request-flow)
3. [Infrastructure Layer](#infrastructure-layer)
4. [API Gateway](#api-gateway)
5. [Scam Detection Engine](#scam-detection-engine)
6. [Intelligence Extraction](#intelligence-extraction)
7. [Persona Engine](#persona-engine)
8. [Session Management](#session-management)
9. [Graph Intelligence](#graph-intelligence)
10. [Resilience Patterns](#resilience-patterns)
11. [Security Layer](#security-layer)
12. [ML Pipeline](#ml-pipeline)
13. [Deployment Architecture](#deployment-architecture)
14. [Data Flow Diagrams](#data-flow-diagrams)

---

## System Overview

ScamIntelli is a real-time scam honeypot API that processes incoming scam messages, detects fraud intent, extracts intelligence, and responds with persona-driven replies designed to keep scammers engaged. The system is built as a set of loosely coupled, async-first Python modules running behind Nginx inside Docker.

### Core Responsibilities

| Responsibility | Component | Purpose |
|---------------|-----------|---------|
| **Detect** | Hybrid Engine | Determine if a message is a scam using 11 scoring layers |
| **Extract** | Intelligence Extractor | Pull phone numbers, bank accounts, UPI IDs, links, emails |
| **Engage** | Persona Engine | Generate realistic victim-like responses via Gemini LLM |
| **Map** | Graph Backend (Neo4j) | Build fraud network graphs, detect rings, identify kingpins |
| **Store** | Session Manager (Redis) | Persist conversation state across turns and workers |

### High-Level Architecture

```
Internet
    │
    ▼
┌─────────────────────────────────────────────────────────┐
│                    Nginx (TLS/HTTP2)                     │
│  - Cloudflare IP passthrough                            │
│  - Rate limiting & bot protection                       │
│  - Reverse proxy to upstream API workers                │
└────────────────────────┬────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────┐
│              Gunicorn (4 UvicornWorkers)                  │
│                                                          │
│  ┌────────────────────────────────────────────────────┐  │
│  │               FastAPI Application                   │  │
│  │                                                     │  │
│  │  /api/v1/honeypot  ─── Main honeypot endpoint       │  │
│  │  /api/v1/message   ─── Alternative message API      │  │
│  │  /api/v1/health    ─── Health & readiness checks    │  │
│  │  /api/v1/session   ─── Session management           │  │
│  │  /api/v1/stats     ─── System statistics            │  │
│  └────────────────────────────────────────────────────┘  │
└──────────┬──────────┬──────────┬──────────┬─────────────┘
           │          │          │          │
     ┌─────▼────┐ ┌───▼───┐ ┌───▼───┐ ┌───▼────┐
     │  Redis 7 │ │Neo4j 5│ │Gemini │ │Sarvam  │
     │(sessions)│ │(graph)│ │ (LLM) │ │(trans) │
     └──────────┘ └───────┘ └───────┘ └────────┘
```

---

## Request Flow

When a scammer sends a message to the `/api/v1/honeypot` endpoint, the following happens:

### Step-by-Step Processing

```
1. REQUEST ARRIVES
   │
   ├─ Nginx terminates TLS, applies rate limits
   ├─ Forwards to one of 4 Gunicorn workers
   │
2. API GATEWAY (routes.py)
   │
   ├─ Validates x-api-key header
   ├─ Validates request body (sessionId, message, metadata)
   ├─ Sanitizes input text (XSS, injection prevention)
   ├─ Applies tamper-proof validation
   │
3. SESSION MANAGEMENT
   │
   ├─ Loads or creates session from Redis
   ├─ Adds message to conversation history
   ├─ Tracks turn count, timestamps, engagement metrics
   │
4. SCAM DETECTION (hybrid_engine.py)
   │
   ├─ Layer 1:  Keyword scoring (200+ scam keywords)
   ├─ Layer 2:  Hard indicator patterns (UPI, bank, OTP)
   ├─ Layer 3:  ML ensemble prediction (5 models)
   ├─ Layer 4:  TF-IDF similarity scoring
   ├─ Layer 5:  URL/document detection
   ├─ Layer 6:  Urgency language detection
   ├─ Layer 7:  Multilingual translation + recheck
   ├─ Layer 8:  Gemini LLM cross-verification
   ├─ Layer 9:  Cumulative session scoring
   ├─ Layer 10: Pattern learning (online)
   ├─ Layer 11: Meta-detection (ensemble of ensembles)
   │
   ├─ Weighted combination → final confidence score
   ├─ Scam type classification
   │
5. INTELLIGENCE EXTRACTION (extractor.py)
   │
   ├─ Phone number extraction (Indian +91 format)
   ├─ Bank account number extraction
   ├─ UPI ID extraction (@upi, @paytm, etc.)
   ├─ Phishing link extraction
   ├─ Email address extraction
   ├─ Preserves both original and normalized formats
   │
6. PERSONA RESPONSE (personas.py)
   │
   ├─ Select persona profile (elderly, student, professional)
   ├─ Build context-aware prompt with conversation history
   ├─ Call Gemini API with multi-key rotation
   ├─ Apply age-adaptive language adjustment
   ├─ Apply emotional intelligence modifiers
   ├─ Simulate realistic typing delay
   │
7. GRAPH INTELLIGENCE (neo4j_backend.py)
   │
   ├─ Store extracted entities in Neo4j
   ├─ Link entities to scammer/session nodes
   ├─ Detect fraud rings (community detection)
   ├─ Identify kingpins (centrality analysis)
   │
8. RESPONSE ASSEMBLY
   │
   ├─ Build JSON response with all required fields
   ├─ Update session in Redis
   ├─ Enqueue background tasks (callback, graph, fingerprint)
   ├─ Return response to scammer
```

### Timing Budget

| Operation | Target | Timeout |
|-----------|--------|---------|
| Total request | < 30s | 60s |
| Gemini LLM call | < 5s | 15s |
| ML inference | < 100ms | — |
| Redis operations | < 10ms | 5s |
| Neo4j writes | async | 30s |
| Sarvam translation | < 3s | 10s |

---

## Infrastructure Layer

### Docker Compose Services

The system runs as 5 Docker containers orchestrated by Docker Compose:

| Service | Image | Role | Resources |
|---------|-------|------|-----------|
| `nginx` | nginx:1.27-alpine | TLS termination, reverse proxy, rate limiting | 0.15 CPU, 96MB |
| `api` | Custom (Dockerfile) | FastAPI app serving all endpoints | 0.70 CPU, 2560MB |
| `worker` | Custom (Dockerfile) | Background task processor | 0.35 CPU, 512MB |
| `redis` | redis:7-alpine | Session storage, task queues, caching | 0.25 CPU, 640MB |
| `neo4j` | neo4j:5-community | Fraud network graph database | 0.30 CPU, 512MB |

### Nginx Configuration

- **TLS termination** with HTTP/2 support
- **Cloudflare IP passthrough** using `real_ip_from` directives
- **Bot protection** blocks common scanners with 444 responses
- **Proxy timeouts**: 90s read, 30s connect
- **Upstream** load balances across API container (port 8000)

### Gunicorn Configuration

- **Workers**: 4 (UvicornWorker class)
- **Timeout**: 120 seconds
- **Max requests**: 2000 per worker (with 200 jitter for graceful rotation)
- **Keep-alive**: 10 seconds
- **Binding**: 0.0.0.0:8000

---

## API Gateway

**Module**: `src/api_gateway/`

The API gateway handles all HTTP routing, authentication, and request validation.

### Endpoints

| Route | Method | Auth | Purpose |
|-------|--------|------|---------|
| `/api/v1/honeypot` | POST | API key | Main honeypot conversation endpoint |
| `/api/v1/detect` | POST | API key | Standalone scam detection (no engagement) |
| `/api/v1/message` | POST | API key | Alternative message endpoint |
| `/api/v1/session/{id}` | GET | API key | Retrieve session details |
| `/api/v1/session/{id}/end` | POST | API key | End session, get final report |
| `/api/v1/health` | GET | None | Liveness check |
| `/api/v1/health/ready` | GET | None | Readiness (Redis, Neo4j, ML) |
| `/api/v1/stats` | GET | API key | System statistics |

### Authentication

API key validation via `x-api-key` header. Returns 401 if missing, 403 if invalid.

### Request Validation

- Session ID format validation (UUID pattern)
- Message content validation (non-empty, max length)
- Input sanitization (HTML entities, script injection prevention)
- Tamper-proof request validation

---

## Scam Detection Engine

**Module**: `src/scam_detector/`

The hybrid scam detection engine uses 11 scoring layers that are weighted and combined into a final confidence score.

### Layer Architecture

```
Input Message
    │
    ▼
┌─────────────────────────────────────────────┐
│            LAYER 1: Keyword Scoring          │
│  200+ weighted keywords across categories    │
│  urgency, financial, threats, personal_info  │
└─────────────────────┬───────────────────────┘
                      │
┌─────────────────────▼───────────────────────┐
│        LAYER 2: Hard Indicator Patterns      │
│  UPI IDs, bank references, OTP requests      │
│  Regex-based instant detection               │
└─────────────────────┬───────────────────────┘
                      │
┌─────────────────────▼───────────────────────┐
│         LAYER 3: ML Ensemble (5 models)      │
│  Random Forest, Gradient Boosting, LR,       │
│  LightGBM, XGBoost — soft voting             │
└─────────────────────┬───────────────────────┘
                      │
┌─────────────────────▼───────────────────────┐
│          LAYER 4: TF-IDF Similarity          │
│  Compare against 3,390 training samples      │
│  Cosine similarity scoring                   │
└─────────────────────┬───────────────────────┘
                      │
┌─────────────────────▼───────────────────────┐
│        LAYER 5: URL/Document Detection       │
│  Suspicious URL patterns, shortened links    │
│  Document-based phishing detection           │
└─────────────────────┬───────────────────────┘
                      │
┌─────────────────────▼───────────────────────┐
│        LAYER 6: Urgency Language             │
│  Time pressure phrases, threat detection     │
│  CAPS analysis, exclamation frequency        │
└─────────────────────┬───────────────────────┘
                      │
┌─────────────────────▼───────────────────────┐
│      LAYER 7: Multilingual Translation       │
│  Sarvam API: Hindi, Bengali, Tamil, Telugu   │
│  Translate → re-run detection on English     │
└─────────────────────┬───────────────────────┘
                      │
┌─────────────────────▼───────────────────────┐
│      LAYER 8: Gemini LLM Cross-Verify        │
│  Google Gemini analyzes full conversation     │
│  Returns structured scam assessment          │
└─────────────────────┬───────────────────────┘
                      │
┌─────────────────────▼───────────────────────┐
│      LAYER 9: Cumulative Session Score       │
│  Aggregate detection across all turns        │
│  Persistent scam signal tracking             │
└─────────────────────┬───────────────────────┘
                      │
┌─────────────────────▼───────────────────────┐
│      LAYER 10: Online Pattern Learning       │
│  Live pattern updates from confirmed scams   │
│  Adaptive threshold adjustment               │
└─────────────────────┬───────────────────────┘
                      │
┌─────────────────────▼───────────────────────┐
│      LAYER 11: Meta-Detection                │
│  Ensemble of all layer scores                │
│  Final weighted confidence computation       │
└─────────────────────┬───────────────────────┘
                      │
                      ▼
              Final Confidence Score
              (0.0 → 1.0, threshold: 0.4)
```

### Score Weighting

When the ML ensemble is available, the scoring weights are:

| Layer | Weight |
|-------|--------|
| ML Ensemble | 0.42 |
| ML Model (standalone) | 0.10 |
| Keyword Score | 0.08 |
| Other layers | Remaining |

### Scam Type Classification

The system classifies detected scams into 19 categories: `bank_fraud`, `upi_fraud`, `phishing`, `kyc_phishing`, `digital_arrest`, `investment_fraud`, `lottery_prize`, `tech_support`, `job_scam`, `romance_scam`, `customs_parcel`, `loan_fraud`, `crypto_scam`, `deepfake_impersonation`, `sim_swap`, `qr_code_scam`, `refund_scam`, `sextortion`, `unknown`. Each category has a `ScamProfile` (severity 1-10, typical tactics, recommended persona, max turns). Classification uses keyword-based rules (16 keyword categories via `SCAM_CATEGORY_KEYWORDS`) and intelligence-based override (e.g., presence of UPI IDs → `upi_fraud`).

---

## Intelligence Extraction

**Module**: `src/intelligence_extractor/`

### Extraction Categories

| Category | Method | Example |
|----------|--------|---------|
| Phone Numbers | Regex (Indian +91 format) | `+91-9876543210`, `9876543210` |
| Bank Accounts | Regex (8-18 digit patterns) | `1234567890123456` |
| UPI IDs | Regex (@provider patterns) | `user@paytm`, `user@ybl` |
| Phishing Links | URL pattern matching | `http://fake-bank.com/verify` |
| Email Addresses | Standard email regex | `scammer@example.com` |
| Case IDs | Reference/case number patterns | `CBI-2025-001234` |
| Policy Numbers | Insurance policy patterns | `POL-123456789` |
| Order Numbers | Order ID patterns | `ORD-2025-5678` |
| Organization Names | NLP entity extraction | `SBI Fraud Department` |
| Addresses | Location pattern matching | `123 MG Road, Mumbai` |
| Employee IDs | ID pattern extraction | `EMP-SBI-12345` |
| Names Mentioned | Name entity extraction | `Inspector Rajesh Kumar` |
| Suspicious Keywords | Scam vocabulary detection | `OTP`, `verify`, `blocked` |

### Phone Number Handling

Phone numbers are extracted in both original and normalized format to support evaluator substring matching:

- Input: `+91-9876543210`
- Extracted: `["+91-9876543210", "+919876543210"]`

The first digit of Indian mobile numbers must be 6-9. The regex enforces trailing boundary assertions to prevent partial matches.

### Behavioral Fingerprinting

**Module**: `behavioral_fingerprint.py`

Creates unique behavioral profiles of scammers based on:
- Message timing patterns
- Vocabulary and language style
- Urgency escalation patterns
- Conversation flow characteristics

### Network Analysis

**Module**: `network_analyzer.py`

Builds in-memory graphs of connected entities to identify:
- Shared phone numbers across sessions
- Common bank accounts
- Linked UPI IDs
- Cluster membership

---

## Question Engine & Red Flag Tracker

**Modules**: `src/agent_controller/question_engine.py`, `src/agent_controller/red_flag_tracker.py`

### Question Engine

The question engine generates investigative questions to maximize intelligence extraction and engagement quality.

**Architecture**:
- `IntelligenceExtractionPlanner` determines the highest-priority missing intel type for the current scam category and turn.
- `QuestionBank` stores category-specific questions for 16 scam types + 15 general investigative questions.
- 9 question types: Identity Verification, Organization Details, Contact Verification, Process Verification, Authority Challenge, Time Stalling, Payment Clarification, Technical Confusion, Technical Details.
- Probing follow-ups (6 trigger types: `phone_mentioned`, `upi_mentioned`, `link_mentioned`, `organization_mentioned`, `email_mentioned`, `case_mentioned`) fire automatically when specific entity types are extracted.

### Red Flag Tracker

Detects 12 behavioral indicators in scammer messages and generates targeted probing questions:

- Urgency escalation
- Credential requests (OTP, password, PIN)
- Authority impersonation
- Threat patterns (account block, arrest)
- Payment pressure
- Identity probing
- Time pressure tactics
- Social engineering patterns
- Information inconsistencies
- Communication channel switching
- Emotional manipulation
- Verification resistance

**Flow**: `RedFlagDetector.detect_red_flags()` runs every turn → flags accumulate in `session.red_flags_detected` → `RedFlagProber.should_probe_now()` decides timing → `RedFlagProber.generate_probing_question()` creates targeted probes.

---

## Persona Engine

**Module**: `src/persona_engine/`

The persona engine generates realistic victim-like responses to keep scammers engaged.

### Persona Types

| Persona | Age | Style | Purpose |
|---------|-----|-------|---------|
| Confused Elderly | 60-75 | Slow, worried, trusting | Maximum engagement duration |
| Gullible Student | 18-22 | Eager, naive, tech-confused | Natural information sharing |
| Busy Professional | 35-50 | Distracted, impatient | Believable delays |

### Response Generation Pipeline

```
Session Context
    │
    ├─ Scam type & confidence
    ├─ Conversation history (last N turns)
    ├─ Selected persona profile
    ├─ Extracted intelligence so far
    │
    ▼
┌──────────────────────────┐
│   Prompt Construction     │
│   (persona + context)     │
└────────────┬─────────────┘
             │
             ▼
┌──────────────────────────┐
│   Gemini API Call          │
│   (multi-key rotation)    │
│   (15s timeout)           │
└────────────┬─────────────┘
             │
             ▼
┌──────────────────────────┐
│   Age-Adaptive Filter     │
│   (vocabulary, sentence   │
│    length, formality)     │
└────────────┬─────────────┘
             │
             ▼
┌──────────────────────────┐
│   Emotional Intelligence  │
│   (fear, confusion,       │
│    trust calibration)     │
└────────────┬─────────────┘
             │
             ▼
┌──────────────────────────┐
│   Typing Delay Simulator  │
│   (WPM-based, realistic)  │
└────────────┬─────────────┘
             │
             ▼
        Final Response
```

### Gemini API Multi-Key Rotation

Multiple API keys are configured via `GEMINI_API_KEYS` (comma-separated). A thread-safe round-robin selector (`threading.Lock`) cycles through keys to distribute load and avoid rate limiting.

---

## Session Management

**Module**: `src/session_manager/`

### Storage Architecture

```
┌─────────────────────────────────────────┐
│          BaseSessionStore (ABC)          │
├─────────────────┬───────────────────────┤
│                 │                       │
│  RedisSessionStore    InMemorySessionStore │
│  (production)         (fallback)          │
└─────────────────┴───────────────────────┘
```

### Redis Connection

- **Direct connection** mode (Sentinel disabled in production Docker)
- Connection pooling: min 10, max 100 connections
- Socket timeout: 5 seconds
- Retry: 3 attempts with 0.5s delay
- Session TTL: 3600 seconds (1 hour)
- Password authentication

### Session Data Structure

Each session stores:
- Session ID (UUID)
- Conversation history (list of messages)
- Scam detection state (type, confidence, is_detected)
- Extracted intelligence (accumulated across turns, 13 categories)
- Engagement metrics (start time, turn count, duration)
- Persona assignment (type, scam category)
- Red flags detected (list of behavioral indicators with turn context)
- Detection details (layer-by-layer scores)
- Confidence level (0.0–1.0)
- Client metadata (IP, user-agent)
- Timestamps (created_at, last_updated)

### Distributed Locking

Redis-based distributed locks prevent concurrent writes to the same session across multiple Gunicorn workers:
- Lock TTL: 30 seconds
- Retry count: 3
- Retry delay: 0.2 seconds

---

## Graph Intelligence

**Module**: `src/graph/`

### Neo4j Schema

```
(:Scammer {id, session_id, ip_address})
    │
    ├──[:USES_PHONE]──▶ (:Phone {number, normalized})
    ├──[:USES_BANK]───▶ (:BankAccount {number})
    ├──[:USES_UPI]────▶ (:UPI {id, provider})
    ├──[:USES_EMAIL]──▶ (:Email {address, domain})
    └──[:SENDS_LINK]──▶ (:URL {url, domain})

(:Session {id, scam_type, confidence, timestamp})
    └──[:INVOLVES]────▶ (:Scammer)
```

### Fraud Ring Detection

1. **Entity Loading**: Exports Neo4j subgraph to NetworkX
2. **Community Detection**: Identifies clusters of connected entities
3. **Ring Classification**: Groups with shared entities across sessions = potential fraud rings
4. **Kingpin Identification**: Nodes with highest betweenness centrality = likely coordinators

### Query Examples

- Find all sessions sharing a phone number
- Identify scammers using the same bank account
- Detect clusters of related UPI IDs
- Map complete fraud network topology

---

## Resilience Patterns

**Module**: `src/resilience/`

### Circuit Breaker

Prevents cascading failures when external services (Gemini, Sarvam, callback) are down:

```
CLOSED ──(failures > threshold)──▶ OPEN
  ▲                                  │
  │                          (recovery timeout)
  │                                  │
  └──(success)── HALF_OPEN ◀────────┘
```

- Failure threshold: 5
- Recovery timeout: 30 seconds
- Half-open max attempts: 3

### Backpressure Controller

Protects the system from overload:

| Metric | Threshold | Action |
|--------|-----------|--------|
| Queue depth | 500 max | Reject new requests |
| Shed threshold | 85% | Start dropping low-priority work |
| Slowdown threshold | 70% | Apply artificial delays |
| Max queue depth | 16 (configurable) | Hard limit |

---

## Security Layer

**Module**: `src/security/`

### Jailbreak Guard

Detects and blocks attempts to manipulate the honeypot into revealing its true purpose:
- Pattern matching against known jailbreak prompts
- Instruction injection detection
- Role-breaking attempt detection

### Tamper-Proof Middleware

Ensures response integrity:
- Request validation (structure, field types)
- Response consistency checks
- Audit trail of modifications

### Input Sanitization

- HTML entity encoding
- Script tag removal
- SQL injection pattern detection
- Max message length enforcement

---

## ML Pipeline

**Module**: `src/scam_detector/`

### Training Pipeline

```
Raw Text Data (3,390 samples)
    │
    ▼
┌──────────────────────────┐
│   Text Preprocessing      │
│   - Lowercase             │
│   - Remove special chars  │
│   - Tokenization          │
└────────────┬─────────────┘
             │
             ▼
┌──────────────────────────┐
│   TF-IDF Vectorization    │
│   - 545 features          │
│   - Unigrams + bigrams    │
└────────────┬─────────────┘
             │
             ▼
┌──────────────────────────┐
│   Feature Engineering     │
│   - Text statistics       │
│   - Urgency indicators    │
│   - Pattern features      │
└────────────┬─────────────┘
             │
             ▼
┌──────────────────────────┐
│   Model Training          │
│   ├─ Random Forest        │
│   ├─ Gradient Boosting    │
│   ├─ Logistic Regression  │
│   ├─ LightGBM             │
│   └─ XGBoost              │
└────────────┬─────────────┘
             │
             ▼
┌──────────────────────────┐
│   Soft Voting Ensemble    │
│   Accuracy: 97.64%        │
│   F1 Score: 0.9784        │
└────────────┬─────────────┘
             │
             ▼
    Serialized Models (.joblib)
```

### Online Learning

The training pipeline supports online learning — confirmed scam patterns are saved to `learned_patterns.json` and incorporated into future detection without full model retraining.

### Model Files

| File | Description |
|------|-------------|
| `ensemble_detector.joblib` | Trained 5-model ensemble |
| `tfidf_vectorizer.joblib` | Fitted TF-IDF vectorizer |
| `feature_scaler.joblib` | Feature normalization scaler |
| `learned_patterns.json` | Online-learned pattern database |
| `training_data.jsonl` | Full training dataset (3,390 samples) |
| `training_metrics.json` | Training performance metrics |

---

## Deployment Architecture

### Production Setup (AWS m7i-flex.large)

```
┌───────────────────────────────────────────────┐
│              AWS m7i-flex.large                 │
│              2 vCPU, 4 GB RAM                  │
│                                                │
│  ┌────────────────────────────────────────┐    │
│  │         Docker Compose Network          │    │
│  │         (bridge: 172.28.0.0/16)        │    │
│  │                                         │    │
│  │  ┌──────┐ ┌──────┐ ┌──────┐           │    │
│  │  │Nginx │ │ API  │ │Worker│           │    │
│  │  │:80   │ │:8000 │ │      │           │    │
│  │  │:443  │ │(x4)  │ │      │           │    │
│  │  └──┬───┘ └──┬───┘ └──┬───┘           │    │
│  │     │        │        │                │    │
│  │  ┌──▼────────▼────────▼───┐            │    │
│  │  │    Internal Network     │            │    │
│  │  └──┬─────────────────┬───┘            │    │
│  │     │                 │                │    │
│  │  ┌──▼───┐          ┌──▼───┐           │    │
│  │  │Redis │          │Neo4j │           │    │
│  │  │:6379 │          │:7687 │           │    │
│  │  └──────┘          └──────┘           │    │
│  └────────────────────────────────────────┘    │
│                                                │
│  Cloudflare DNS → :443 (TLS termination)       │
└───────────────────────────────────────────────┘
```

### Resource Allocation

| Service | CPU Limit | Memory Limit | CPU Reserved | Memory Reserved |
|---------|-----------|-------------|-------------|----------------|
| Nginx | 0.15 | 96 MB | 0.05 | 32 MB |
| API | 0.70 | 2560 MB | 0.25 | 384 MB |
| Worker | 0.35 | 512 MB | 0.10 | 192 MB |
| Redis | 0.25 | 640 MB | 0.10 | 192 MB |
| Neo4j | 0.30 | 512 MB | 0.10 | 256 MB |
| **Total** | **1.75** | **4320 MB** | **0.60** | **1056 MB** |

### Health Checks

| Service | Check | Interval | Timeout |
|---------|-------|----------|---------|
| Nginx | `curl http://localhost/nginx-health` | 10s | 3s |
| API | `curl http://localhost:8000/api/v1/health` | 15s | 5s |
| Worker | `python -c "import sys; sys.exit(0)"` | 30s | 5s |
| Redis | `redis-cli ping` | 10s | 3s |
| Neo4j | `wget http://localhost:7474` | 15s | 5s |

### Kubernetes Support

Kubernetes manifests are provided in `docker/k8s/` for production scaling:
- Horizontal Pod Autoscaler (HPA)
- Pod Disruption Budget (PDB)
- Ingress with TLS
- ConfigMap for environment variables
- Separate Redis and Neo4j deployments

---

## Data Flow Diagrams

### Honeypot Conversation Flow

```
Scammer Message (Turn N)
    │
    ▼
┌─ API Gateway ──────────────────────────────────┐
│  1. Authenticate (x-api-key)                    │
│  2. Validate & sanitize input                   │
│  3. Load session from Redis                     │
│  4. Run detection (parallel):                   │
│     ├─ Keyword scoring                          │
│     ├─ ML ensemble inference                    │
│     ├─ Hard indicator check                     │
│     └─ Gemini LLM verification                  │
│  5. Extract intelligence (13 categories)        │
│  6. Detect red flags (12 behavioral indicators)  │
│  7. Select/apply persona                        │
│  8. Generate response via Gemini                │
│  9. Append investigative question (question engine)│
│  10. Update session in Redis                    │
│  11. Dispatch callback (every turn):            │
│      └─ GUVI callback with full session analysis │
│  12. Enqueue background tasks:                  │
│      ├─ Neo4j graph update                      │
│      └─ Behavioral fingerprint update           │
│  13. Return JSON response                       │
└─────────────────────────────────────────────────┘
```

### Intelligence Accumulation

```
Turn 1: "Your SBI account compromised, call +91-9876543210"
  → phones: ["+91-9876543210", "+919876543210"]
  → scam_type: bank_fraud

Turn 2: "Send OTP to verify account 1234567890123456"
  → phones: ["+91-9876543210", "+919876543210"]  (accumulated)
  → bank_accounts: ["1234567890123456"]           (new)

Turn 3: "Pay ₹500 to verify@paytm for verification"
  → phones: ["+91-9876543210", "+919876543210"]
  → bank_accounts: ["1234567890123456"]
  → upi_ids: ["verify@paytm"]                     (new)

Final → All intelligence merged across turns
```

---

## Architecture Decision Records

Detailed ADRs are available in `docs/architecture/`:

- [ADR-001: Docker Compose Scaling](architecture/ADR-001-docker-compose-scaling.md) — Worker count and resource allocation strategy
- [ADR-002: Backpressure and Concurrency](architecture/ADR-002-backpressure-and-concurrency.md) — Load shedding and queue management
- [ADR-003: Redis HA and Client Config](architecture/ADR-003-redis-ha-and-client-config.md) — Redis direct vs Sentinel mode decision
