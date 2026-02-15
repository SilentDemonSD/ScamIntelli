<div align="center">

# ScamIntelli

### AI-Powered Scam Honeypot Agent

An autonomous, multi-layered honeypot system that detects scam intent in real-time, impersonates believable Indian user personas, engages scammers across extended conversations, and extracts actionable intelligence — powered by a 10-layer hybrid detection engine with ML capabilities, graph-based network analysis, behavioral fingerprinting, and an explainability dashboard.

[![Python 3.11+](https://img.shields.io/badge/Python-3.11+-blue.svg)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.100+-green.svg)](https://fastapi.tiangolo.com)
[![Tests](https://img.shields.io/badge/Tests-269%20Passing-brightgreen.svg)]()
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

</div>

---

## Architecture Overview

```
┌──────────────────────────────────────────────────────────────────────────────┐
│                           API Gateway (FastAPI)                              │
│  /message  /honeypot  /session  /health  /summary  /stats  /logs            │
│  /network/analysis  /session/fingerprint  /session/explanation               │
│  /session/visualization                                                      │
├──────────────────────────────────────────────────────────────────────────────┤
│                            Security Layer                                    │
│  ┌─────────────────┐  ┌──────────────────┐  ┌──────────────────┐            │
│  │  Tamper-Proof    │  │  Jailbreak Guard │  │  Rate Limiter    │            │
│  │  Middleware      │  │  (5 Attack Types)│  │  Anti-Fingerprint│            │
│  └────────┬────────┘  └────────┬─────────┘  └────────┬─────────┘            │
├───────────┴────────────────────┴──────────────────────┴──────────────────────┤
│                       Agent Controller (Strategy)                            │
│  ┌───────────────────────────────────────────────────────────────────┐       │
│  │  ConversationContextTracker  │  EngagementStrategy (16 cats)      │       │
│  └───────────────────────────────────────────────────────────────────┘       │
├──────────────────────────────────────────────────────────────────────────────┤
│                 10-Layer Hybrid Scam Detection Engine                         │
│  ┌──────────┬──────────┬──────────┬──────────┬───────────────────┐           │
│  │ Keyword  │  Intent  │ Pattern  │ Emotion  │   Behavioral      │           │
│  │  (0.12)  │  (0.25)  │  (0.12)  │  (0.08)  │    (0.08)        │           │
│  ├──────────┼──────────┼──────────┼──────────┼───────────────────┤           │
│  │URL Threat│Multilang │Multi-Vec │ML Model  │ Learned Patterns  │           │
│  │  (0.08)  │  (0.04)  │  (0.05)  │  (0.12)  │    (0.06)        │           │
│  └──────────┴──────────┴──────────┴──────────┴───────────────────┘           │
├──────────────────────────────────────────────────────────────────────────────┤
│                 Advanced Intelligence & Analytics                            │
│  ┌──────────────────┐  ┌────────────────────┐  ┌─────────────────┐          │
│  │  Network Analyzer│  │  Behavioral        │  │  Explainability │          │
│  │  (Graph/networkx)│  │  Fingerprinter     │  │  Dashboard      │          │
│  ├──────────────────┤  ├────────────────────┤  ├─────────────────┤          │
│  │  Fraud Ring      │  │  Cross-Session     │  │  40+ Advanced   │          │
│  │  Detection       │  │  Scammer Tracking  │  │  ML Features    │          │
│  └──────────────────┘  └────────────────────┘  └─────────────────┘          │
├──────────────────────────────────────────────────────────────────────────────┤
│                           Persona Engine                                     │
│  ┌────────────────┐  ┌──────────────┐  ┌─────────────────────────┐          │
│  │ 12 Persona     │  │  Emotional   │  │  Age-Adaptive Engine    │          │
│  │ Types + Gemini │  │  Intelligence│  │  (Senior/Mid/Young)     │          │
│  ├────────────────┤  ├──────────────┤  ├─────────────────────────┤          │
│  │ ResponseSelf   │  │  Typing      │  │  Language-Adaptive      │          │
│  │ Corrector      │  │  Simulator   │  │  (6 Language Styles)    │          │
│  └────────────────┘  └──────────────┘  └─────────────────────────┘          │
├──────────────────────────────────────────────────────────────────────────────┤
│  ┌──────────────────┐  ┌──────────────────┐  ┌──────────────────┐           │
│  │  Intelligence    │  │  Session Manager │  │  GUVI Callback   │           │
│  │  Extractor       │  │  (Redis/Memory)  │  │  Worker (HTTP/2) │           │
│  └──────────────────┘  └──────────────────┘  └──────────────────┘           │
├──────────────────────────────────────────────────────────────────────────────┤
│              Deployment & Scaling (Docker Compose + Nginx)                   │
│  ┌──────────────────┐  ┌──────────────────┐  ┌──────────────────┐           │
│  │  Nginx Reverse   │  │  Docker Compose  │  │  Gunicorn +      │           │
│  │  Proxy + LB      │  │  --scale api=N   │  │  Uvicorn Workers │           │
│  │  (least_conn)    │  │  (2-3 replicas)  │  │  (async ASGI)    │           │
│  └──────────────────┘  └──────────────────┘  └──────────────────┘           │
│  ┌──────────────────┐  ┌──────────────────┐  ┌──────────────────┐           │
│  │  Cloudflare CDN  │  │  Redis Session   │  │  K8s-Ready       │           │
│  │  + SSL + DDoS    │  │  Store (local)   │  │  Migration Path  │           │
│  └──────────────────┘  └──────────────────┘  └──────────────────┘           │
└──────────────────────────────────────────────────────────────────────────────┘
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

### 2. Graph-Based Scammer Network Analysis

NetworkX-powered graph analysis engine that maps relationships between scam entities across sessions:

- **Entity Graph Construction** — Builds weighted undirected graphs from UPI IDs, bank accounts, phone numbers, and phishing links extracted across all sessions
- **Fraud Ring Detection** — Uses `connected_components` to identify clusters of related entities (minimum 3 entities per ring), with composite risk scoring based on ring size, session count, entity type diversity, and high-value entity density
- **Kingpin Identification** — Ranks entities by composite centrality score: degree centrality (0.4 weight), betweenness centrality (0.4), and eigenvector centrality (0.2) to find the most connected and influential scam entities
- **Network Statistics** — Real-time metrics: total entities, edges, connected components, clustering coefficient, network density, entity type distribution
- **Session Connection Mapping** — For any session, identifies all cross-session connections and assigns risk levels (none/low/medium/high/critical)

### 3. Advanced Feature Engineering (40 ML Features)

`AdvancedFeatureExtractor` extends detection with 40 engineered features across 5 categories:

| Category | Count | Features |
|----------|-------|----------|
| **Temporal** | 8 | Message rate, response gaps, session duration ratio, burst score, time pressure count, deadline mentions, countdown patterns, recency bias |
| **Linguistic** | 10 | Vocabulary richness, sentence length, readability, passive voice ratio, imperative ratio, pronoun ratio, formality score, repetition, code-switching, punctuation abuse |
| **Psychological** | 8 | Fear appeals, authority claims, social proof, scarcity, reciprocity exploitation, commitment/consistency, price anchoring, emotional manipulation |
| **Behavioral** | 6 | Message length trends, topic shifts, information request density, compliance testing, rapport-vs-demand ratio, grooming score |
| **Info Extraction** | 8 | Unique phone/UPI/URL/email counts, amount mentions, credential request density, personal data requests, financial entity density |

All features are bounded [0, 1] and integrated into the explainability engine.

### 4. Behavioral Fingerprinting

Cross-session scammer identification through behavioral analysis:

- **Timing Patterns** — Average message length, length variance, word count, punctuation density, capitalization ratio
- **Language Patterns** — Vocabulary richness, sentence length, top bigrams, language mix ratio, formality score, filler word ratio
- **Escalation Patterns** — Escalation speed, threat density, urgency progression, pressure pattern classification (aggressive_escalation, gradual_escalation, sustained_pressure, urgency_buildup, low_pressure)
- **Entity Patterns** — URL, phone, UPI, email, and monetary amount usage frequencies
- **Cross-Session Matching** — Weighted similarity scoring (0.3 timing + 0.4 language + 0.3 pattern) with 0.75 threshold to link sessions to the same scammer
- **Signature Hashing** — Compact behavioral signature for fast lookups

### 5. Explainability Dashboard

Full transparency into detection decisions with interactive visualization:

- **Layer-by-Layer Breakdown** — Raw score, weight, contribution, and percentage impact of each detection layer
- **Top Signal Analysis** — Ranked list of the strongest detection signals with strength and impact values
- **Risk Factor Enumeration** — Human-readable list of detected risk factors (keyword density, malicious intent, behavioral escalation, suspicious URLs, multi-vector attacks, hard indicators)
- **Psychological Tactic Detection** — Identifies manipulation techniques: fear/threat appeals, authority impersonation, artificial scarcity, social proof manipulation, reciprocity exploitation, emotional manipulation
- **Risk Level Classification** — 5-tier system: critical (>=0.85), high (>=0.72), medium (>=0.50), low (>=0.30), minimal (<0.30)
- **Interactive HTML Dashboard** — Chart.js powered dark-theme UI with radar charts, bar charts, signal strength bars, feature heatmaps, and session details (served via `/session/{id}/visualization`)

### 6. 12 Persona Types

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

### 7. 16 Scam Categories

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

### 8. ML-Powered Adaptive Detection

LightGBM-based machine learning engine with 25 base features + 40 advanced features:

**Base Features (25)**:
- **Text Features** — Message length, word count, average word length, uppercase ratio
- **Entity Detection** — URLs, phone numbers, emails, UPI IDs
- **Keyword Density** — Urgency, threat, credential, and payment keyword counts
- **Structural Analysis** — Currency symbols, number counts, special character ratio
- **Language Features** — Hindi word ratio, consecutive caps, sentiment negativity
- **Information Theory** — Message entropy, repeated character ratio
- **Session Context** — Turn count, escalation score, multi-vector count

**Advanced Features (40)** — Temporal dynamics, linguistic profiling, psychological manipulation scoring, behavioral trend analysis, and information extraction density (see Feature 3 above).

Graceful fallback to weighted heuristic scoring when LightGBM/NumPy are unavailable. Training samples are automatically persisted for future model improvement.

### 9. Emotional Intelligence Engine

Detects 9 emotional states and 8 manipulation patterns in scammer messages:

**Emotional States**: Fear, Greed, Urgency, Trust, Confusion, Anger, Sadness, Excitement, Neutral

**Manipulation Patterns**: Fear Escalation, Urgency Pressure, Greed Exploitation, Authority Intimidation, Emotional Blackmail, Trust Building, Isolation Tactics, Shame Inducement

Includes 40+ emoji sentiment analysis, per-session escalation tracking, and persona emotion mirroring.

### 10. Multilingual Detection (11 Languages)

Unicode script detection for Devanagari, Bengali, Tamil, Telugu, Kannada, Malayalam, Gujarati, and Gurmukhi. Romanized Hindi detection with 58 Hindi + 28 Hinglish scam keywords. Regional keyword sets for Tamil, Bengali, and Telugu. Optional Sarvam AI translation integration. Code-switching analysis (inter-sentential, intra-sentential, tag-switching).

### 11. Age-Adaptive Persona Engine

3 demographic profiles (Senior 55+, Middle-Aged 35–55, Young Adult 18–35):

- **Typing Speed** — 15/40/55 WPM respectively
- **Typo Generation** — Adjacent key errors, character swaps, doubles, skips
- **Senior Artifacts** — Random caps, double spaces, long corrections
- **Young Adult Patterns** — Abbreviations (16 pairs), slang (12 items), skeptical phrases
- **Intel Extraction** — Age-appropriate information gathering strategies

### 12. URL & Document Threat Analysis

- **Phishing Detection** — 20 suspicious TLDs, IP-based URLs, path keyword analysis
- **Lookalike Domains** — 7 major brand targets (SBI, HDFC, ICICI, Paytm, PhonePe, RBI, Income Tax) with 35+ fake domain patterns
- **Homograph Attacks** — 17 Cyrillic-to-Latin character mappings
- **URL Shortener Expansion** — 16 shortener domains with async HTTP redirect following
- **Misleading Subdomains** — Detection of legitimate brand names used as subdomains

### 13. Meta-Scam Detection

Detects when scammers attempt to identify the honeypot:

- **38 honeypot probe patterns** (bilingual) — "Are you a bot?", "Kya tum AI ho?"
- **25 reverse psychology patterns** — "I know this is a scam"
- **16 capability probe patterns** — "What model are you using?"
- **Timing analysis** — rapid requests, uniform intervals
- **Message hash deduplication** — repeated message detection
- **Counter-responses** — in-character deflection per probe type

### 14. Security Layer

**Tamper-Proof Middleware** — Request fingerprinting, bot UA detection (13 patterns), suspicious header analysis (8 patterns), request timing analysis (>30/min, <0.5s intervals)

**Jailbreak Guard** — 5 attack vector protection:
- Prompt injection (27 bilingual patterns)
- Persona hijacking (17 patterns)
- Prompt leaking (18 patterns)
- Encoding attacks (7 regex: base64, eval/exec, hex/unicode escapes)
- Token overflow (500 word threshold)

**Anti-Fingerprinting** — Response jitter, randomized error messages, internal state masking, response humanization with fillers and typos

### 15. Human Typing Simulator

WPM-based delay calculation per age group. 4 typo generation strategies (swap, adjacent key, double, skip). Age-specific correction formats. Thinking pauses and error correction delays.

### 16. Intelligence Extraction

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
| LLM | Google Gemini (gemini-2.0-flash) |
| ML Engine | LightGBM + NumPy |
| Graph Analysis | NetworkX |
| HTTP Client | httpx (HTTP/2) |
| Session Storage | Redis 7 (local container) / In-Memory |
| Process Manager | Gunicorn + Uvicorn (async ASGI workers) |
| Reverse Proxy | Nginx 1.27 (least_conn LB, gzip, rate limiting) |
| CDN / SSL | Cloudflare (Full Strict SSL, HTTP/2, DDoS protection) |
| Validation | Pydantic Settings + Custom Validators |
| Testing | pytest + pytest-asyncio (269 tests) |
| Containerization | Docker (multi-stage) + Docker Compose |
| Orchestration | Docker Compose --scale (K8s-ready migration path) |

---

## API Endpoints

All endpoints are prefixed with `/api/v1` and require `X-API-Key` header authentication (except `/health`).

### Core Endpoints

#### POST `/api/v1/message`

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

#### POST `/api/v1/honeypot`

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

#### GET `/api/v1/session/{session_id}`

Retrieve session state including scam detection status and extracted intelligence.

#### DELETE `/api/v1/session/{session_id}`

End session, trigger GUVI callback if scam was detected, and clean up.

#### GET `/api/v1/health`

Health check endpoint (no authentication required).

#### GET `/api/v1/summary/{session_id}`

Get engagement summary with conversation analysis.

#### GET `/api/v1/stats`

Aggregated system statistics: total sessions, scam detections, intelligence gathered, ML model info, per-session breakdown.

#### GET `/api/v1/logs`

Real-time application log buffer (last 500 entries). Supports query parameters:
- `limit` — int, max 500
- `level` — INFO, WARNING, ERROR
- `source` — filter by logger name

### Intelligence & Analytics Endpoints

#### GET `/api/v1/network/analysis`

Graph-based scammer network analysis across all tracked sessions.

```json
// Response
{
  "network_statistics": {
    "total_entities": 47,
    "total_edges": 82,
    "total_sessions_tracked": 15,
    "connected_components": 5,
    "fraud_rings_detected": 3,
    "average_cluster_coefficient": 0.72,
    "network_density": 0.074
  },
  "fraud_rings": [
    {
      "ring_id": "a1b2c3d4e5f6g7h8",
      "size": 8,
      "risk_score": 0.82,
      "sessions": ["sess-1", "sess-3", "sess-7"],
      "entity_types": {"upi_id": 3, "phone_number": 3, "bank_account": 2}
    }
  ],
  "kingpin_entities": [
    {
      "entity_value": "scammer@upi",
      "entity_type": "upi_id",
      "centrality_score": 0.87,
      "connected_sessions": 5,
      "connected_entities": 12
    }
  ]
}
```

#### POST `/api/v1/session/{session_id}/fingerprint`

Generate a behavioral fingerprint for a session and match against known scammer patterns.

```json
// Response
{
  "fingerprint_id": "a1b2c3d4e5f6g7h8i9j0",
  "signature_hash": "f7e8d9c0b1a2...",
  "timing_pattern": {
    "avg_message_length": 145.2,
    "avg_word_count": 28.5,
    "punctuation_density": 0.032,
    "capitalization_ratio": 0.058
  },
  "escalation_pattern": {
    "pressure_pattern": "aggressive_escalation",
    "threat_density": 0.15,
    "escalation_speed": 0.08
  },
  "matches": [
    {
      "matched_session_id": "sess-old-42",
      "similarity_score": 0.89,
      "timing_similarity": 0.85,
      "language_similarity": 0.92,
      "pattern_similarity": 0.88
    }
  ]
}
```

#### GET `/api/v1/session/{session_id}/explanation`

Full explainability breakdown for a session's scam detection decision.

```json
// Response
{
  "detection_result": {
    "is_scam": true,
    "confidence": 0.91,
    "risk_level": "critical",
    "has_hard_indicators": true
  },
  "top_signals": [
    {"signal": "intent", "strength": 0.85, "impact": 23.4},
    {"signal": "keyword", "strength": 0.72, "impact": 9.5}
  ],
  "risk_factors": [
    "High scam keyword density detected",
    "Strong malicious intent signals",
    "Hard indicators present (UPI/phone/link)"
  ],
  "psychological_tactics": [
    "Fear/threat appeals",
    "Authority impersonation"
  ],
  "advanced_features": {
    "psych_fear_appeal_score": 0.67,
    "psych_authority_claim_score": 0.5,
    "temporal_time_pressure_count": 0.33
  }
}
```

#### GET `/api/v1/session/{session_id}/visualization`

Interactive HTML dashboard with Chart.js visualizations of the detection decision. Returns a full dark-themed HTML page with:
- Summary cards (confidence, scam status, message count, hard indicators)
- Bar chart of detection layer scores
- Radar chart of score distribution
- Signal strength analysis bars
- Risk factors and psychological tactics tags
- Advanced feature heatmap grouped by category
- Session details panel

---

## Project Structure

```
ScamIntelli/
├── src/
│   ├── config.py                          # Settings (Pydantic)
│   ├── models.py                          # Request/response models
│   ├── api_gateway/
│   │   ├── app.py                         # FastAPI app, lifespan, rate limiter
│   │   └── routes.py                      # 12 API route handlers
│   ├── agent_controller/
│   │   ├── agent_state.py                 # Agent state definitions
│   │   └── strategy.py                    # EngagementStrategy, ContextTracker
│   ├── scam_detector/
│   │   ├── classifier.py                  # Core 3-signal scam scoring
│   │   ├── keywords.py                    # 250+ keywords, 15 categories
│   │   ├── scam_types.py                  # 16 ScamCategory definitions
│   │   ├── hybrid_engine.py               # 10-layer detection + explainability
│   │   ├── ml_engine.py                   # LightGBM ML + 65 feature extraction
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
│   │   ├── extractor.py                   # UPI, phone, bank, link extraction
│   │   ├── network_analyzer.py            # Graph-based scammer network analysis
│   │   └── behavioral_fingerprint.py      # Cross-session behavioral fingerprinting
│   ├── callback_worker/
│   │   └── guvi_callback.py               # HTTP/2 callback with retry + enrichment
│   ├── session_manager/
│   │   └── session_store.py               # Redis + in-memory storage
│   └── utils/
│       ├── logging.py                     # Structured logging + LogBuffer
│       └── validation.py                  # Input sanitization
├── templates/
│   └── dashboard.html                     # Explainability dashboard (Chart.js)
├── tests/
│   ├── test_agent.py                      # Core agent tests
│   ├── test_detector.py                   # Scam detector tests
│   ├── test_extractor.py                  # Intelligence extraction tests
│   ├── test_callback.py                   # GUVI callback tests
│   ├── test_new_features.py               # Feature v1 tests (36)
│   ├── test_new_features_v2.py            # Feature v2 tests (73)
│   ├── test_api_comprehensive.py          # API + ML + pipeline tests (73)
│   ├── test_network_analyzer.py           # Network analysis tests (12)
│   ├── test_advanced_features.py          # Advanced ML features tests (14)
│   ├── test_behavioral_fingerprint.py     # Behavioral fingerprinting tests (13)
│   └── test_explainability.py             # Explainability engine tests (12)
├── docker/
│   ├── Dockerfile                         # Multi-stage production image (non-root)
│   ├── docker-compose.yml                 # Nginx + API (scalable) + Redis
│   ├── gunicorn.conf.py                   # Gunicorn + Uvicorn worker config
│   ├── deploy.sh                          # One-command production deployment
│   ├── sysctl-tuning.conf                 # Linux kernel tuning (TCP, BBR, etc)
│   ├── ulimits.conf                       # File descriptor / process limits
│   ├── ARCHITECTURE.md                    # Full architecture & ops guide
│   ├── nginx/
│   │   ├── nginx.conf                     # Main config (upstream, gzip, keepalive)
│   │   └── conf.d/
│   │       └── default.conf               # Virtual host (proxy, rate limit, CF IPs)
│   └── k8s/                               # Future Kubernetes manifests
│       ├── namespace.yaml
│       ├── configmap.yaml
│       ├── deployment.yaml
│       ├── service.yaml
│       ├── redis.yaml
│       ├── hpa.yaml
│       └── ingress.yaml
├── requirements.txt
├── .dockerignore                          # Optimized build context
├── pytest.ini
└── LICENSE
```

---

## Installation

### Prerequisites

- Python 3.11+
- Google Gemini API key
- Docker & Docker Compose V2 (for production)
- Redis (optional for local dev)

### Local Development

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

### Run (Development)

```bash
uvicorn src.api_gateway.app:app --host 0.0.0.0 --port 8000 --reload
```

### Docker Production Deployment

Optimized for AWS m7i-flex.large (2 vCPU / 8 GB RAM) behind Cloudflare.

```
Cloudflare (TLS + HTTP/2 + DDoS)
    │
    ▼  port 80
  Nginx (least_conn LB, gzip, rate limiting)
    │
    ├──► API container (2 Uvicorn workers, single instance)
    │
    ▼
  Redis (384 MB, LRU eviction, AOF persistence, AUTH enabled)
```

> **Scaling Note**: Docker Compose runs a **single API instance** for development.
> For horizontal scaling with multiple replicas, use Kubernetes (see `docker/k8s/`).
> See [ADR-001](docs/architecture/ADR-001-docker-compose-scaling.md) for details.

```bash
cd docker

# One-command deploy (applies sysctl + ulimits + builds + starts)
sudo ./deploy.sh

# Or manual deployment
docker compose build --no-cache
docker compose up -d --remove-orphans

# View logs
docker compose logs -f api nginx

# Container stats
docker stats

# Stop
docker compose down
```

**Container Resource Allocation (8 GB VM)**:

| Container | CPU | RAM Limit | Instances |
|-----------|-----|-----------|----------|
| Nginx     | 0.15 | 96 MB    | 1        |
| API       | 0.70 | 2560 MB  | 1        |
| Redis     | 0.25 | 640 MB   | 1        |

**Backpressure Tuning** (see [ADR-002](docs/architecture/ADR-002-backpressure-and-concurrency.md)):

| Setting | Dev (Compose) | Prod (K8s) |
|---------|---------------|------------|
| `GUNICORN_WORKERS` | 2 | 4 |
| `BACKPRESSURE_MAX_QUEUE_DEPTH` | 16 (2×8) | 32 (4×8) |
| `BACKPRESSURE_SHED_THRESHOLD` | 0.85 | 0.85 |

Monitor `p99_latency_ms` via `GET /api/v1/health/ready` to validate.

**Redis Configuration** (see [ADR-003](docs/architecture/ADR-003-redis-ha-and-client-config.md)):

| Setting | Dev (Compose) | Prod (K8s) |
|---------|---------------|------------|
| Connection | Direct `redis://` with AUTH | Sentinel-aware with AUTH |
| `REDIS_SENTINEL_ENABLED` | `false` | `true` |
| `protected-mode` | `yes` + `requirepass` | `requirepass` + `masterauth` |
| Failover | Manual | Automatic (Sentinel) |

**Performance Estimates (single instance)**:

| Endpoint | Est. RPS | P50 Latency |
|----------|---------|-------------|
| `GET /health` (JSON) | 5,000-8,000 | <1ms |
| `POST /message` (Gemini + ML) | 50-140 | ~200ms |
| Concurrent connections | ~1,000 | — |

### Kubernetes Production Deployment

K8s provides horizontal scaling, Redis Sentinel HA, and automatic failover — features intentionally omitted from the dev Compose setup.

**Key differences from Compose**:
- **API**: 3 replicas (HPA scales to 20), 4 Gunicorn workers per pod
- **Redis**: 3-node StatefulSet with Sentinel sidecar, automatic failover
- **Backpressure**: `BACKPRESSURE_MAX_QUEUE_DEPTH=32` aligned with 4 workers
- **Auth**: Redis AUTH via `REDIS_PASSWORD` Secret, Sentinel auth-pass

```bash
# Update secrets before applying
kubectl apply -f docker/k8s/namespace.yaml
kubectl apply -f docker/k8s/configmap.yaml   # Includes Gunicorn, backpressure, Sentinel config
kubectl apply -f docker/k8s/redis.yaml        # StatefulSet + Sentinel + AUTH
kubectl apply -f docker/k8s/deployment.yaml
kubectl apply -f docker/k8s/service.yaml
kubectl apply -f docker/k8s/hpa.yaml
kubectl apply -f docker/k8s/ingress.yaml
```

See [docker/ARCHITECTURE.md](docker/ARCHITECTURE.md) for the full architecture guide, OS tuning, Cloudflare config, monitoring, and K8s migration path.

### Tests

```bash
pytest tests/ -v --tb=short
```

```
269 passed in ~55s
```

---

## License

MIT License
