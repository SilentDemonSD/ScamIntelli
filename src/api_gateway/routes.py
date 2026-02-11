from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, Header, HTTPException, Request
from fastapi.responses import HTMLResponse

from src.agent_controller.strategy import (
    get_engagement_summary,
    process_message,
    should_trigger_callback,
)
from src.callback_worker.guvi_callback import send_guvi_callback
from src.config import get_settings
from src.models import (
    AgentReply,
    EndSessionResponse,
    HealthResponse,
    HoneypotRequest,
    HoneypotSimpleResponse,
    MessageRequest,
    SessionResponse,
)
from src.scam_detector.ml_engine import MLScamDetector, PatternLearner
from src.intelligence_extractor.network_analyzer import get_network_analyzer
from src.intelligence_extractor.behavioral_fingerprint import get_fingerprinter
from src.scam_detector.hybrid_engine import HybridScamDetectionEngine
from src.security.tamper_proof import (
    TamperProofMiddleware,
    create_tamper_proof_response,
    validate_incoming_request,
)
from src.session_manager.session_store import get_or_create_session, update_session
from src.utils.logging import LogBuffer
from src.utils.validation import sanitize_input, validate_message, validate_session_id

settings = get_settings()
router = APIRouter(prefix="/api/v1", tags=["honeypot"])
_middleware = TamperProofMiddleware()


async def verify_api_key(x_api_key: Optional[str] = Header(None)) -> str:
    if not x_api_key:
        raise HTTPException(status_code=401, detail="API key required")
    if x_api_key != settings.api_key:
        raise HTTPException(status_code=403, detail="Invalid API key")
    return x_api_key


def _extract_client_info(request: Request) -> tuple:
    ip = request.client.host if request.client else "unknown"
    user_agent = request.headers.get("user-agent", "unknown")
    return ip, user_agent, dict(request.headers)


@router.post("/message", response_model=AgentReply)
async def handle_message(
    request_body: MessageRequest,
    request: Request,
    api_key: str = Depends(verify_api_key),
):
    if not validate_session_id(request_body.session_id):
        raise HTTPException(status_code=400, detail="Invalid session ID format")
    if not validate_message(request_body.message):
        raise HTTPException(status_code=400, detail="Invalid message format")

    message = sanitize_input(request_body.message)
    ip, user_agent, headers = _extract_client_info(request)
    try:
        validate_incoming_request(
            ip, user_agent, request_body.session_id, message, headers
        )
    except Exception:
        pass

    session = await get_or_create_session(request_body.session_id)
    session, reply = await process_message(session, message)
    await update_session(session)

    if not session.engagement_active and await should_trigger_callback(session):
        await send_guvi_callback(session)

    return reply


@router.post("/honeypot", response_model=HoneypotSimpleResponse)
async def honeypot_endpoint(
    request_body: HoneypotRequest,
    request: Request,
    x_api_key: Optional[str] = Header(None, alias="x-api-key"),
):
    if not x_api_key or x_api_key != settings.api_key:
        raise HTTPException(
            status_code=401 if not x_api_key else 403,
            detail="API key required" if not x_api_key else "Invalid API key",
        )

    message_text = (
        request_body.message.get("text", "")
        if isinstance(request_body.message, dict)
        else request_body.message.text
    )
    if not message_text:
        raise HTTPException(status_code=400, detail="Message text required")

    ip, user_agent, headers = _extract_client_info(request)
    try:
        validate_incoming_request(
            ip, user_agent, request_body.sessionId, message_text, headers
        )
    except Exception:
        pass

    session = await get_or_create_session(request_body.sessionId)
    session, reply = await process_message(session, message_text)
    await update_session(session)

    conversation_complete = not session.engagement_active or session.turn_count >= 10
    if conversation_complete and session.scam_detected:
        await send_guvi_callback(session)

    persona_type = getattr(session, "persona_type", None)
    if persona_type is None:
        persona_str = "default"
    elif hasattr(persona_type, "value"):
        persona_str = persona_type.value
    else:
        persona_str = str(persona_type)

    response_data, _ = create_tamper_proof_response(
        {"status": "success", "reply": reply.reply}, persona_str
    )

    return HoneypotSimpleResponse(
        status=response_data.get("status", "success"),
        reply=response_data.get("reply", reply.reply),
    )


@router.get("/session/{session_id}", response_model=SessionResponse)
async def get_session(session_id: str, api_key: str = Depends(verify_api_key)):
    if not validate_session_id(session_id):
        raise HTTPException(status_code=400, detail="Invalid session ID format")

    session = await get_or_create_session(session_id)

    return SessionResponse(
        session_id=session.session_id,
        scam_detected=session.scam_detected,
        engagement_active=session.engagement_active,
        turn_count=session.turn_count,
        extracted_intelligence=session.extracted_intel,
    )


@router.delete("/session/{session_id}", response_model=EndSessionResponse)
async def end_session(session_id: str, api_key: str = Depends(verify_api_key)):
    if not validate_session_id(session_id):
        raise HTTPException(status_code=400, detail="Invalid session ID format")

    session = await get_or_create_session(session_id)
    callback_sent = (
        await send_guvi_callback(session) if session.scam_detected else False
    )

    from src.session_manager.session_store import get_or_create_session_store

    store = await get_or_create_session_store()
    await store.delete(session_id)

    return EndSessionResponse(
        status="success",
        session_id=session_id,
        callback_sent=callback_sent,
        total_messages=session.turn_count,
        extracted_intelligence=session.extracted_intel,
    )


@router.get("/health", response_model=HealthResponse)
async def health_check():
    return HealthResponse(status="healthy", timestamp=datetime.now(timezone.utc))


@router.get("/summary/{session_id}")
async def get_summary(session_id: str, api_key: str = Depends(verify_api_key)):
    if not validate_session_id(session_id):
        raise HTTPException(status_code=400, detail="Invalid session ID format")
    session = await get_or_create_session(session_id)
    return await get_engagement_summary(session)


@router.get("/stats")
async def get_stats(api_key: str = Depends(verify_api_key)):
    from src.session_manager.session_store import get_or_create_session_store

    store = await get_or_create_session_store()
    session_ids = await store.get_active_session_ids()

    total_sessions = len(session_ids)
    total_turns = 0
    total_scams_detected = 0
    total_intel = {
        "upi_ids": 0,
        "phone_numbers": 0,
        "bank_accounts": 0,
        "phishing_links": 0,
        "suspicious_keywords": 0,
    }
    active_engagements = 0
    scam_categories: dict = {}
    sessions_summary = []

    for sid in session_ids:
        session = await store.get(sid)
        if session is None:
            continue

        total_turns += session.turn_count

        if session.scam_detected:
            total_scams_detected += 1
            cat = session.scam_category or "unknown"
            scam_categories[cat] = scam_categories.get(cat, 0) + 1

        if session.engagement_active:
            active_engagements += 1

        intel = session.extracted_intel
        total_intel["upi_ids"] += len(intel.upi_ids)
        total_intel["phone_numbers"] += len(intel.phone_numbers)
        total_intel["bank_accounts"] += len(intel.bank_accounts)
        total_intel["phishing_links"] += len(intel.phishing_links)
        total_intel["suspicious_keywords"] += len(intel.suspicious_keywords)

        sessions_summary.append({
            "session_id": session.session_id,
            "scam_detected": session.scam_detected,
            "scam_category": session.scam_category,
            "turn_count": session.turn_count,
            "engagement_active": session.engagement_active,
            "persona_type": session.persona_type,
            "intel_count": (
                len(intel.upi_ids)
                + len(intel.phone_numbers)
                + len(intel.bank_accounts)
                + len(intel.phishing_links)
            ),
            "created_at": session.created_at.isoformat() if session.created_at else None,
            "last_updated": session.last_updated.isoformat() if session.last_updated else None,
        })

    ml_info = MLScamDetector.get_model_info()

    return {
        "total_sessions": total_sessions,
        "active_engagements": active_engagements,
        "completed_engagements": total_sessions - active_engagements,
        "total_scams_detected": total_scams_detected,
        "total_turns": total_turns,
        "avg_turns_per_session": round(total_turns / max(total_sessions, 1), 1),
        "intelligence_gathered": total_intel,
        "total_intel_items": sum(total_intel.values()),
        "scam_categories_breakdown": scam_categories,
        "ml_model": ml_info,
        "learned_patterns": PatternLearner.get_learned_pattern_count(),
        "sessions": sessions_summary,
    }


@router.get("/logs")
async def get_logs(
    limit: int = 100,
    level: Optional[str] = None,
    source: Optional[str] = None,
    api_key: str = Depends(verify_api_key),
):
    limit = min(limit, 500)
    logs = LogBuffer.get_logs(limit=limit, level=level, source=source)
    return {
        "total_in_buffer": LogBuffer.count(),
        "returned": len(logs),
        "filters": {"level": level, "source": source, "limit": limit},
        "logs": logs,
    }


@router.get("/network/analysis")
async def get_network_analysis(api_key: str = Depends(verify_api_key)):
    analyzer = get_network_analyzer()
    stats = analyzer.get_network_statistics()
    rings = analyzer.detect_fraud_rings()
    kingpins = analyzer.identify_kingpins(top_n=10)

    return {
        "network_statistics": {
            "total_entities": stats.total_entities,
            "total_edges": stats.total_edges,
            "total_sessions_tracked": stats.total_sessions_tracked,
            "connected_components": stats.connected_components,
            "fraud_rings_detected": stats.fraud_rings_detected,
            "average_cluster_coefficient": stats.average_cluster_coefficient,
            "network_density": stats.network_density,
            "top_entity_types": stats.top_entity_types,
        },
        "fraud_rings": [
            {
                "ring_id": r.ring_id,
                "size": r.size,
                "risk_score": r.risk_score,
                "sessions": r.sessions,
                "entity_types": r.entity_types,
                "first_seen": r.first_seen,
                "last_seen": r.last_seen,
            }
            for r in rings[:20]
        ],
        "kingpin_entities": [
            {
                "entity_value": k.entity_value,
                "entity_type": k.entity_type,
                "centrality_score": k.centrality_score,
                "connected_sessions": k.connected_sessions,
                "connected_entities": k.connected_entities,
            }
            for k in kingpins
        ],
    }


@router.post("/session/{session_id}/fingerprint")
async def create_session_fingerprint(
    session_id: str,
    api_key: str = Depends(verify_api_key),
):
    if not validate_session_id(session_id):
        raise HTTPException(status_code=400, detail="Invalid session ID format")

    session = await get_or_create_session(session_id)

    if session.turn_count < 3:
        raise HTTPException(
            status_code=400,
            detail="Minimum 3 messages required for fingerprinting",
        )

    fingerprinter = get_fingerprinter()
    fp = fingerprinter.create_fingerprint(session_id, session.messages)

    if fp is None:
        raise HTTPException(
            status_code=400,
            detail="Insufficient scammer messages for fingerprinting",
        )

    fingerprinter.store_fingerprint(fp)
    matches = fingerprinter.match_fingerprint(fp)

    analyzer = get_network_analyzer()
    analyzer.add_intelligence(session_id, session.extracted_intel)

    return {
        "fingerprint_id": fp.fingerprint_id,
        "session_id": fp.session_id,
        "signature_hash": fp.signature_hash,
        "message_count": fp.message_count,
        "timing_pattern": {
            "avg_message_length": fp.timing.avg_message_length,
            "avg_word_count": fp.timing.avg_word_count,
            "punctuation_density": fp.timing.punctuation_density,
            "capitalization_ratio": fp.timing.capitalization_ratio,
        },
        "language_pattern": {
            "vocabulary_richness": fp.language.vocabulary_richness,
            "avg_sentence_length": fp.language.avg_sentence_length,
            "formality_score": fp.language.formality_score,
            "language_mix_ratio": fp.language.language_mix_ratio,
        },
        "escalation_pattern": {
            "pressure_pattern": fp.escalation.pressure_pattern,
            "threat_density": fp.escalation.threat_density,
            "escalation_speed": fp.escalation.escalation_speed,
        },
        "entity_patterns": fp.entity_patterns,
        "matches": [
            {
                "matched_session_id": m.matched_session_id,
                "similarity_score": m.similarity_score,
                "timing_similarity": m.timing_similarity,
                "language_similarity": m.language_similarity,
                "pattern_similarity": m.pattern_similarity,
            }
            for m in matches
        ],
        "stored_fingerprints": fingerprinter.get_stored_count(),
    }


@router.get("/session/{session_id}/explanation")
async def get_session_explanation(
    session_id: str,
    api_key: str = Depends(verify_api_key),
):
    if not validate_session_id(session_id):
        raise HTTPException(status_code=400, detail="Invalid session ID format")

    session = await get_or_create_session(session_id)

    if session.detection_details:
        return session.detection_details

    if not session.messages:
        return {
            "session_id": session_id,
            "detection_result": {
                "is_scam": False,
                "confidence": 0.0,
                "risk_level": "minimal",
                "has_hard_indicators": False,
            },
            "layer_breakdown": {},
            "top_signals": [],
            "risk_factors": [],
            "psychological_tactics": [],
            "advanced_features": {},
            "detection_layers_used": [],
            "score_breakdown": {},
        }

    last_scammer_msg = ""
    for msg in reversed(session.messages):
        if msg.get("role") in ("user", "scammer") and msg.get("content"):
            last_scammer_msg = msg["content"]
            break

    if not last_scammer_msg:
        last_scammer_msg = session.messages[-1].get("content", "") if session.messages else ""

    explanation = await HybridScamDetectionEngine.detect_with_explanation(
        last_scammer_msg, session.messages
    )

    explanation["session_id"] = session_id
    session.detection_details = explanation
    await update_session(session)

    return explanation


@router.get("/session/{session_id}/visualization")
async def get_session_visualization(
    session_id: str,
    api_key: str = Depends(verify_api_key),
):
    if not validate_session_id(session_id):
        raise HTTPException(status_code=400, detail="Invalid session ID format")

    session = await get_or_create_session(session_id)

    if not session.detection_details:
        if session.messages:
            last_scammer_msg = ""
            for msg in reversed(session.messages):
                if msg.get("role") in ("user", "scammer") and msg.get("content"):
                    last_scammer_msg = msg["content"]
                    break
            if not last_scammer_msg and session.messages:
                last_scammer_msg = session.messages[-1].get("content", "")

            explanation = await HybridScamDetectionEngine.detect_with_explanation(
                last_scammer_msg, session.messages
            )
            explanation["session_id"] = session_id
            session.detection_details = explanation
            await update_session(session)

    from pathlib import Path

    template_path = Path(__file__).parent.parent.parent / "templates" / "dashboard.html"
    if not template_path.exists():
        raise HTTPException(status_code=500, detail="Dashboard template not found")

    import json

    html_content = template_path.read_text(encoding="utf-8")
    details_json = json.dumps(session.detection_details or {})
    session_json = json.dumps({
        "session_id": session.session_id,
        "scam_detected": session.scam_detected,
        "turn_count": session.turn_count,
        "confidence_level": session.confidence_level,
        "scam_category": session.scam_category,
        "persona_type": session.persona_type,
        "engagement_active": session.engagement_active,
    })

    html_content = html_content.replace("{{DETECTION_DETAILS}}", details_json)
    html_content = html_content.replace("{{SESSION_DATA}}", session_json)

    return HTMLResponse(content=html_content)
