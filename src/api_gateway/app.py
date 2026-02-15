import asyncio
import random
import time
from collections import defaultdict
from contextlib import asynccontextmanager
from typing import Dict

from fastapi import FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from src.api_gateway.routes import router
from src.callback_worker.guvi_callback import cleanup_client
from src.config import get_settings
from src.resilience.backpressure import BackpressureController
from src.utils.logging import get_logger

settings = get_settings()
logger = get_logger(__name__)

GENERIC_ERRORS = [
    "Request could not be processed",
    "Service temporarily unavailable",
    "Please try again later",
    "An error occurred",
]


class RateLimiter:
    def __init__(self, requests_per_minute: int = 60):
        self._requests: Dict[str, list] = defaultdict(list)
        self._lock = asyncio.Lock()
        self._window = 60.0
        self._limit = requests_per_minute

    async def is_allowed(self, client_id: str) -> bool:
        now = time.time()
        async with self._lock:
            self._requests[client_id] = [
                t for t in self._requests[client_id] if now - t < self._window
            ]
            if len(self._requests[client_id]) >= self._limit:
                return False
            self._requests[client_id].append(now)
            return True

    async def cleanup(self) -> None:
        now = time.time()
        async with self._lock:
            expired = [
                k
                for k, v in self._requests.items()
                if not v or now - max(v) > self._window * 2
            ]
            for k in expired:
                del self._requests[k]


rate_limiter = RateLimiter(settings.rate_limit_per_minute)
backpressure = BackpressureController.get_instance()
_cleanup_task: asyncio.Task = None


async def periodic_cleanup():
    while True:
        await asyncio.sleep(300)
        await rate_limiter.cleanup()
        from src.session_manager.session_store import get_or_create_session_store

        try:
            store = await get_or_create_session_store()
            await store.cleanup_expired()

            if settings.use_redis:
                from src.session_manager.distributed_lock import DistributedLockManager
                lock_mgr = DistributedLockManager.get_instance()
                if lock_mgr:
                    active = await store.get_active_session_ids()
                    await lock_mgr.cleanup_stale(active)
        except Exception:
            pass

        try:
            from src.graph.graph_backend import get_graph_cache
            cache = get_graph_cache()
            await cache.cleanup_expired()
        except Exception:
            pass


async def _init_task_queue():
    if settings.use_redis:
        try:
            from src.task_queue.broker import get_or_create_broker
            broker = await get_or_create_broker()
            if broker:
                logger.info("Task queue broker initialized")
        except Exception as e:
            logger.warning(f"Task queue init failed (non-fatal): {e}")


async def _init_batch_processor():
    try:
        from src.graph.graph_backend import get_batch_processor
        processor = get_batch_processor()
        await processor.start()
        logger.info("Batch graph processor started")
    except Exception as e:
        logger.warning(f"Batch processor init failed: {e}")


@asynccontextmanager
async def lifespan(app: FastAPI):
    global _cleanup_task
    logger.info("Starting Scam Honeypot API")

    if settings.use_redis:
        from src.session_manager.session_store import get_or_create_session_store
        await get_or_create_session_store()
        logger.info("Redis session store initialized")

    await _init_task_queue()
    await _init_batch_processor()

    if settings.neo4j_enabled:
        try:
            from src.graph.neo4j_backend import Neo4jGraphStore
            await Neo4jGraphStore.create()
            from src.intelligence_extractor.network_analyzer import get_network_analyzer
            analyzer = get_network_analyzer()
            await analyzer.sync_from_neo4j()
            logger.info("Neo4j graph store initialized")
        except Exception as e:
            logger.warning(f"Neo4j init failed (falling back to NetworkX): {e}")

    _cleanup_task = asyncio.create_task(periodic_cleanup())

    from src.intelligence_extractor.network_analyzer import get_network_analyzer
    from src.intelligence_extractor.behavioral_fingerprint import get_fingerprinter
    from src.scam_detector.training_pipeline import get_training_pipeline

    get_network_analyzer()
    get_fingerprinter()
    logger.info("Initialized network analyzer and behavioral fingerprinter")

    pipeline = get_training_pipeline()
    if pipeline.is_trained:
        logger.info("Ensemble model loaded and ready")
    else:
        logger.warning(
            "No trained ensemble model found. "
            "Run POST /api/v1/train or python -m src.scam_detector.train_model to train."
        )

    yield

    if _cleanup_task:
        _cleanup_task.cancel()
        try:
            await _cleanup_task
        except asyncio.CancelledError:
            pass

    try:
        from src.graph.graph_backend import get_batch_processor
        processor = get_batch_processor()
        await processor.stop()
    except Exception:
        pass

    try:
        from src.session_manager.session_store import RedisConnectionManager
        await RedisConnectionManager.close()
    except Exception:
        pass

    try:
        from src.graph.neo4j_backend import Neo4jGraphStore
        store = Neo4jGraphStore.get_instance()
        if store:
            await store.close()
    except Exception:
        pass

    await cleanup_client()
    logger.info("Shutting down Scam Honeypot API")


app = FastAPI(
    title="ScamIntelli API",
    description="A stateful, agentic honeypot API for scam detection and intelligence extraction",
    version="2.0.0",
    lifespan=lifespan,
    docs_url=None if settings.is_production else "/docs",
    redoc_url=None if settings.is_production else "/redoc",
    openapi_url=None if settings.is_production else "/openapi.json",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.middleware("http")
async def security_middleware(request: Request, call_next):
    start_time = time.time()

    if request.url.path in ("/api/v1/health", "/api/v1/health/ready", "/"):
        response = await call_next(request)
        return response

    client_ip = request.client.host if request.client else "unknown"
    if not await rate_limiter.is_allowed(client_ip):
        return JSONResponse(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            content={"status": "error", "detail": "Too many requests"},
            headers={"Retry-After": str(backpressure.get_retry_after())},
        )

    acquired = await backpressure.acquire()
    if not acquired:
        return JSONResponse(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            content={"status": "error", "detail": "Service at capacity"},
            headers={"Retry-After": str(backpressure.get_retry_after())},
        )

    try:
        response = await call_next(request)
    finally:
        process_time_ms = (time.time() - start_time) * 1000
        await backpressure.release(process_time_ms)

    process_time = time.time() - start_time
    jitter = random.uniform(0.05, 0.15)

    response.headers["X-Response-Time"] = f"{process_time + jitter:.3f}"

    for header in ("server", "x-powered-by"):
        if header in response.headers:
            del response.headers[header]

    return response


@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    logger.error(f"Unhandled exception: {str(exc)}")
    return JSONResponse(
        status_code=500,
        content={"status": "error", "detail": random.choice(GENERIC_ERRORS)},
    )


app.include_router(router)


@app.get("/")
async def root():
    return {"status": "running", "service": "honeypot"}
