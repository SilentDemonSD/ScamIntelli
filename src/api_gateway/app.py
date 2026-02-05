from fastapi import FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from contextlib import asynccontextmanager
import time
import random
import asyncio
from collections import defaultdict
from src.api_gateway.routes import router
from src.utils.logging import get_logger
from src.config import get_settings
from src.callback_worker.guvi_callback import cleanup_client

settings = get_settings()
logger = get_logger(__name__)

GENERIC_ERRORS = [
    "Request could not be processed",
    "Service temporarily unavailable",
    "Please try again later",
    "An error occurred"
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
                t for t in self._requests[client_id] 
                if now - t < self._window
            ]
            if len(self._requests[client_id]) >= self._limit:
                return False
            self._requests[client_id].append(now)
            return True
    
    async def cleanup(self) -> None:
        now = time.time()
        async with self._lock:
            expired = [
                k for k, v in self._requests.items()
                if not v or now - max(v) > self._window * 2
            ]
            for k in expired:
                del self._requests[k]


from typing import Dict
rate_limiter = RateLimiter(settings.rate_limit_per_minute)
_cleanup_task: asyncio.Task = None


async def periodic_cleanup():
    while True:
        await asyncio.sleep(300)
        await rate_limiter.cleanup()
        from src.session_manager.session_store import get_or_create_session_store
        try:
            store = await get_or_create_session_store()
            await store.cleanup_expired()
        except Exception:
            pass


@asynccontextmanager
async def lifespan(app: FastAPI):
    global _cleanup_task
    logger.info("Starting Scam Honeypot API")
    _cleanup_task = asyncio.create_task(periodic_cleanup())
    yield
    if _cleanup_task:
        _cleanup_task.cancel()
        try:
            await _cleanup_task
        except asyncio.CancelledError:
            pass
    await cleanup_client()
    logger.info("Shutting down Scam Honeypot API")


app = FastAPI(
    title="ScamIntelli API",
    description="A stateful, agentic honeypot API for scam detection and intelligence extraction",
    version="1.0.0",
    lifespan=lifespan,
    docs_url=None if settings.is_production else "/docs",
    redoc_url=None if settings.is_production else "/redoc",
    openapi_url=None if settings.is_production else "/openapi.json"
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
    
    client_ip = request.client.host if request.client else "unknown"
    if not await rate_limiter.is_allowed(client_ip):
        return JSONResponse(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            content={"status": "error", "detail": "Too many requests"}
        )
    
    response = await call_next(request)
    
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
        content={"status": "error", "detail": random.choice(GENERIC_ERRORS)}
    )


app.include_router(router)


@app.get("/")
async def root():
    return {"status": "running", "service": "honeypot"}
