from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from contextlib import asynccontextmanager
import time
import random
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


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Starting Scam Honeypot API")
    yield
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
    response = await call_next(request)
    
    process_time = time.time() - start_time
    jitter = random.uniform(0.05, 0.15)
    
    response.headers["X-Response-Time"] = f"{process_time + jitter:.3f}"
    response.headers.pop("server", None)
    response.headers.pop("x-powered-by", None)
    
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
