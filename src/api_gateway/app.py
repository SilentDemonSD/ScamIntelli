from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from contextlib import asynccontextmanager
import time
from src.api_gateway.routes import router
from src.utils.logging import get_logger
from src.config import get_settings

settings = get_settings()
logger = get_logger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Starting Scam Honeypot API")
    yield
    logger.info("Shutting down Scam Honeypot API")


app = FastAPI(
    title="ScamIntelli API",
    description="A stateful, agentic honeypot API for scam detection and intelligence extraction",
    version="1.0.0",
    lifespan=lifespan
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.middleware("http")
async def add_process_time_header(request: Request, call_next):
    start_time = time.time()
    response = await call_next(request)
    process_time = time.time() - start_time
    response.headers["X-Process-Time"] = str(process_time)
    return response


@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    logger.error(f"Unhandled exception: {str(exc)}")
    return JSONResponse(
        status_code=500,
        content={"status": "error", "detail": "Internal server error"}
    )


app.include_router(router)


@app.get("/")
async def root():
    return {
        "name": "ScamIntelli API",
        "version": "1.0.0",
        "status": "running"
    }
