import logging
import sys
from datetime import datetime
from pathlib import Path

import aiofiles

from src.config import get_settings

settings = get_settings()

logging.basicConfig(
    level=getattr(logging, settings.log_level.upper()),
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)


def get_logger(name: str) -> logging.Logger:
    return logging.getLogger(name)


async def log_session(
    session_id: str, message: str, direction: str, scam_detected: bool = False
):
    log_file = Path("scamsession.txt")
    timestamp = datetime.utcnow().isoformat()
    log_entry = f"[{timestamp}] SESSION: {session_id} | DIRECTION: {direction} | SCAM: {scam_detected} | MESSAGE: {message}\n"

    async with aiofiles.open(log_file, mode="a", encoding="utf-8") as f:
        await f.write(log_entry)
