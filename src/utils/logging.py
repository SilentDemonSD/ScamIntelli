import logging
import sys
from collections import deque
from datetime import datetime, timezone
from pathlib import Path
from typing import List

import aiofiles

from src.config import get_settings

settings = get_settings()

logging.basicConfig(
    level=getattr(logging, settings.log_level.upper()),
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)


class LogBuffer:
    _buffer: deque = deque(maxlen=500)

    @classmethod
    def add(cls, level: str, source: str, message: str, extra: dict = None) -> None:
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": level,
            "source": source,
            "message": message,
        }
        if extra:
            entry["extra"] = extra
        cls._buffer.append(entry)

    @classmethod
    def get_logs(
        cls,
        limit: int = 100,
        level: str = None,
        source: str = None,
    ) -> List[dict]:
        logs = list(cls._buffer)

        if level:
            level_upper = level.upper()
            logs = [entry for entry in logs if entry["level"] == level_upper]

        if source:
            logs = [entry for entry in logs if source.lower() in entry["source"].lower()]

        return logs[-limit:]

    @classmethod
    def clear(cls) -> None:
        cls._buffer.clear()

    @classmethod
    def count(cls) -> int:
        return len(cls._buffer)


class BufferedLogHandler(logging.Handler):
    def emit(self, record: logging.LogRecord) -> None:
        try:
            LogBuffer.add(
                level=record.levelname,
                source=record.name,
                message=record.getMessage(),
            )
        except Exception:
            pass


_buffer_handler = BufferedLogHandler()
_buffer_handler.setLevel(logging.DEBUG)
logging.getLogger().addHandler(_buffer_handler)


def get_logger(name: str) -> logging.Logger:
    return logging.getLogger(name)


async def log_session(
    session_id: str,
    message: str,
    direction: str,
    scam_detected: bool = False,
    confidence: float = 0.0,
    scam_category: str = None,
):
    log_file = Path("scamsession.txt")
    timestamp = datetime.now(timezone.utc).isoformat()
    log_entry = f"[{timestamp}] SESSION: {session_id} | DIRECTION: {direction} | SCAM: {scam_detected} | CONFIDENCE: {confidence:.4f} | MESSAGE: {message}\n"

    extra = {
        "session_id": session_id,
        "direction": direction,
        "scam_detected": scam_detected,
        "confidence": round(confidence, 4),
    }
    if scam_category:
        extra["scam_category"] = scam_category

    LogBuffer.add(
        level="INFO",
        source=f"session:{session_id}",
        message=f"[{direction}] {message}",
        extra=extra,
    )

    async with aiofiles.open(log_file, mode="a", encoding="utf-8") as f:
        await f.write(log_entry)
