import asyncio
import json
import time
from collections import defaultdict
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Set

import redis.asyncio as redis

from src.config import get_settings
from src.utils.logging import get_logger

logger = get_logger(__name__)
settings = get_settings()


@dataclass
class CachedResult:
    data: Any
    computed_at: float
    ttl: int

    @property
    def is_expired(self) -> bool:
        return (time.time() - self.computed_at) > self.ttl


class GraphCache:
    def __init__(self, default_ttl: int = None):
        self._cache: Dict[str, CachedResult] = {}
        self._lock = asyncio.Lock()
        self._default_ttl = default_ttl or settings.graph_cache_ttl

    async def get(self, key: str) -> Optional[Any]:
        async with self._lock:
            result = self._cache.get(key)
            if result is None:
                return None
            if result.is_expired:
                del self._cache[key]
                return None
            return result.data

    async def put(self, key: str, data: Any, ttl: int = None) -> None:
        async with self._lock:
            self._cache[key] = CachedResult(
                data=data,
                computed_at=time.time(),
                ttl=ttl or self._default_ttl,
            )

    async def invalidate(self, key: str = None) -> None:
        async with self._lock:
            if key:
                self._cache.pop(key, None)
            else:
                self._cache.clear()

    async def cleanup_expired(self) -> int:
        async with self._lock:
            expired = [k for k, v in self._cache.items() if v.is_expired]
            for k in expired:
                del self._cache[k]
            return len(expired)


class RedisGraphCache:
    def __init__(self, redis_client: redis.Redis, prefix: str = "graph_cache:"):
        self._redis = redis_client
        self._prefix = prefix
        self._default_ttl = settings.graph_cache_ttl

    async def get(self, key: str) -> Optional[Any]:
        try:
            data = await self._redis.get(f"{self._prefix}{key}")
            if data is None:
                return None
            return json.loads(data)
        except Exception:
            return None

    async def put(self, key: str, data: Any, ttl: int = None) -> None:
        try:
            await self._redis.setex(
                f"{self._prefix}{key}",
                ttl or self._default_ttl,
                json.dumps(data, default=str),
            )
        except Exception as e:
            logger.error(f"Graph cache put failed: {e}")

    async def invalidate(self, key: str = None) -> None:
        try:
            if key:
                await self._redis.delete(f"{self._prefix}{key}")
            else:
                cursor = 0
                while True:
                    cursor, keys = await self._redis.scan(
                        cursor=cursor, match=f"{self._prefix}*", count=100
                    )
                    if keys:
                        await self._redis.delete(*keys)
                    if cursor == 0:
                        break
        except Exception as e:
            logger.error(f"Graph cache invalidate failed: {e}")


class BatchGraphProcessor:
    def __init__(self, flush_interval: int = None, max_batch_size: int = 100):
        self._buffer: List[Dict[str, Any]] = []
        self._lock = asyncio.Lock()
        self._flush_interval = flush_interval or settings.graph_batch_interval
        self._max_batch_size = max_batch_size
        self._flush_task: Optional[asyncio.Task] = None
        self._running = False

    async def start(self) -> None:
        self._running = True
        self._flush_task = asyncio.create_task(self._periodic_flush())

    async def stop(self) -> None:
        self._running = False
        if self._flush_task:
            self._flush_task.cancel()
            try:
                await self._flush_task
            except asyncio.CancelledError:
                pass
        await self.flush()

    async def add(self, session_id: str, intel_data: Dict[str, Any]) -> None:
        async with self._lock:
            self._buffer.append({
                "session_id": session_id,
                "intel": intel_data,
                "timestamp": time.time(),
            })

            if len(self._buffer) >= self._max_batch_size:
                await self._flush_locked()

    async def flush(self) -> int:
        async with self._lock:
            return await self._flush_locked()

    async def _flush_locked(self) -> int:
        if not self._buffer:
            return 0

        batch = self._buffer[:]
        self._buffer.clear()

        try:
            from src.intelligence_extractor.network_analyzer import get_network_analyzer
            from src.models import ExtractedIntelligence

            analyzer = get_network_analyzer()
            processed = 0

            for item in batch:
                try:
                    intel = ExtractedIntelligence(**item["intel"])
                    analyzer.add_intelligence(item["session_id"], intel)
                    processed += 1
                except Exception as e:
                    logger.error(f"Batch graph update failed for {item['session_id']}: {e}")

            logger.info(f"Batch graph flush: {processed}/{len(batch)} processed")
            return processed
        except Exception as e:
            logger.error(f"Batch graph flush error: {e}")
            self._buffer = batch + self._buffer
            return 0

    async def _periodic_flush(self) -> None:
        while self._running:
            try:
                await asyncio.sleep(self._flush_interval)
                flushed = await self.flush()
                if flushed > 0:
                    logger.debug(f"Periodic graph flush: {flushed} items")
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Periodic flush error: {e}")

    @property
    def pending_count(self) -> int:
        return len(self._buffer)


_graph_cache: Optional[GraphCache] = None
_batch_processor: Optional[BatchGraphProcessor] = None


def get_graph_cache() -> GraphCache:
    global _graph_cache
    if _graph_cache is None:
        _graph_cache = GraphCache()
    return _graph_cache


def get_batch_processor() -> BatchGraphProcessor:
    global _batch_processor
    if _batch_processor is None:
        _batch_processor = BatchGraphProcessor()
    return _batch_processor
