import asyncio
import uuid
from contextlib import asynccontextmanager
from typing import Dict, Optional

import redis.asyncio as redis

from src.config import get_settings
from src.utils.logging import get_logger

logger = get_logger(__name__)
settings = get_settings()


class DistributedLock:
    def __init__(
        self,
        redis_client: redis.Redis,
        key: str,
        ttl: int = None,
        retry_count: int = None,
        retry_delay: float = None,
    ):
        self._redis = redis_client
        self._key = f"lock:{key}"
        self._token = str(uuid.uuid4())
        self._ttl = ttl or settings.distributed_lock_ttl
        self._retry_count = retry_count or settings.distributed_lock_retry_count
        self._retry_delay = retry_delay or settings.distributed_lock_retry_delay
        self._acquired = False

    async def acquire(self) -> bool:
        for attempt in range(self._retry_count):
            result = await self._redis.set(
                self._key,
                self._token,
                nx=True,
                ex=self._ttl,
            )
            if result:
                self._acquired = True
                return True

            if attempt < self._retry_count - 1:
                jitter = self._retry_delay * (0.5 + 0.5 * (attempt / self._retry_count))
                await asyncio.sleep(jitter)

        return False

    async def release(self) -> bool:
        if not self._acquired:
            return False

        release_script = """
        if redis.call("get", KEYS[1]) == ARGV[1] then
            return redis.call("del", KEYS[1])
        else
            return 0
        end
        """
        try:
            result = await self._redis.eval(release_script, 1, self._key, self._token)
            self._acquired = False
            return bool(result)
        except Exception:
            return False

    async def extend(self, additional_ttl: int = None) -> bool:
        if not self._acquired:
            return False

        extend_ttl = additional_ttl or self._ttl
        extend_script = """
        if redis.call("get", KEYS[1]) == ARGV[1] then
            return redis.call("expire", KEYS[1], ARGV[2])
        else
            return 0
        end
        """
        try:
            result = await self._redis.eval(
                extend_script, 1, self._key, self._token, str(extend_ttl)
            )
            return bool(result)
        except Exception:
            return False


class DistributedLockManager:
    _instance: Optional["DistributedLockManager"] = None
    _local_locks: Dict[str, asyncio.Lock] = {}
    _global_lock = asyncio.Lock()

    def __init__(self, redis_client: redis.Redis):
        self._redis = redis_client

    @classmethod
    def initialize(cls, redis_client: redis.Redis) -> "DistributedLockManager":
        cls._instance = cls(redis_client)
        return cls._instance

    @classmethod
    def get_instance(cls) -> Optional["DistributedLockManager"]:
        return cls._instance

    @asynccontextmanager
    async def session_lock(self, session_id: str, ttl: int = None):
        async with self._global_lock:
            if session_id not in self._local_locks:
                self._local_locks[session_id] = asyncio.Lock()
            local_lock = self._local_locks[session_id]

        async with local_lock:
            dist_lock = DistributedLock(
                self._redis,
                f"session:{session_id}",
                ttl=ttl,
            )
            acquired = await dist_lock.acquire()
            if not acquired:
                raise SessionLockError(
                    f"Failed to acquire lock for session {session_id}"
                )
            try:
                yield dist_lock
            finally:
                await dist_lock.release()

    @asynccontextmanager
    async def resource_lock(self, resource_name: str, ttl: int = None):
        dist_lock = DistributedLock(
            self._redis,
            f"resource:{resource_name}",
            ttl=ttl or 60,
        )
        acquired = await dist_lock.acquire()
        if not acquired:
            raise ResourceLockError(
                f"Failed to acquire lock for resource {resource_name}"
            )
        try:
            yield dist_lock
        finally:
            await dist_lock.release()

    async def cleanup_stale(self, active_sessions: set) -> int:
        async with self._global_lock:
            stale = [sid for sid in self._local_locks if sid not in active_sessions]
            for sid in stale:
                self._local_locks.pop(sid, None)
            return len(stale)


class FallbackLockManager:
    _locks: Dict[str, asyncio.Lock] = {}
    _global_lock = asyncio.Lock()
    _semaphore: Optional[asyncio.Semaphore] = None

    @classmethod
    async def get_semaphore(cls) -> asyncio.Semaphore:
        if cls._semaphore is None:
            cls._semaphore = asyncio.Semaphore(settings.max_concurrent_sessions)
        return cls._semaphore

    @classmethod
    @asynccontextmanager
    async def session_lock(cls, session_id: str, ttl: int = None):
        async with cls._global_lock:
            if session_id not in cls._locks:
                cls._locks[session_id] = asyncio.Lock()
            lock = cls._locks[session_id]
        async with lock:
            yield None

    @classmethod
    @asynccontextmanager
    async def resource_lock(cls, resource_name: str, ttl: int = None):
        async with cls._global_lock:
            if resource_name not in cls._locks:
                cls._locks[resource_name] = asyncio.Lock()
            lock = cls._locks[resource_name]
        async with lock:
            yield None

    @classmethod
    async def cleanup_stale(cls, active_sessions: set) -> int:
        async with cls._global_lock:
            stale = [sid for sid in cls._locks if sid not in active_sessions]
            for sid in stale:
                cls._locks.pop(sid, None)
            return len(stale)


class SessionLockError(Exception):
    pass


class ResourceLockError(Exception):
    pass
