import asyncio
import json
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from typing import Dict, Optional

import redis.asyncio as redis

from src.config import get_settings
from src.models import ExtractedIntelligence, PersonaStyle, SessionState
from src.utils.logging import get_logger

settings = get_settings()
logger = get_logger(__name__)


class BaseSessionStore(ABC):
    @abstractmethod
    async def get(self, session_id: str) -> Optional[SessionState]:
        pass

    @abstractmethod
    async def set(self, session_id: str, state: SessionState) -> None:
        pass

    @abstractmethod
    async def delete(self, session_id: str) -> bool:
        pass

    @abstractmethod
    async def exists(self, session_id: str) -> bool:
        pass

    async def cleanup_expired(self) -> int:
        return 0

    async def get_active_session_ids(self) -> set:
        return set()

    async def get_session_count(self) -> int:
        return len(await self.get_active_session_ids())


class InMemorySessionStore(BaseSessionStore):
    def __init__(self):
        self._store: Dict[str, dict] = {}
        self._timestamps: Dict[str, datetime] = {}
        self._lock = asyncio.Lock()
        self._versions: Dict[str, int] = {}

    async def get(self, session_id: str) -> Optional[SessionState]:
        async with self._lock:
            data = self._store.get(session_id)
            if data is None:
                return None
            return SessionState(**data)

    async def set(self, session_id: str, state: SessionState) -> None:
        state.last_updated = datetime.now(timezone.utc)
        async with self._lock:
            self._store[session_id] = json.loads(state.model_dump_json())
            self._timestamps[session_id] = state.last_updated
            self._versions[session_id] = self._versions.get(session_id, 0) + 1

    async def delete(self, session_id: str) -> bool:
        async with self._lock:
            if session_id in self._store:
                del self._store[session_id]
                self._timestamps.pop(session_id, None)
                self._versions.pop(session_id, None)
                return True
            return False

    async def exists(self, session_id: str) -> bool:
        return session_id in self._store

    async def cleanup_expired(self) -> int:
        now = datetime.now(timezone.utc)
        expired = []
        async with self._lock:
            for sid, ts in self._timestamps.items():
                if (now - ts).total_seconds() > settings.session_timeout_seconds:
                    expired.append(sid)
            for sid in expired:
                self._store.pop(sid, None)
                self._timestamps.pop(sid, None)
                self._versions.pop(sid, None)
        return len(expired)

    async def get_active_session_ids(self) -> set:
        async with self._lock:
            return set(self._store.keys())

    async def get_session_count(self) -> int:
        return len(self._store)


class RedisSessionStore(BaseSessionStore):
    def __init__(self, redis_client: redis.Redis):
        self._redis = redis_client
        self._prefix = "scam_session:"
        self._version_prefix = "scam_version:"
        self._ttl = settings.session_timeout_seconds

    async def get(self, session_id: str) -> Optional[SessionState]:
        try:
            data = await self._redis.get(f"{self._prefix}{session_id}")
            if data is None:
                return None
            return SessionState(**json.loads(data))
        except redis.ConnectionError:
            logger.error(f"Redis connection failed during get for {session_id}")
            return None
        except Exception as e:
            logger.error(f"Session get error for {session_id}: {e}")
            return None

    async def set(self, session_id: str, state: SessionState) -> None:
        state.last_updated = datetime.now(timezone.utc)
        try:
            pipe = self._redis.pipeline()
            pipe.setex(
                f"{self._prefix}{session_id}",
                self._ttl,
                state.model_dump_json(),
            )
            pipe.incr(f"{self._version_prefix}{session_id}")
            pipe.expire(f"{self._version_prefix}{session_id}", self._ttl)
            await pipe.execute()
        except redis.ConnectionError:
            logger.error(f"Redis connection failed during set for {session_id}")
        except Exception as e:
            logger.error(f"Session set error for {session_id}: {e}")

    async def delete(self, session_id: str) -> bool:
        try:
            pipe = self._redis.pipeline()
            pipe.delete(f"{self._prefix}{session_id}")
            pipe.delete(f"{self._version_prefix}{session_id}")
            results = await pipe.execute()
            return results[0] > 0
        except Exception as e:
            logger.error(f"Session delete error for {session_id}: {e}")
            return False

    async def exists(self, session_id: str) -> bool:
        try:
            return await self._redis.exists(f"{self._prefix}{session_id}") > 0
        except Exception:
            return False

    async def cleanup_expired(self) -> int:
        return 0

    async def get_active_session_ids(self) -> set:
        try:
            cursor = 0
            session_ids = set()
            while True:
                cursor, keys = await self._redis.scan(
                    cursor=cursor,
                    match=f"{self._prefix}*",
                    count=100,
                )
                for k in keys:
                    session_ids.add(k.replace(self._prefix, ""))
                if cursor == 0:
                    break
            return session_ids
        except Exception as e:
            logger.error(f"Failed to scan session keys: {e}")
            return set()


class RedisConnectionManager:
    _instance: Optional["RedisConnectionManager"] = None
    _redis: Optional[redis.Redis] = None

    @classmethod
    async def get_connection(cls) -> redis.Redis:
        if cls._redis is not None:
            try:
                await cls._redis.ping()
                return cls._redis
            except Exception:
                cls._redis = None

        if settings.redis_sentinel_enabled:
            cls._redis = await cls._create_sentinel_connection()
        else:
            cls._redis = await cls._create_direct_connection()

        return cls._redis

    @classmethod
    async def _create_direct_connection(cls) -> redis.Redis:
        return redis.from_url(
            settings.redis_url,
            decode_responses=True,
            max_connections=settings.redis_pool_max,
            socket_timeout=settings.redis_socket_timeout,
            socket_connect_timeout=settings.redis_socket_connect_timeout,
            retry_on_timeout=True,
            health_check_interval=30,
        )

    @classmethod
    async def _create_sentinel_connection(cls) -> redis.Redis:
        from redis.asyncio.sentinel import Sentinel

        sentinel = Sentinel(
            settings.sentinel_host_list,
            socket_timeout=settings.redis_socket_timeout,
            decode_responses=True,
        )
        return sentinel.master_for(
            settings.redis_sentinel_master,
            socket_timeout=settings.redis_socket_timeout,
            db=0,
        )

    @classmethod
    async def close(cls) -> None:
        if cls._redis:
            await cls._redis.aclose()
            cls._redis = None


_session_store: Optional[BaseSessionStore] = None
_fallback_store: Optional[InMemorySessionStore] = None


def _get_fallback_store() -> InMemorySessionStore:
    global _fallback_store
    if _fallback_store is None:
        _fallback_store = InMemorySessionStore()
    return _fallback_store


async def get_or_create_session_store() -> BaseSessionStore:
    global _session_store

    if _session_store is not None:
        return _session_store

    if not settings.use_redis:
        _session_store = InMemorySessionStore()
        return _session_store

    try:
        redis_conn = await RedisConnectionManager.get_connection()
        _session_store = RedisSessionStore(redis_conn)

        from src.session_manager.distributed_lock import DistributedLockManager
        DistributedLockManager.initialize(redis_conn)

        return _session_store
    except Exception as e:
        logger.error(f"Redis connection failed, using in-memory fallback: {e}")
        _session_store = _get_fallback_store()
        return _session_store


async def get_or_create_session(session_id: str) -> SessionState:
    store = await get_or_create_session_store()

    lock_mgr = None
    if settings.use_redis:
        from src.session_manager.distributed_lock import DistributedLockManager
        lock_mgr = DistributedLockManager.get_instance()

    if lock_mgr:
        try:
            async with lock_mgr.session_lock(session_id):
                return await _get_or_create_session_inner(store, session_id)
        except Exception as e:
            logger.warning(f"Distributed lock failed for {session_id}, using local: {e}")
            return await _get_or_create_session_inner(store, session_id)
    else:
        return await _get_or_create_session_inner(store, session_id)


async def _get_or_create_session_inner(
    store: BaseSessionStore, session_id: str
) -> SessionState:
    session = await store.get(session_id)
    if session is None:
        session = SessionState(
            session_id=session_id,
            persona_style=PersonaStyle.CONFUSED,
            extracted_intel=ExtractedIntelligence(),
            turn_count=0,
            confidence_level=0.5,
            scam_detected=False,
            engagement_active=True,
            messages=[],
        )
        await store.set(session_id, session)
    return session


async def update_session(session: SessionState) -> None:
    store = await get_or_create_session_store()

    lock_mgr = None
    if settings.use_redis:
        from src.session_manager.distributed_lock import DistributedLockManager
        lock_mgr = DistributedLockManager.get_instance()

    if lock_mgr:
        try:
            async with lock_mgr.session_lock(session.session_id):
                await store.set(session.session_id, session)
        except Exception as e:
            logger.warning(f"Distributed lock failed during update for {session.session_id}: {e}")
            await store.set(session.session_id, session)
    else:
        await store.set(session.session_id, session)


async def delete_session(session_id: str) -> bool:
    store = await get_or_create_session_store()
    return await store.delete(session_id)


async def session_exists(session_id: str) -> bool:
    store = await get_or_create_session_store()
    return await store.exists(session_id)
