from abc import ABC, abstractmethod
from typing import Optional, Dict
from datetime import datetime, timezone
import json
import asyncio
import redis.asyncio as redis
from src.models import SessionState, ExtractedIntelligence, PersonaStyle
from src.config import get_settings


settings = get_settings()


class SessionLockManager:
    _instance = None
    _locks: Dict[str, asyncio.Lock] = {}
    _global_lock = asyncio.Lock()
    _semaphore: Optional[asyncio.Semaphore] = None
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance
    
    @classmethod
    async def get_semaphore(cls) -> asyncio.Semaphore:
        if cls._semaphore is None:
            cls._semaphore = asyncio.Semaphore(settings.max_concurrent_sessions)
        return cls._semaphore
    
    @classmethod
    async def get_lock(cls, session_id: str) -> asyncio.Lock:
        async with cls._global_lock:
            if session_id not in cls._locks:
                cls._locks[session_id] = asyncio.Lock()
            return cls._locks[session_id]
    
    @classmethod
    async def release_lock(cls, session_id: str) -> None:
        async with cls._global_lock:
            cls._locks.pop(session_id, None)
    
    @classmethod
    async def cleanup_stale_locks(cls, active_sessions: set) -> int:
        async with cls._global_lock:
            stale = [sid for sid in cls._locks if sid not in active_sessions]
            for sid in stale:
                cls._locks.pop(sid, None)
            return len(stale)


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


class InMemorySessionStore(BaseSessionStore):
    def __init__(self):
        self._store: Dict[str, dict] = {}
        self._timestamps: Dict[str, datetime] = {}
        self._lock = asyncio.Lock()

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

    async def delete(self, session_id: str) -> bool:
        async with self._lock:
            if session_id in self._store:
                del self._store[session_id]
                self._timestamps.pop(session_id, None)
                await SessionLockManager.release_lock(session_id)
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
        for sid in expired:
            await SessionLockManager.release_lock(sid)
        return len(expired)
    
    async def get_active_session_ids(self) -> set:
        async with self._lock:
            return set(self._store.keys())
    
    async def get_session_count(self) -> int:
        return len(self._store)


class RedisSessionStore(BaseSessionStore):
    def __init__(self, redis_url: str):
        self._redis = redis.from_url(
            redis_url,
            decode_responses=True,
            max_connections=50,
            socket_timeout=5.0,
            socket_connect_timeout=5.0
        )
        self._prefix = "scam_session:"
        self._ttl = settings.session_timeout_seconds

    async def get(self, session_id: str) -> Optional[SessionState]:
        try:
            data = await self._redis.get(f"{self._prefix}{session_id}")
            if data is None:
                return None
            return SessionState(**json.loads(data))
        except Exception:
            return None

    async def set(self, session_id: str, state: SessionState) -> None:
        state.last_updated = datetime.now(timezone.utc)
        try:
            await self._redis.setex(
                f"{self._prefix}{session_id}",
                self._ttl,
                state.model_dump_json()
            )
        except Exception:
            pass

    async def delete(self, session_id: str) -> bool:
        try:
            result = await self._redis.delete(f"{self._prefix}{session_id}")
            await SessionLockManager.release_lock(session_id)
            return result > 0
        except Exception:
            return False

    async def exists(self, session_id: str) -> bool:
        try:
            return await self._redis.exists(f"{self._prefix}{session_id}") > 0
        except Exception:
            return False
    
    async def get_active_session_ids(self) -> set:
        try:
            keys = await self._redis.keys(f"{self._prefix}*")
            return {k.replace(self._prefix, "") for k in keys}
        except Exception:
            return set()


def get_session_store() -> BaseSessionStore:
    if settings.use_redis:
        return RedisSessionStore(settings.redis_url)
    return InMemorySessionStore()


_session_store: Optional[BaseSessionStore] = None


async def get_or_create_session_store() -> BaseSessionStore:
    global _session_store
    if _session_store is None:
        _session_store = get_session_store()
    return _session_store


async def get_or_create_session(session_id: str) -> SessionState:
    semaphore = await SessionLockManager.get_semaphore()
    session_lock = await SessionLockManager.get_lock(session_id)
    
    async with semaphore:
        async with session_lock:
            store = await get_or_create_session_store()
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
                    messages=[]
                )
                await store.set(session_id, session)
            return session


async def update_session(session: SessionState) -> None:
    session_lock = await SessionLockManager.get_lock(session.session_id)
    async with session_lock:
        store = await get_or_create_session_store()
        await store.set(session.session_id, session)


async def delete_session(session_id: str) -> bool:
    store = await get_or_create_session_store()
    return await store.delete(session_id)


async def session_exists(session_id: str) -> bool:
    store = await get_or_create_session_store()
    return await store.exists(session_id)
