import asyncio
import json
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional

import redis.asyncio as redis

from src.config import get_settings
from src.utils.logging import get_logger

logger = get_logger(__name__)
settings = get_settings()


class TaskPriority(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    NORMAL = "normal"
    LOW = "low"


class TaskStatus(str, Enum):
    PENDING = "pending"
    PROCESSING = "processing"
    COMPLETED = "completed"
    FAILED = "failed"
    DEAD = "dead"


@dataclass
class TaskMessage:
    task_id: str
    task_type: str
    payload: Dict[str, Any]
    priority: TaskPriority = TaskPriority.NORMAL
    retry_count: int = 0
    max_retries: int = 3
    created_at: float = field(default_factory=time.time)
    scheduled_at: Optional[float] = None

    def to_dict(self) -> Dict[str, str]:
        return {
            "task_id": self.task_id,
            "task_type": self.task_type,
            "payload": json.dumps(self.payload),
            "priority": self.priority.value,
            "retry_count": str(self.retry_count),
            "max_retries": str(self.max_retries),
            "created_at": str(self.created_at),
        }

    @classmethod
    def from_stream(cls, data: Dict[str, str]) -> "TaskMessage":
        return cls(
            task_id=data.get("task_id", str(uuid.uuid4())),
            task_type=data.get("task_type", "unknown"),
            payload=json.loads(data.get("payload", "{}")),
            priority=TaskPriority(data.get("priority", "normal")),
            retry_count=int(data.get("retry_count", "0")),
            max_retries=int(data.get("max_retries", "3")),
            created_at=float(data.get("created_at", str(time.time()))),
        )


class TaskBroker:
    _instance: Optional["TaskBroker"] = None

    def __init__(self, redis_client: redis.Redis):
        self._redis = redis_client
        self._stream = settings.task_queue_stream
        self._dlq_stream = settings.task_queue_dlq_stream
        self._group = settings.task_queue_consumer_group
        self._initialized = False

    @classmethod
    async def create(cls, redis_client: redis.Redis) -> "TaskBroker":
        broker = cls(redis_client)
        await broker._ensure_streams()
        cls._instance = broker
        return broker

    @classmethod
    def get_instance(cls) -> Optional["TaskBroker"]:
        return cls._instance

    async def _ensure_streams(self):
        if self._initialized:
            return
        try:
            await self._redis.xgroup_create(
                self._stream, self._group, id="0", mkstream=True
            )
        except redis.ResponseError as e:
            if "BUSYGROUP" not in str(e):
                raise
        try:
            await self._redis.xgroup_create(
                self._dlq_stream, f"{self._group}-dlq", id="0", mkstream=True
            )
        except redis.ResponseError as e:
            if "BUSYGROUP" not in str(e):
                raise
        self._initialized = True

    async def enqueue(self, task: TaskMessage) -> str:
        try:
            msg_id = await self._redis.xadd(
                self._stream,
                task.to_dict(),
                maxlen=10000,
            )
            logger.debug(f"Task enqueued: {task.task_type} ({task.task_id})")
            return msg_id
        except Exception as e:
            logger.error(f"Failed to enqueue task {task.task_type}: {e}")
            raise

    async def enqueue_callback(
        self, session_id: str, session_data: Dict[str, Any]
    ) -> str:
        task = TaskMessage(
            task_id=str(uuid.uuid4()),
            task_type="callback",
            payload={"session_id": session_id, "session_data": session_data},
            priority=TaskPriority.HIGH,
            max_retries=settings.task_queue_max_retries,
        )
        return await self.enqueue(task)

    async def enqueue_graph_update(
        self, session_id: str, intel_data: Dict[str, Any]
    ) -> str:
        task = TaskMessage(
            task_id=str(uuid.uuid4()),
            task_type="graph_update",
            payload={"session_id": session_id, "intel": intel_data},
            priority=TaskPriority.NORMAL,
        )
        return await self.enqueue(task)

    async def enqueue_fingerprint(
        self, session_id: str, messages: List[Dict]
    ) -> str:
        task = TaskMessage(
            task_id=str(uuid.uuid4()),
            task_type="fingerprint",
            payload={"session_id": session_id, "messages": messages},
            priority=TaskPriority.LOW,
        )
        return await self.enqueue(task)

    async def consume(
        self,
        consumer_name: str,
        count: int = None,
        block_ms: int = 5000,
    ) -> List[tuple]:
        count = count or settings.task_queue_batch_size
        try:
            results = await self._redis.xreadgroup(
                self._group,
                consumer_name,
                {self._stream: ">"},
                count=count,
                block=block_ms,
            )
            if not results:
                return []

            tasks = []
            for stream_name, entries in results:
                for msg_id, data in entries:
                    try:
                        task = TaskMessage.from_stream(data)
                        tasks.append((msg_id, task))
                    except Exception as e:
                        logger.error(f"Failed to parse task {msg_id}: {e}")
                        await self.acknowledge(msg_id)
            return tasks
        except Exception as e:
            logger.error(f"Consumer {consumer_name} read error: {e}")
            return []

    async def acknowledge(self, msg_id: str) -> None:
        try:
            await self._redis.xack(self._stream, self._group, msg_id)
        except Exception as e:
            logger.error(f"Failed to acknowledge {msg_id}: {e}")

    async def send_to_dlq(self, task: TaskMessage, error: str) -> None:
        dlq_data = task.to_dict()
        dlq_data["error"] = error
        dlq_data["failed_at"] = str(time.time())
        try:
            await self._redis.xadd(self._dlq_stream, dlq_data, maxlen=5000)
            logger.warning(
                f"Task {task.task_id} ({task.task_type}) sent to DLQ: {error}"
            )
        except Exception as e:
            logger.error(f"Failed to send task to DLQ: {e}")

    async def retry_or_dlq(self, task: TaskMessage, error: str) -> bool:
        if task.retry_count < task.max_retries:
            task.retry_count += 1
            await self.enqueue(task)
            logger.info(
                f"Task {task.task_id} retry {task.retry_count}/{task.max_retries}"
            )
            return True
        else:
            await self.send_to_dlq(task, error)
            return False

    async def reclaim_pending(
        self, consumer_name: str, min_idle_ms: int = None
    ) -> int:
        min_idle = min_idle_ms or (settings.task_queue_visibility_timeout * 1000)
        try:
            result = await self._redis.xautoclaim(
                self._stream,
                self._group,
                consumer_name,
                min_idle_time=min_idle,
                start_id="0-0",
                count=10,
            )
            if result and len(result) >= 2:
                reclaimed = result[1]
                return len(reclaimed)
            return 0
        except Exception as e:
            logger.error(f"Reclaim failed: {e}")
            return 0

    async def get_queue_depth(self) -> int:
        try:
            info = await self._redis.xinfo_stream(self._stream)
            return info.get("length", 0)
        except Exception:
            return 0

    async def get_dlq_depth(self) -> int:
        try:
            info = await self._redis.xinfo_stream(self._dlq_stream)
            return info.get("length", 0)
        except Exception:
            return 0


async def get_or_create_broker() -> Optional[TaskBroker]:
    broker = TaskBroker.get_instance()
    if broker:
        return broker

    if not settings.use_redis:
        return None

    try:
        from src.session_manager.session_store import RedisConnectionManager
        redis_conn = await RedisConnectionManager.get_connection()
        return await TaskBroker.create(redis_conn)
    except Exception as e:
        logger.error(f"Failed to create task broker: {e}")
        return None
