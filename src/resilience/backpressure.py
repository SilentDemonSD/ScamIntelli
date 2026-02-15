import asyncio
import time
from dataclasses import dataclass, field
from typing import Optional

from src.config import get_settings
from src.utils.logging import get_logger

logger = get_logger(__name__)
settings = get_settings()


@dataclass
class LoadMetrics:
    active_requests: int = 0
    total_requests: int = 0
    rejected_requests: int = 0
    avg_latency_ms: float = 0.0
    p99_latency_ms: float = 0.0
    queue_depth: int = 0
    last_updated: float = field(default_factory=time.time)


class BackpressureController:
    _instance: Optional["BackpressureController"] = None

    def __init__(
        self,
        max_concurrent: int = None,
        shed_threshold: float = None,
        slowdown_threshold: float = None,
    ):
        self._max_concurrent = max_concurrent or settings.backpressure_max_queue_depth
        self._shed_threshold = shed_threshold or settings.backpressure_shed_threshold
        self._slowdown_threshold = slowdown_threshold or settings.backpressure_slowdown_threshold
        self._active = 0
        self._total = 0
        self._rejected = 0
        self._lock = asyncio.Lock()
        self._latencies: list = []
        self._max_latency_samples = 1000

    @classmethod
    def get_instance(cls) -> "BackpressureController":
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    @property
    def load_factor(self) -> float:
        if self._max_concurrent == 0:
            return 0.0
        return self._active / self._max_concurrent

    @property
    def should_shed(self) -> bool:
        return self.load_factor >= self._shed_threshold

    @property
    def should_slow_down(self) -> bool:
        return self.load_factor >= self._slowdown_threshold

    async def acquire(self) -> bool:
        async with self._lock:
            self._total += 1

            if self._active >= self._max_concurrent:
                self._rejected += 1
                return False

            load = self._active / max(self._max_concurrent, 1)
            if load >= self._shed_threshold:
                self._rejected += 1
                return False

            self._active += 1
            return True

    async def release(self, latency_ms: float = 0.0) -> None:
        async with self._lock:
            self._active = max(0, self._active - 1)
            if latency_ms > 0:
                self._latencies.append(latency_ms)
                if len(self._latencies) > self._max_latency_samples:
                    self._latencies = self._latencies[-self._max_latency_samples:]

    def get_metrics(self) -> LoadMetrics:
        avg_latency = 0.0
        p99_latency = 0.0
        snapshot = self._latencies[:]
        if snapshot:
            avg_latency = sum(snapshot) / len(snapshot)
            snapshot.sort()
            p99_idx = int(len(snapshot) * 0.99)
            p99_latency = snapshot[min(p99_idx, len(snapshot) - 1)]

        return LoadMetrics(
            active_requests=self._active,
            total_requests=self._total,
            rejected_requests=self._rejected,
            avg_latency_ms=round(avg_latency, 2),
            p99_latency_ms=round(p99_latency, 2),
            queue_depth=self._active,
        )

    def get_retry_after(self) -> int:
        if self.load_factor >= 0.95:
            return 30
        if self.load_factor >= 0.85:
            return 10
        return 5
