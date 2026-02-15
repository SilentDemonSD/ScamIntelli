import asyncio
import time
from enum import Enum
from typing import Any, Callable, Dict

from src.config import get_settings
from src.utils.logging import get_logger

logger = get_logger(__name__)
settings = get_settings()


class CircuitState(str, Enum):
    CLOSED = "closed"
    OPEN = "open"
    HALF_OPEN = "half_open"


class CircuitBreaker:
    def __init__(
        self,
        name: str,
        failure_threshold: int = None,
        recovery_timeout: int = None,
        half_open_max: int = None,
    ):
        self.name = name
        self._failure_threshold = failure_threshold or settings.circuit_breaker_failure_threshold
        self._recovery_timeout = recovery_timeout or settings.circuit_breaker_recovery_timeout
        self._half_open_max = half_open_max or settings.circuit_breaker_half_open_max
        self._state = CircuitState.CLOSED
        self._failure_count = 0
        self._success_count = 0
        self._half_open_calls = 0
        self._last_failure_time = 0.0
        self._lock = asyncio.Lock()

    @property
    def state(self) -> CircuitState:
        if self._state == CircuitState.OPEN:
            if time.time() - self._last_failure_time >= self._recovery_timeout:
                return CircuitState.HALF_OPEN
        return self._state

    async def call(self, func: Callable, *args, **kwargs) -> Any:
        async with self._lock:
            current_state = self.state

            if current_state == CircuitState.OPEN:
                raise CircuitOpenError(
                    f"Circuit '{self.name}' is open, request rejected"
                )

            if current_state == CircuitState.HALF_OPEN:
                if self._half_open_calls >= self._half_open_max:
                    raise CircuitOpenError(
                        f"Circuit '{self.name}' half-open limit reached"
                    )
                self._state = CircuitState.HALF_OPEN
                self._half_open_calls += 1

        try:
            result = func(*args, **kwargs)
            if asyncio.iscoroutine(result):
                result = await result

            async with self._lock:
                await self._on_success()
            return result

        except CircuitOpenError:
            raise
        except Exception as e:
            async with self._lock:
                await self._on_failure()
            raise

    async def _on_success(self) -> None:
        if self._state in (CircuitState.HALF_OPEN, CircuitState.OPEN):
            self._success_count += 1
            if self._success_count >= self._half_open_max:
                self._state = CircuitState.CLOSED
                self._failure_count = 0
                self._success_count = 0
                self._half_open_calls = 0
                logger.info(f"Circuit '{self.name}' closed (recovered)")
        else:
            self._failure_count = max(0, self._failure_count - 1)

    async def _on_failure(self) -> None:
        self._failure_count += 1
        self._last_failure_time = time.time()

        if self._state == CircuitState.HALF_OPEN:
            self._state = CircuitState.OPEN
            self._half_open_calls = 0
            self._success_count = 0
            logger.warning(f"Circuit '{self.name}' re-opened from half-open")
        elif self._failure_count >= self._failure_threshold:
            self._state = CircuitState.OPEN
            logger.warning(
                f"Circuit '{self.name}' opened "
                f"(failures: {self._failure_count}/{self._failure_threshold})"
            )

    def get_status(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "state": self.state.value,
            "failure_count": self._failure_count,
            "failure_threshold": self._failure_threshold,
            "last_failure_time": self._last_failure_time,
            "recovery_timeout": self._recovery_timeout,
        }


class CircuitBreakerRegistry:
    _breakers: Dict[str, CircuitBreaker] = {}

    @classmethod
    def get(cls, name: str, **kwargs) -> CircuitBreaker:
        if name not in cls._breakers:
            cls._breakers[name] = CircuitBreaker(name, **kwargs)
        return cls._breakers[name]

    @classmethod
    def get_all_status(cls) -> Dict[str, Dict]:
        return {name: cb.get_status() for name, cb in cls._breakers.items()}


class CircuitOpenError(Exception):
    pass
